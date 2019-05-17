/*
 * Software License Agreement (BSD License)
 *
 *  Copyright (c) 2008, Willow Garage, Inc.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *   * Neither the name of Willow Garage, Inc. nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *  COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 *  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include "ros/connection.h"
#include "ros/transport/transport.h"
#include "ros/file_log.h"
#include <ros/assert.h>

#include <boost/shared_array.hpp>
#include <boost/bind.hpp>
#include <boost/make_shared.hpp>

#include <openssl/hmac.h>

namespace ros
{

Connection::Connection() :
		    is_server_(false),
		    dropped_(false),
		    is_available(false),
		    read_filled_(0),
		    read_size_(0),
		    reading_(false),
		    has_read_callback_(0),
		    buffered_read_size_(0),
		    buffered_read_capacity_(0),
		    buffered_read_offset_(0),
		    read_pending_size_(0),
		    write_sent_(0),
		    write_size_(0),
		    writing_(false),
		    has_write_callback_(0),
		    sending_header_error_(false),
		    read_header_func_(0) {
}

Connection::~Connection() {
	ROS_DEBUG_NAMED("superdebug", "Connection destructing, dropped=%s",
	    dropped_ ? "true" : "false");
	drop(Destructing);
}

void Connection::initialize(const TransportPtr& transport, bool is_server,
    const HeaderReceivedFunc& header_func) {

	transport_ = transport;
	is_server_ = is_server;

	transport_->setReadCallback(boost::bind(&Connection::onReadable, this, _1));
	transport_->setWriteCallback(boost::bind(&Connection::onWriteable, this, _1));
	transport_->setDisconnectCallback(
	    boost::bind(&Connection::onDisconnect, this, _1));

	read_func_ = boost::bind(&Connection::readSimple, this, _1, _2);
	write_func_ = boost::bind(&Connection::writeSimple, this, _1, _2, _3, _4);

	if (!transport->requiresHeader()) {
		is_available = true;
		return;
	}

	ROS_ASSERT(!security_module_);
	security_module_ = boost::make_shared<SecurityModule>();

	if (header_func)
		setHeaderReceivedCallback(header_func);
}

void Connection::secureConnection() {

	ROS_ASSERT(transport_->requiresHeader()); // no sense in this call otherwise

	{
		boost::recursive_mutex::scoped_lock lock(available_mutex_);

		if (is_server_) { // server-side takes the passive role
			read(4,
			    boost::bind(&Connection::onSecureConnectionHeaderLengthRead, this, _1, _2, _3,
			        _4));
		} else { // client-side takes the active role
			boost::shared_array<uint8_t> dh_public_key;
			size_t dh_public_key_size;

			//TODO(nmf) assert/handle proper return
			security_module_->initialize(dh_public_key, dh_public_key_size,
			    peer_key_retrieved_callback_);

			writeDH(dh_public_key, dh_public_key_size,
			    boost::bind(&Connection::onSecureConnectionHeaderWritten, this, _1));
		}
	} //unlock(available_mutex)
}


boost::signals2::connection Connection::addDropListener(const DropFunc& slot)
{
  boost::recursive_mutex::scoped_lock lock(drop_mutex_);
  return drop_signal_.connect(slot);
}

void Connection::removeDropListener(const boost::signals2::connection& c)
{
  boost::recursive_mutex::scoped_lock lock(drop_mutex_);
  c.disconnect();
}


void Connection::onReadable(const TransportPtr& transport)
{
  (void)transport;
  ROS_ASSERT(transport == transport_);

  readTransport();
}


void Connection::readTransport()
{
  boost::recursive_mutex::scoped_try_lock lock(read_mutex_);

	if (!lock.owns_lock() || dropped_ || reading_) {
    return;
  }

  reading_ = true;

  while (!dropped_ && has_read_callback_)
  {
		ROS_ASSERT(read_buffer_);

		uint32_t to_read = read_size_ - read_filled_;

		if (to_read > 0)
    {
      int32_t bytes_read = transport_->read(read_buffer_.get() + read_filled_, to_read);
      ROS_DEBUG_NAMED("superdebug", "Connection read %d bytes", bytes_read);
			if (dropped_) {
        return;
      }
      else if (bytes_read < 0) {
        // Bad read, throw away results and report error
        ReadFinishedFunc callback;
        callback = read_callback_;
        read_callback_.clear();
        read_buffer_.reset();
        uint32_t size = read_size_;
        read_size_ = 0;
        read_filled_ = 0;
        has_read_callback_ = 0;

				if (callback) {
          callback(shared_from_this(), read_buffer_, size, false);
				}
        break;
      }
      read_filled_ += bytes_read;
    }

    ROS_ASSERT((int32_t)read_size_ >= 0);
    ROS_ASSERT((int32_t)read_filled_ >= 0);
    ROS_ASSERT_MSG(read_filled_ <= read_size_, "read_filled_ = %d, read_size_ = %d", read_filled_, read_size_);

    if (read_filled_ == read_size_ && !dropped_)
    {
      ReadFinishedFunc callback;
      uint32_t size;
      boost::shared_array<uint8_t> buffer;

      ROS_ASSERT(has_read_callback_);

      // store off the read info in case another read() call is made from within the callback
      callback = read_callback_;
      size = read_size_;
      buffer = read_buffer_;
      read_callback_.clear();
      read_buffer_.reset();
      read_size_ = 0;
      read_filled_ = 0;
      has_read_callback_ = 0;

      ROS_DEBUG_NAMED("superdebug", "Calling read callback");
      callback(shared_from_this(), buffer, size, true);
    }
    else {
      break;
    }
  }

	if (!has_read_callback_) {
    transport_->disableRead();
  }
  reading_ = false;
}


void Connection::writeTransport() {
  boost::recursive_mutex::scoped_try_lock lock(write_mutex_);

	if (!lock.owns_lock() || dropped_ || writing_) {
    return;
  }

  writing_ = true;
  bool can_write_more = true;

  while (has_write_callback_ && can_write_more && !dropped_)
  {
    uint32_t to_write = write_size_ - write_sent_;

    ROS_DEBUG_NAMED("superdebug", "Connection writing %d bytes", to_write);
    int32_t bytes_sent = transport_->write(write_buffer_.get() + write_sent_, to_write);
    ROS_DEBUG_NAMED("superdebug", "Connection wrote %d bytes", bytes_sent);

    if (bytes_sent < 0)
    {
      writing_ = false;
      return;
    }

    write_sent_ += bytes_sent;

    if (bytes_sent < (int)write_size_ - (int)write_sent_)
    {
      can_write_more = false;
    }

    if (write_sent_ == write_size_ && !dropped_)
    {
      WriteFinishedFunc callback;
      {
        boost::mutex::scoped_lock lock(write_callback_mutex_);
        ROS_ASSERT(has_write_callback_);
        // Store off a copy of the callback in case another write() call happens in it
        callback = write_callback_;
        write_callback_ = WriteFinishedFunc();
        write_buffer_ = boost::shared_array<uint8_t>();
        write_sent_ = 0;
        write_size_ = 0;
        has_write_callback_ = 0;
      }

      ROS_DEBUG_NAMED("superdebug", "Calling write callback");
      callback(shared_from_this());
    }
  }

  {
    boost::mutex::scoped_lock lock(write_callback_mutex_);
		if (!has_write_callback_)
		{
      transport_->disableWrite();
		}
  }

  writing_ = false;
}

void Connection::onWriteable(const TransportPtr& transport)
{
  (void)transport;
  ROS_ASSERT(transport == transport_);

	writeTransport();
}

void Connection::read(uint32_t size, const ReadFinishedFunc& callback)
{
  if (dropped_ || sending_header_error_)
  {
    return;
  }
	// added indirection level to handle secure vs insecure connections
	read_func_(size, callback);
}

void Connection::readSimple(uint32_t size, const ReadFinishedFunc& callback) {
	{
		boost::recursive_mutex::scoped_lock lock(read_mutex_);

		ROS_ASSERT(!read_callback_);

		read_callback_ = callback;
		read_buffer_ = boost::shared_array<uint8_t>(new uint8_t[size]);
		read_size_ = size;
		read_filled_ = 0;
		has_read_callback_ = 1;
	}

	transport_->enableRead();
	readTransport();
}

void Connection::readSecure(uint32_t size, const ReadFinishedFunc& callback) {

		boost::shared_array<uint8_t> read_return = nullptr;

	{
		boost::recursive_mutex::scoped_lock lock(read_mutex_);

		ROS_ASSERT(!read_callback_);
		ROS_ASSERT(size > 0);

		if (size <= buffered_read_size_) // can return from buffer
		{
			ROS_DEBUG_NAMED("superdebug",
			    "Can serve read request of [%d] bytes from current buffer of [%d] bytes",
			    size, buffered_read_size_);

			read_return = boost::shared_array<uint8_t>(new uint8_t[size]);
			memcpy(read_return.get(),
			    buffered_read_buffer_.get() + buffered_read_offset_,
			    size);
			buffered_read_size_ -= size;
			buffered_read_offset_ += size;

		} else // need to read from transport
		{
			ROS_DEBUG_NAMED("superdebug",
			    "Need to read from transport to serve read request of [%d] bytes as "
					    "current buffer contains only [%d] bytes", size,
			    buffered_read_size_);

			boost::shared_array<uint8_t> tmp = buffered_read_buffer_;
			buffered_read_buffer_ = boost::shared_array<uint8_t>(new uint8_t[size]);

			if (buffered_read_size_ > 0)
				memcpy(buffered_read_buffer_.get(), tmp.get() + buffered_read_offset_,
				    buffered_read_size_);

			buffered_read_offset_ = 0;
			// buffered_read_size_ remains unchanged until data is returned

			// store off read call parameters for later
			read_pending_callback_ = callback;
			read_pending_size_ = size;
		}
	} //unlock(read_mutex)

	if (read_return) //no need for transport read
	{
		ROS_DEBUG_NAMED("superdebug",
		    "Calling read callback with [%d] bytes, leaving [%d] bytes in buffer",
		    size, buffered_read_size_);
		callback(shared_from_this(), read_return, size, true);
		return;
	}

	readSimple(4,
	    boost::bind(&Connection::onSecureBlockLengthRead, this, _1, _2, _3, _4));
}

// internal call from transport - read_mutex_ still locked
void Connection::onSecureBlockLengthRead(const ConnectionPtr& conn,
    const boost::shared_array<uint8_t> buffer, uint32_t size, bool success) {

	ROS_ASSERT(conn.get() == this);
	ROS_ASSERT(size == 4);

	if (!success)
		return;

	uint32_t len = *((uint32_t*) buffer.get());

	readSimple(len,
	    boost::bind(&Connection::onSecureBlockRead, this, _1, _2, _3, _4));
}

// internal call from transport - read_mutex_ still locked
void Connection::onSecureBlockRead(const ConnectionPtr& conn,
    const boost::shared_array<uint8_t> buffer, uint32_t size, bool success) {

	ROS_ASSERT(conn.get() == this);

	if (!success)
		return;

	ROS_DEBUG_NAMED("superdebug",
	    "Retrieving secured data from a block of [%u] bytes", size);

	boost::shared_array<uint8_t> plain_data = nullptr;
	uint32_t plain_data_len = 0;


	if (!security_module_->retrieve(buffer, size, 0, plain_data,
	    plain_data_len, 0))
	{
		//TODO(nmf) handle fail
		// DROP;
	}

	uint32_t available_bytes_total = plain_data_len + buffered_read_size_;

	ROS_DEBUG_NAMED("superdebug",
	    "Retrieved [%u] of data from secure block of [%u] bytes: progress "
			    "[%u]/[%u]", plain_data_len, size, available_bytes_total,
	    read_pending_size_);


	if (read_pending_size_ > available_bytes_total)
	{
		// store and read more
		memcpy(buffered_read_buffer_.get() + buffered_read_size_, plain_data.get(),
		    plain_data_len);
		buffered_read_size_ += plain_data_len;

		readSimple(4,
		    boost::bind(&Connection::onSecureBlockLengthRead, this, _1, _2, _3,
		        _4));
	} else
	{
		uint32_t required_bytes = read_pending_size_ - buffered_read_size_;
		memcpy(buffered_read_buffer_.get() + buffered_read_size_, plain_data.get(),
		    required_bytes);
		boost::shared_array<uint8_t> pending_read = boost::shared_array<uint8_t>(
		    new uint8_t[0]);
		pending_read.swap(buffered_read_buffer_);
		buffered_read_buffer_.swap(plain_data);
		buffered_read_size_ = plain_data_len - required_bytes;
		buffered_read_offset_ += required_bytes;


		ReadFinishedFunc callback = read_pending_callback_;
		int pending_read_size = read_pending_size_;
		read_pending_callback_ = ReadFinishedFunc();
		read_pending_size_ = 0;

		ROS_DEBUG_NAMED("superdebug",
		    "Calling back with [%u] bytes of read, leaving [%u] bytes in buffer",
		    pending_read_size, buffered_read_size_);

		callback(conn, pending_read, pending_read_size, true);
	}
}

void Connection::write(const boost::shared_array<uint8_t>& buffer,
  uint32_t size, const WriteFinishedFunc& callback, bool immediate)
{
	// caller must ensure size > 0

  if (dropped_ || sending_header_error_)
	{
    return;
	}

	{
		boost::mutex::scoped_lock lock(write_callback_mutex_);

		ROS_ASSERT(!write_callback_);

		// added indirection level to handle secure vs insecure connections
		write_func_(buffer, size, callback, immediate);
	}

  transport_->enableWrite();
	if (immediate)
	{
		// write immediately if possible
    writeTransport();
	}
}

// note: caller already holds write_callback_mutex
void Connection::writeSimple(const boost::shared_array<uint8_t>& buffer,
  uint32_t size, const WriteFinishedFunc& callback, bool immediate) {

	(void) immediate;

	write_callback_ = callback;
	write_buffer_ = buffer;
	write_size_ = size;
	write_sent_ = 0;
	has_write_callback_ = 1;
}

// note: caller already holds write_callback_mutex
void Connection::writeSecure(const boost::shared_array<uint8_t>& buffer,
    uint32_t size, const WriteFinishedFunc& callback, bool immediate) {

	(void) immediate;

	// build secure message
	boost::shared_array<uint8_t> secure_data = nullptr;
	uint32_t secure_data_len = 0;

	if (!security_module_->secure(buffer, size, 0, secure_data, secure_data_len,
	    4))
	{
		//TODO(nmf) handle fail
	}

	*((uint32_t*) secure_data.get()) = secure_data_len;

	write_callback_ = callback;
	write_buffer_ = secure_data;
	write_size_ = 4 + secure_data_len;
	write_sent_ = 0;
	has_write_callback_ = 1;

	ROS_DEBUG_NAMED("superdebug",
	    "Secured [%u] bytes worth of data, setting the write size to a total "
			    "of [%u] bytes", size, write_size_);
}


void Connection::onDisconnect(const TransportPtr& transport)
{
  (void)transport;
  ROS_ASSERT(transport == transport_);

  drop(TransportDisconnect);
}

void Connection::drop(DropReason reason)
{
  ROSCPP_LOG_DEBUG("Connection::drop(%u)", reason);
  bool did_drop = false;
  {
    boost::recursive_mutex::scoped_lock lock(drop_mutex_);
    if (!dropped_)
    {
      dropped_ = true;
      did_drop = true;
    }
  }

  if (did_drop)
  {
    drop_signal_(shared_from_this(), reason);
    transport_->close();
  }
}

bool Connection::isDropped()
{
  boost::recursive_mutex::scoped_lock lock(drop_mutex_);
  return dropped_;
}


void Connection::writeHeader(const M_string& key_vals,
    const WriteFinishedFunc& finished_callback) {

	ROS_ASSERT(!header_written_callback_);

	// links do not know connection types, and they sometimes call writeHeader
	// during initialization; we just drop it for udpros
	if (!transport_->requiresHeader()) {
		header_written_callback_ = finished_callback;
		onHeaderWritten(shared_from_this());
		return;
	}

	boost::shared_array<uint8_t> buffer;
	uint32_t len;
	Header::write(key_vals, buffer, len);

	uint32_t msg_len = len + 4;
	boost::shared_array<uint8_t> full_msg(new uint8_t[msg_len]);
	memcpy(full_msg.get() + 4, buffer.get(), len);
	*((uint32_t*) full_msg.get()) = len;

	{
		boost::recursive_mutex::scoped_lock lock(available_mutex_);

		header_written_callback_ = finished_callback;
		write_header_func_ = boost::bind(&Connection::write, this, full_msg,
		    msg_len,
		    WriteFinishedFunc(boost::bind(&Connection::onHeaderWritten, this, _1)),
		    false);

		//TODO(nmf) consider is_securing flag
		if (!is_available && !header_func_) {

			secureConnection();

			ROS_DEBUG_NAMED("superdebug",
			    "Delaying [%u] bytes worth write header request until connection is "
					    "ready", len);
			return;
		}

		if (!is_available)
			return;
	}

	write(full_msg, msg_len, boost::bind(&Connection::onHeaderWritten, this, _1),
	    false);
}

void Connection::writeDH(const boost::shared_array<uint8_t> dh_buffer,
    const uint32_t dh_size, const WriteFinishedFunc& finished_callback)
{

	uint32_t dh_exchange_size = 4 + dh_size;
	boost::shared_array<uint8_t> dh_exchange = boost::shared_array<uint8_t>(
	    new uint8_t[dh_exchange_size]);
	memcpy(dh_exchange.get() + 4, dh_buffer.get(), dh_size);
	*((uint32_t*) dh_exchange.get()) = dh_size;

	write(dh_exchange, dh_exchange_size, finished_callback, false);
}

void Connection::sendHeaderError(const std::string& error_msg)
{
  M_string m;
  m["error"] = error_msg;

	writeHeader(m, boost::bind(&Connection::onErrorHeaderWritten, this, _1));
  sending_header_error_ = true;
}

// callback from transport
void Connection::onHeaderLengthRead(const ConnectionPtr& conn,
    const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success)
{
  (void)size;
  ROS_ASSERT(conn.get() == this);
  ROS_ASSERT(size == 4);

  if (!success)
    return;

  uint32_t len = *((uint32_t*)buffer.get());

  if (len > 1000000000)
  {
    ROS_ERROR("a header of over a gigabyte was " \
                "predicted in tcpros. that seems highly " \
                "unlikely, so I'll assume protocol " \
                "synchronization is lost.");
    conn->drop(HeaderError);
  }

  read(len, boost::bind(&Connection::onHeaderRead, this, _1, _2, _3, _4));
}

// callback from transport
void Connection::onHeaderRead(const ConnectionPtr& conn,
  const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success)
{
  ROS_ASSERT(conn.get() == this);

  if (!success)
    return;

  std::string error_msg;
  if (!header_.parse(buffer, size, error_msg))
  {
    drop(HeaderError);
  }
  else
  {
    std::string error_val;
		if (header_.getValue("error", error_val))
    {
			ROSCPP_LOG_DEBUG(
			    "Received error message in header  for connection to [%s]: [%s]",
			    transport_->getTransportInfo().c_str(), error_val.c_str());
      drop(HeaderError);
    }
		// TODO(nmf)redo and comment this bit - consequence of broken encapsulation
		// of transport in service.cpp (called outside a connection)
		std::string probe_val;
		if (!is_available && !header_.getValue("probe", probe_val))
		{
			ROSCPP_LOG_DEBUG(
			    "Received actual connection header before security exchange for connection [%s]: only probe header allowed",
			    transport_->getTransportInfo().c_str());
			drop(HeaderError);
		}

    else
    {
      ROS_ASSERT(header_func_);
      transport_->parseHeader(header_);
      header_func_(conn, header_);
    }
  }

}

void Connection::onSecureConnectionHeaderWritten(const ConnectionPtr& conn)
{
	(void) conn;
	ROS_ASSERT(conn.get() == this);

	read(4,
	  boost::bind(&Connection::onSecureConnectionHeaderLengthRead, this, _1, _2, _3, _4));
}

void Connection::onSecureConnectionHeaderLengthRead(const ConnectionPtr& conn,
    const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success)
{

	(void) size;
	ROS_ASSERT(conn.get() == this);
	ROS_ASSERT(size == 4);

	if (!success)
		return;

	uint32_t len = *((uint32_t*) buffer.get());

	//TODO(nmf) adjust this error handling
	if (len > 1000000000) {
		ROS_ERROR("a header of over a gigabyte was "
			"predicted in tcpros. that seems highly "
			"unlikely, so I'll assume protocol "
			"synchronization is lost.");
		conn->drop(HeaderError);
	}

	ROS_DEBUG_NAMED("superdebug",
	    "Calling to read secure connection header of [%u] bytes worth length",
	    size);

	read(len, boost::bind(&Connection::onSecureConnectionHeaderRead, this, _1, _2, _3, _4));
}

// TODO(nmf) rename?
void Connection::onSecureConnectionHeaderRead(const ConnectionPtr& conn,
    const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success)
{

	ROS_ASSERT(conn.get() == this);
	if (!success)
		return;

	if (peer_key_retrieved_callback_) // client side
	{
		//TODO (nmf) attest success of peer_key_retrieved
		//TODO (nmf) remove success -> already asserted it at the top
		peer_key_retrieved_callback_(buffer, size, success);
		onConnectionSecured(conn);
		return;
	}

	boost::shared_array<uint8_t> dh_public_key = nullptr;
	size_t dh_public_key_size = 0;

	// TODO (nmf) test not dh_public_key not null
	if (security_module_->initialize(dh_public_key, dh_public_key_size, buffer,
	    size))
	{
		writeDH(dh_public_key, dh_public_key_size,
		    boost::bind(&Connection::onConnectionSecured, this, _1));
		return;
	}

	//TODO(nmf) ros_debug and comment - encapsulation breach in service
	// !key? ->  - probeHeader ? OK : DROP
	std::string error_msg;
	if (header_.parse(buffer, size, error_msg))
	{
		is_available = true;
		onHeaderRead(conn, buffer, size, success);
	}
}

void Connection::onConnectionSecured(const ConnectionPtr& conn)
{
	ROS_ASSERT(conn.get() == this);

	boost::function<void()> read_header_func = 0;
	boost::function<void()> write_header_func = 0;

	{
		boost::recursive_mutex::scoped_lock lock(available_mutex_);
		is_available = true;
		read_func_ = boost::bind(&Connection::readSecure, this, _1, _2);
		write_func_ = boost::bind(&Connection::writeSecure, this, _1, _2, _3, _4);
		read_header_func = read_header_func_;
		write_header_func = write_header_func_;
	}

	if (read_header_func)
	{
		read_header_func();
	}
	if (write_header_func)
	{
		write_header_func();
	}
}

void Connection::onHeaderWritten(const ConnectionPtr& conn)
{
  ROS_ASSERT(conn.get() == this);
	ROS_ASSERT(header_written_callback_);

	// TODO(nmf) change this
	//transport_->requiresHeader();
	header_written_callback_(conn);
  header_written_callback_ = WriteFinishedFunc();
}

void Connection::onErrorHeaderWritten(const ConnectionPtr& conn)
{
  (void)conn;
  drop(HeaderError);
}


void Connection::setHeaderReceivedCallback(const HeaderReceivedFunc& func)
{
	if (!transport_->requiresHeader())
		return;

	ROS_ASSERT(!header_func_);

	{
		boost::recursive_mutex::scoped_lock lock(available_mutex_);

		header_func_ = func;
		//TODO(nmf) rename with *_callback? - this is actually just a pending call
		read_header_func_ = boost::bind(&Connection::read, this, 4,
		    ReadFinishedFunc(
		        boost::bind(&Connection::onHeaderLengthRead, this, _1, _2, _3,
		            _4)));

		if (!is_available && !write_header_func_) {
			secureConnection();
			return;
		}

		if (!is_available)
			return;
	}

	read(4, boost::bind(&Connection::onHeaderLengthRead, this, _1, _2, _3, _4));
}

std::string Connection::getCallerId()
{
  std::string callerid;
  if (header_.getValue("callerid", callerid))
  {
    return callerid;
  }

  return std::string("unknown");
}

std::string Connection::getRemoteString()
{
  std::stringstream ss;
	ss << "callerid=[" << getCallerId() << "] address=["
	  << transport_->getTransportInfo() << "]";
  return ss.str();
}


}
