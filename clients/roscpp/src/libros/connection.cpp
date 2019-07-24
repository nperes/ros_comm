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

namespace ros
{

Connection::Connection() :
		    is_server_(false),
		    dropped_(false),
		    connection_ready_(false),
		    secure_connection_requested_(ATOMIC_FLAG_INIT),
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
		    read_header_func_(0)
{
}

Connection::~Connection() {
	ROS_DEBUG_NAMED("superdebug", "Connection destructing, dropped=%s",
	    dropped_ ? "true" : "false");
	drop(Destructing);
}

void Connection::initialize(const TransportPtr& transport, bool is_server,
    const HeaderReceivedFunc& header_func)
{
	ROS_ASSERT(transport);
	ROS_ASSERT(!transport_);

	transport_ = transport;
	is_server_ = is_server;

	transport_->setReadCallback(boost::bind(&Connection::onReadable, this, _1));
	transport_->setWriteCallback(boost::bind(&Connection::onWriteable, this, _1));
	transport_->setDisconnectCallback(
	    boost::bind(&Connection::onDisconnect, this, _1));

	read_func_ = boost::bind(&Connection::readSimple, this, _1, _2);
	write_func_ = boost::bind(&Connection::writeSimple, this, _1, _2, _3, _4);

	if (!transport->requiresHeader())
	{
		connection_ready_ = true;
		return;
	}

	security_module_ = boost::make_shared<SecurityModule>(is_server_);

	if (header_func)
	{
		setHeaderReceivedCallback(header_func);
	}
}

// called once, either from setHeaderReceivedCallback() or from
// writeHeader(); no need to lock yet
void Connection::doSecurityHandshake() {
	ROS_ASSERT(transport_->requiresHeader());
	// caller has initialized the connection-header exchange => transport is
	// ready (no guarantees otherwise!)
	ROS_ASSERT(header_received_callback_ || header_written_callback_);

	if (is_server_)
	{
		read(4,
		    boost::bind(&Connection::onSecurityHandshakeLengthRead, this, _1, _2,
		        _3, _4));
	} else
	{
		boost::shared_array<uint8_t> dh_peer_key;
		size_t dh_peer_key_size;

		if (!security_module_->initialize(dh_peer_key, dh_peer_key_size,
		    peer_key_retrieved_callback_))
		{
			drop(SecureConnectionFailed);
			return;
		}

		read(4,
		    boost::bind(&Connection::onSecurityHandshakeLengthRead, this, _1, _2,
		        _3, _4));
		writeSecurityHandshake(dh_peer_key, dh_peer_key_size,
		    boost::bind(&Connection::onSecurityHandshakeWritten, this, _1));
	}
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
	// indirection to handle sec-enabled vs sec-disabled connections
	read_func_(size, callback);
}

void Connection::readSimple(uint32_t size, const ReadFinishedFunc& callback) {
	{
		boost::recursive_mutex::scoped_lock lock(read_mutex_);

		ROS_ASSERT(!read_callback_);

		read_callback_ = callback;
		has_read_callback_ = 1;
		read_buffer_ = boost::shared_array<uint8_t>(new uint8_t[size]);
		read_size_ = size;
		read_filled_ = 0;
	}

	transport_->enableRead();
	readTransport();
}

void Connection::readSecure(uint32_t size, const ReadFinishedFunc& callback) {

	boost::shared_array<uint8_t> read_return = nullptr;

	{
		boost::recursive_mutex::scoped_lock lock(read_mutex_);

		ROS_ASSERT(!read_callback_);

		if (size <= buffered_read_size_) // can return from buffer
		{
			ROS_DEBUG_NAMED("superdebug",
			    "Can serve read request of [%d] bytes from current buffer of [%d] bytes",
			    size, buffered_read_size_);

			read_return = boost::shared_array<uint8_t>(new uint8_t[size]);

			memcpy(read_return.get(),
			    buffered_read_.get() + buffered_read_offset_,
			    size);

			buffered_read_size_ -= size;
			buffered_read_offset_ += size;
		} else // need to read from transport
		{
			ROS_DEBUG_NAMED("superdebug",
			    "Need to read from transport to serve read request of [%d] bytes as "
					    "current buffer contains only [%d] bytes", size,
			    buffered_read_size_);

			boost::shared_array<uint8_t> tmp = buffered_read_;
			buffered_read_ = boost::shared_array<uint8_t>(new uint8_t[size]);

			if (buffered_read_size_ > 0)
			{
				memcpy(buffered_read_.get(), tmp.get() + buffered_read_offset_,
				    buffered_read_size_);
			}

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

void Connection::onSecureBlockLengthRead(const ConnectionPtr& conn,
    const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success)
{
	ROS_ASSERT(conn.get() == this);
	ROS_ASSERT(size == 4);
	(void) size;

	if (!success)
		return;

	uint32_t len = *((uint32_t*) buffer.get());

	readSimple(len,
	    boost::bind(&Connection::onSecureBlockRead, this, _1, _2, _3, _4));
}

void Connection::onSecureBlockRead(const ConnectionPtr& conn,
    const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success)
{
	ROS_ASSERT(conn.get() == this);

	if (!success)
		return;

	ROS_DEBUG_NAMED("superdebug",
	    "Retrieving secured data from a [%u]-bytes block", size);

	boost::shared_array<uint8_t> retrieved = nullptr;
	uint32_t retrieved_size = 0;

	if (!security_module_->retrieve(buffer.get(), size, retrieved,
	    retrieved_size, 0))
	{
		//TODO(nmf) proper error handling
		retrieved = boost::shared_array<uint8_t>(new uint8_t[0]);
		retrieved_size = 0;
	}

	uint32_t available_bytes_total = retrieved_size + buffered_read_size_;

	ROS_DEBUG_NAMED("superdebug",
	    "Retrieved [%u] of data from secure block of [%u] bytes: progress "
			    "[%u]/[%u]", retrieved_size, size, available_bytes_total,
	    read_pending_size_);

	if (read_pending_size_ > available_bytes_total)
	{
		memcpy(buffered_read_.get() + buffered_read_size_, retrieved.get(),
		    retrieved_size);
		buffered_read_size_ += retrieved_size;

		readSimple(4,
		    boost::bind(&Connection::onSecureBlockLengthRead, this, _1, _2, _3,
		        _4));
	} else
	{
		uint32_t required_bytes = read_pending_size_ - buffered_read_size_;
		memcpy(buffered_read_.get() + buffered_read_size_, retrieved.get(),
		    required_bytes);

		//TODO(nmf) rethink this
		buffered_read_.swap(retrieved);
		boost::shared_array<uint8_t> pending_read = retrieved;

		buffered_read_size_ = retrieved_size - required_bytes;
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
	ROS_ASSERT(buffer);
	ROS_ASSERT(size > 0);
	ROS_ASSERT(callback);

  if (dropped_ || sending_header_error_)
	{
    return;
	}

	// added indirection level to handle secure vs insecure connections
	write_func_(buffer, size, callback, immediate);

	if (write_size_ == 0)
	{
		ROS_WARN("Dropping write request due to fail in securing message");

		{
			boost::mutex::scoped_lock lock(write_callback_mutex_);
			ROS_ASSERT(has_write_callback_);
			write_callback_ = WriteFinishedFunc();
			write_buffer_ = boost::shared_array<uint8_t>();
			write_sent_ = 0;
			write_size_ = 0;
			has_write_callback_ = 0;
		}

		callback(shared_from_this());

		return;
	}

  transport_->enableWrite();
	if (immediate)
	{
		// write immediately if possible
    writeTransport();
	}
}

void Connection::writeSimple(const boost::shared_array<uint8_t>& buffer,
  uint32_t size, const WriteFinishedFunc& callback, bool immediate) {

	(void) immediate;

	{
		boost::mutex::scoped_lock lock(write_callback_mutex_);

		ROS_ASSERT(!write_callback_);

		write_callback_ = callback;
		has_write_callback_ = 1;
		write_sent_ = 0;
		write_buffer_ = buffer;
		write_size_ = size;
	}
}

// requires: write_callback_ set
void Connection::writeSecure(const boost::shared_array<uint8_t>& buffer,
    uint32_t size, const WriteFinishedFunc& callback, bool immediate) {

	(void) immediate;

	boost::shared_array<uint8_t> secure_data = nullptr;
	uint32_t secure_data_len = 0;

	if (security_module_->secure(buffer.get(), size, secure_data, secure_data_len,
	    4))
	{
		ROS_DEBUG_NAMED("superdebug",
				"Secured [%u] bytes worth of data, setting the write size to a total "
						"of [%u] bytes", size, write_size_);

		*((uint32_t*) secure_data.get()) = secure_data_len;

		{
			boost::mutex::scoped_lock lock(write_callback_mutex_);

			ROS_ASSERT(!write_callback_);

			write_callback_ = callback;
			has_write_callback_ = 1;
			write_sent_ = 0;
			write_buffer_ = secure_data;
			write_size_ = 4 + secure_data_len;
		}

		return;
	}

	write_size_ = 0;
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

// beware: TransportSubscriberLink::handleHeader() calls us even under UDP; if
// !transport->requiresHeader() we are still expected to trigger the callback
void Connection::writeHeader(const M_string& key_vals,
  const WriteFinishedFunc& finished_callback)
{
	ROS_ASSERT(finished_callback);

	bool has_previous_secure_connection_call =
	    secure_connection_requested_.test_and_set();
	bool connection_ready;

	if (!transport_->requiresHeader())
	{
		{
			boost::recursive_mutex::scoped_lock lock(connection_ready_mutex_);

			ROS_ASSERT(!header_written_callback_);
			header_written_callback_ = finished_callback;
		}

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
		boost::recursive_mutex::scoped_lock lock(connection_ready_mutex_);

		ROS_ASSERT(!header_written_callback_);
		header_written_callback_ = finished_callback;

		write_header_func_ = boost::bind(&Connection::write, this, full_msg,
		    msg_len,
		    WriteFinishedFunc(boost::bind(&Connection::onHeaderWritten, this, _1)),
		    false);
		connection_ready = connection_ready_;
	}

	if (!has_previous_secure_connection_call)
	{
		ROS_DEBUG_NAMED("superdebug",
		    "Delaying [%u] bytes worth write header request until connection is "
				    "ready", len);
		doSecurityHandshake();
	} else if (connection_ready)
	{
		write_header_func_();
	}
}

void Connection::writeSecurityHandshake(
    const boost::shared_array<uint8_t>& buffer, uint32_t size,
    const WriteFinishedFunc& finished_callback)
{
	uint32_t dh_exchange_size = 4 + size;
	boost::shared_array<uint8_t> dh_exchange = boost::shared_array<uint8_t>(
	    new uint8_t[dh_exchange_size]);
	memcpy(dh_exchange.get() + 4, buffer.get(), size);
	*((uint32_t*) dh_exchange.get()) = size;

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
		return;
  }

	std::string error_val;
	if (header_.getValue("error", error_val))
	{
		ROSCPP_LOG_DEBUG(
		    "Received error message in header  for connection to [%s]: [%s]",
		    transport_->getTransportInfo().c_str(), error_val.c_str());
		drop(HeaderError);
		return;
	}

	std::string hmacs, encryption;
	if (header_.getValue("hmacs", hmacs) && hmacs != "0" && hmacs != "1")
	{
		ROSCPP_LOG_DEBUG("Header element \"hmacs\" had invalid value");
		drop(HeaderError);
		return;
	}
	else if (header_.getValue("encryption", encryption) && encryption != "0"
	    && encryption != "1")
	{
		ROSCPP_LOG_DEBUG("Header element \"encryption\" had invalid value");
		drop(HeaderError);
		return;
	}


	// consequence of broken encapsulation of transport in service.cpp
	// (called outside a connection)
	std::string probe_val;
	if (!connection_ready_ && !header_.getValue("probe", probe_val))
	{
		ROSCPP_LOG_DEBUG(
		    "Received actual connection header before security exchange for connection [%s]: only probe header allowed",
		    transport_->getTransportInfo().c_str());
		drop(HeaderError);
		return;
	}

	ROS_ASSERT(header_received_callback_);
	transport_->parseHeader(header_);

	if (!is_server_)
	{
		onConnectionHeaderExchangeDone();
	}

	header_received_callback_(conn, header_);
}

void Connection::onSecurityHandshakeWritten(const ConnectionPtr& conn)
{
	(void) conn;
	ROS_ASSERT(conn.get() == this);
}

void Connection::onSecurityHandshakeLengthRead(const ConnectionPtr& conn,
    const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success)
{
	ROS_ASSERT(conn.get() == this);
	ROS_ASSERT(size == 4);
	(void) size;

	if (!success)
		return;

	uint32_t len = *((uint32_t*) buffer.get());

	//TODO(nmf) proper error handling
	if (len > 1000000000) {
		ROS_ERROR("a secure connection header of over a gigabyte was "
			"predicted in tcpros. that seems highly "
			"unlikely, so I'll assume protocol "
			"synchronization is lost.");
		conn->drop(HeaderError);
	}

	ROS_DEBUG_NAMED("superdebug",
	    "Calling to read secure connection header of [%u] bytes worth length",
	    size);

	read(len, boost::bind(&Connection::onSecurityHandshakeRead, this, _1, _2, _3, _4));
}

void Connection::onSecurityHandshakeRead(const ConnectionPtr& conn,
    const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success)
{
	ROS_ASSERT(conn.get() == this);
	if (!success)
	{
		return;
	}

	if (!security_module_->dhParseKey(buffer.get(), size))
	{
		drop(SecureConnectionFailed);
		return;
	}

	if (peer_key_retrieved_callback_)
	{
		peer_key_retrieved_callback_(buffer, size);
		onSecurityHandshakeDone(conn);
		return;
	}

	boost::shared_array<uint8_t> dh_public_key = nullptr;
	size_t dh_public_key_size = 0;

	if (security_module_->initialize(dh_public_key, dh_public_key_size, buffer,
	    size))
	{
		writeSecurityHandshake(dh_public_key, dh_public_key_size,
		    boost::bind(&Connection::onSecurityHandshakeDone, this, _1));
		return;
	}

	//TODO(nmf) do proper error handling
	drop(SecureConnectionFailed);
}

void Connection::onSecurityHandshakeDone(const ConnectionPtr& conn)
{
	ROS_ASSERT(conn.get() == this);

	(void) conn;

	boost::function<void()> read_header_func = 0;
	boost::function<void()> write_header_func = 0;

	{
		boost::recursive_mutex::scoped_lock lock(connection_ready_mutex_);

		ROS_ASSERT(!connection_ready_);

		security_module_->setHmacs(true).setEncryption(true);
		read_func_ = boost::bind(&Connection::readSecure, this, _1, _2);
		write_func_ = boost::bind(&Connection::writeSecure, this, _1, _2, _3, _4);

		connection_ready_ = true;

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

void Connection::onConnectionHeaderExchangeDone()
{
	ROS_ASSERT(transport_->requiresHeader());

	std::string hmacs, encryption;
	header_.getValue("hmacs", hmacs);
	header_.getValue("encryption", encryption);

	fprintf(stderr, "[%s]\n", hmacs.c_str());
	fprintf(stderr, "[%s]\n", encryption.c_str());

	if (hmacs == "0" && encryption == "0")
	{
		fprintf(stderr, "no security\n");
		read_func_ = boost::bind(&Connection::readSimple, this, _1, _2);
		write_func_ = boost::bind(&Connection::writeSimple, this, _1, _2, _3, _4);
	} else
	{
		fprintf(stderr, "using security\n");
		read_func_ = boost::bind(&Connection::readSecure, this, _1, _2);
		write_func_ = boost::bind(&Connection::writeSecure, this, _1, _2, _3, _4);

		security_module_->setHmacs(hmacs == "1").setEncryption(encryption == "1");
	}
}

// note: might get called even when no header has actually been written - see
// writeHeader(); regardless, always trigger the callback
void Connection::onHeaderWritten(const ConnectionPtr& conn)
{
	ROS_ASSERT(conn.get() == this);
	ROS_ASSERT(header_written_callback_);

	if (transport_->requiresHeader() && is_server_)
	{
		onConnectionHeaderExchangeDone();
	}

	header_written_callback_(conn);
}

void Connection::onErrorHeaderWritten(const ConnectionPtr& conn)
{
  (void)conn;
  drop(HeaderError);
}


// important to keep original code semantics:
// sets header_func_ and returns if !transport->requiresHeader();
void Connection::setHeaderReceivedCallback(const HeaderReceivedFunc& func)
{
	ROS_ASSERT(func);
	ROS_ASSERT(!header_received_callback_);

	bool has_previous_secure_connection_call =
	    secure_connection_requested_.test_and_set();
	bool connection_ready;

	{
		boost::recursive_mutex::scoped_lock lock(connection_ready_mutex_);

		header_received_callback_ = func;
		read_header_func_ = boost::bind(&Connection::read, this, 4,
		    ReadFinishedFunc(
		        boost::bind(&Connection::onHeaderLengthRead, this, _1, _2, _3,
		            _4)));
		connection_ready = connection_ready_;
	}

	if (!transport_->requiresHeader())
	{
		return;
	}

	if (!has_previous_secure_connection_call)
	{
		ROS_DEBUG_NAMED("superdebug",
		    "Delaying read header request until connection is ready");
		doSecurityHandshake();
		return;
	}

	if (connection_ready)
	{
		read_header_func_();
	}
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
