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

#ifndef ROSCPP_CONNECTION_H
#define ROSCPP_CONNECTION_H

#include "ros/header.h"
#include "ros/security/security_module.h"
#include "common.h"

#include <boost/signals2.hpp>

#include <boost/function.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/shared_array.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <openssl/evp.h>

#define READ_BUFFER_SIZE (1024*64)

namespace ros
{

class Transport;
typedef boost::shared_ptr<Transport> TransportPtr;
class Connection;

typedef boost::shared_ptr<Connection> ConnectionPtr;
typedef boost::function<
  void(const ConnectionPtr&, const boost::shared_array<uint8_t>&, uint32_t,
    bool)> ReadFinishedFunc;
typedef boost::function<void(const ConnectionPtr&)> WriteFinishedFunc;
typedef boost::function<bool(const ConnectionPtr&, const Header&)> HeaderReceivedFunc;

/**
 * \brief Encapsulates a connection to a remote host, independent of the
 * transport type
 *
 * Connection provides automatic header negotiation, as well as easy ways of
 * reading and writing arbitrary amounts of data without having to set up your
 * own state machines.
 */
class ROSCPP_DECL Connection : public boost::enable_shared_from_this<Connection>
{
public:
  enum DropReason
  {
    TransportDisconnect,
    HeaderError,
    Destructing,
		SecureConnectionFailed
	};

  Connection();
  ~Connection();

	/**
	 * \brief Initialize this connection, setting up internal state. Attempts to
	 * read a connection header from transport if is_server and header_func is
	 * defined.
	 *
	 * \note Guaranteed not to request any IO from transport until header_func is
	 * defined, or one of setHeaderReceivedCallback or writeHeader methods are
	 * called (this is taken to indicate the caller has already ensured transport
	 * is ready for IO)
	 *
	 * \param transport Actual transport layer implementation
	 * \param is_server Indicates whether this connection should passively wait
	 * 		for requests
	 * \param header_func Callback to handle an incoming Connection Header.
	 */
	void initialize(const TransportPtr& transport, bool is_server,
	    const HeaderReceivedFunc& header_func);
  /**
	 * \brief Drop this connection. Anything added as a drop listener through
	 * addDropListener will get called back when this connection has been
	 * dropped.
   */
  void drop(DropReason reason);
  /**
   * \brief Returns whether or not this connection has been dropped
   */
  bool isDropped();
  /**
	 * \brief Returns true if we're currently sending a header error (and will
	 * be automatically dropped when it's finished)
   */
  bool isSendingHeaderError() { return sending_header_error_; }
  /**
	 * \brief Send a header error message, of the form "error=<message>".  Drops
	 * the connection once the data has written successfully (or fails to write)
	 *
   * \param error_message The error message
   */
  void sendHeaderError(const std::string& error_message);
  /**
   * \brief Send a list of string key/value pairs as a header message.
	 *
	 * \note Under a reliable transport (currently TCPROS), action will be
	 * delayed until both endpoints have change security-related information.
	 *
	 * \param key_vals The values to send: neither keys nor values can have any
	 *  	newlines in them
	 * \param finished_callback The function to call when the header has finished
	 * 		writing
   */
	void writeHeader(const M_string& key_vals,
	    const WriteFinishedFunc& finished_callback);
  /**
   * \brief Read a number of bytes, calling a callback when finished
   *
   * read() will not queue up multiple reads.  Once read() has been called, it is not valid to call it again until the
   * finished callback has been called.  It \b is valid to call read() from within the finished callback.
   *
   * The finished callback is of the form void(const ConnectionPtr&, const boost::shared_array<uint8_t>&, uint32_t)
   *
   * \note The finished callback may be called from within this call to read() if the data has already arrived
   *
   * \param size The size, in bytes, of data to read
   * \param finished_callback The function to call when this read is finished
   */
  void read(uint32_t size, const ReadFinishedFunc& finished_callback);
  /**
   * \brief Write a buffer of bytes, calling a callback when finished
   *
   * write() will not queue up multiple writes.  Once write() has been called, it is not valid to call it again until
   * the finished callback has been called.  It \b is valid to call write() from within the finished callback.
   *
   * * The finished callback is of the form void(const ConnectionPtr&)
   *
   * \note The finished callback may be called from within this call to write() if the data can be written immediately
   *
   * \param buffer The buffer of data to write
   * \param size The size of the buffer, in bytes
   * \param finished_callback The function to call when the write has finished
   * \param immediate Whether to immediately try to write as much data as possible to the socket or to pass
   * the data off to the server thread
   */
	void write(const boost::shared_array<uint8_t>& buffer, uint32_t size,
	  const WriteFinishedFunc& finished_callback, bool immediate = true);

	typedef boost::signals2::signal<void(const ConnectionPtr&, DropReason reason)> DropSignal;
  typedef boost::function<void(const ConnectionPtr&, DropReason reason)> DropFunc;
  /**
   * \brief Add a callback to be called when this connection has dropped
   */
  boost::signals2::connection addDropListener(const DropFunc& slot);
  void removeDropListener(const boost::signals2::connection& c);

  /**
   * \brief Set the header receipt callback
	 *
	 * This method is expected to be called only once and the caller must ensure
	 * that transport is properly initialized for IO.
	 *
	 * \param func Callback that handles a received connection header.
   */
	void setHeaderReceivedCallback(const HeaderReceivedFunc& func);
  /**
   * \brief Get the Transport associated with this connection
   */
  const TransportPtr& getTransport() { return transport_; }
  /**
   * \brief Get the Header associated with this connection
   */
  Header& getHeader() { return header_; }
  /**
	 * \brief Set the Header associated with this connection (used with udpros,
	 *  	which receives the connection header from XMLRPC negotiation).
   */
	void setHeader(const Header& header)
	{
		header_ = header;
	}

  std::string getCallerId();
  std::string getRemoteString();

private:
  /**
   * \brief Called by the Transport when there is data available to be read
   */
  void onReadable(const TransportPtr& transport);
  /**
   * \brief Called by the Transport when it is possible to write data
   */
  void onWriteable(const TransportPtr& transport);
  /**
   * \brief Called by the Transport when it has been disconnected, either through a call to close()
   * or through an error in the connection (such as a remote disconnect)
   */
  void onDisconnect(const TransportPtr& transport);
	/**
	 * \brief Internal callback to handle actual connection-header write by the
	 * underlying transport.
	 */
  void onHeaderWritten(const ConnectionPtr& conn);
  void onErrorHeaderWritten(const ConnectionPtr& conn);
	void onHeaderLengthRead(const ConnectionPtr& conn,
	  const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success);
	void onHeaderRead(const ConnectionPtr& conn,
	  const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success);
	/**
	 * \brief Connection security setup under TCPROS
	 *
	 * Currently includes a Diffie-Hellman exchange so that cryptography can
	 * be used within this connection
	 */
	void doSecurityHandshake();
	void writeSecurityHandshake(const boost::shared_array<uint8_t> &buffer, uint32_t size,
	    const WriteFinishedFunc& finished_callback);
	void onSecurityHandshakeWritten(const ConnectionPtr& conn);
	void onSecurityHandshakeLengthRead(const ConnectionPtr& conn,
	    const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success);
	void onSecurityHandshakeRead(const ConnectionPtr& conn,
	    const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success);
	void onSecurityHandshakeDone(const ConnectionPtr& conn);
	/**
	 * \brief Internal callback: call when the length of an incoming data block
	 * is read from transport under a security-enabled connection.
	 */
	void onSecureBlockLengthRead(const ConnectionPtr& conn,
	    const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success);
	/**
	 * \brief Internal callback: retrieves data received under a security-enabled
	 * connection.
	 */
	void onSecureBlockRead(const ConnectionPtr& conn,
	    const boost::shared_array<uint8_t>& buffer, uint32_t size, bool success);
	/*
	 * \brief Sets internal state according to Connection-Header exchange.
	 */
	void onConnectionHeaderExchangeDone();
	/**
	 * \brief Read size bytes from transport.
	 */
	void readSimple(uint32_t size, const ReadFinishedFunc& callback);
	/**
	 * \brief Read at least size bytes from transport, under a
	 * security-enabled connection.
	 */
	void readSecure(uint32_t size, const ReadFinishedFunc& callback);
	/**
	 * \brief Write size bytes from buffer to transport.
	 */
	void writeSimple(const boost::shared_array<uint8_t>& buffer, uint32_t size,
	  const WriteFinishedFunc& finished_callback, bool immediate);
	/**
	 * \brief Write size bytes from buffer to transport, under a secure
	 * connection.
	 *
	 * \note more than size bytes are likely to be written to transport so that
	 * security-related information is included.
	 */
	void writeSecure(const boost::shared_array<uint8_t>& buffer, uint32_t size,
	    const WriteFinishedFunc& finished_callback, bool immediate);
  /**
   * \brief Read data off our transport.  Also manages calling the read callback.  If there is any data to be read,
   * read() will read it until the fixed read buffer is filled.
   */
  void readTransport();
  /**
   * \brief Write data to our transport.  Also manages calling the write callback.
   */
  void writeTransport();

	/// Are we a server?
  bool is_server_;
  /// Have we dropped?
  bool dropped_;
  /// Incoming header
  Header header_;
  /// Transport associated with us
  TransportPtr transport_;
	/// Handles the incoming header
  HeaderReceivedFunc header_received_callback_;
	/// Indicates whether this connection is ready to call read/write methods
	bool connection_ready_;
	boost::recursive_mutex connection_ready_mutex_;
	std::atomic_flag secure_connection_requested_;
  /// Read buffer that ends up being passed to the read callback
  boost::shared_array<uint8_t> read_buffer_;
  /// Amount of data currently in the read buffer, in bytes
  uint32_t read_filled_;
	/// Capacity of the read buffer, in bytes
  uint32_t read_size_;
  /// Function to call when the read is finished
  ReadFinishedFunc read_callback_;
  /// Mutex used for protecting reading.  Recursive because a read can immediately cause another read through the callback.
  boost::recursive_mutex read_mutex_;
  /// Flag telling us if we're in the middle of a read (mostly to avoid recursive deadlocking)
  bool reading_;
  /// flag telling us if there is a read callback
  /// 32-bit loads and stores are atomic on x86 and PPC... TODO: use a cross-platform atomic operations library
  /// to ensure this is done atomically
  volatile uint32_t has_read_callback_;
	// // appropriate read method to call under this connection (simple/secure)
	boost::function<void(uint32_t, const ReadFinishedFunc&)> read_func_;

	boost::shared_array<uint8_t> buffered_read_;
	uint32_t buffered_read_size_;
	uint32_t buffered_read_capacity_;
	uint32_t buffered_read_offset_;

	// stores off a callback of a pending call to read
	ReadFinishedFunc read_pending_callback_;
	// stores off the number of bytes requested by a pending call to read
	uint32_t read_pending_size_;

  /// Buffer to write from
  boost::shared_array<uint8_t> write_buffer_;
  /// Amount of data we've written from the write buffer
  uint32_t write_sent_;
  /// Size of the write buffer
  uint32_t write_size_;
  /// Function to call when the current write is finished
  WriteFinishedFunc write_callback_;
  boost::mutex write_callback_mutex_;
  /// Mutex used for protecting writing.  Recursive because a write can immediately cause another write through the callback
  boost::recursive_mutex write_mutex_;
  /// Flag telling us if we're in the middle of a write (mostly used to avoid recursive deadlocking)
  bool writing_;
  /// flag telling us if there is a write callback
  /// 32-bit loads and stores are atomic on x86 and PPC... TODO: use a cross-platform atomic operations library
  /// to ensure this is done atomically
  volatile uint32_t has_write_callback_;
  /// Function to call when the outgoing header has finished writing
  WriteFinishedFunc header_written_callback_;
	// appropriate write method to call under this connection (simple/secure)
	boost::function<
	  void(const boost::shared_array<uint8_t>&, uint32_t,
	    const WriteFinishedFunc&, bool)> write_func_;
  /// Signal raised when this connection is dropped
  DropSignal drop_signal_;
  /// Synchronizes drop() calls
  boost::recursive_mutex drop_mutex_;
	/// If we're sending a header error we disable most other calls
  bool sending_header_error_;

	SecurityModulePtr security_module_;

	// TODO(nmf) handle this differently
	//// handles received (public) peer key (during DH exchange); set if
	//// we generated DH keys and a peer key is expected to complete DH exchange)
	PeerKeyRetrievedFunc peer_key_retrieved_callback_;

	/// triggers the proper read call to read a connection header; set by
	/// setHeaderReceivedCallback(); called as soon as connection is
	/// secured, or immediately if security does not apply (udpros)
	boost::function<void()> read_header_func_;
	// triggers the proper write call to write a connection header; set by
	// writeHeader(); called as soon as connection is secured, or immediately
	// if security does not apply (udpros)
	boost::function<void()> write_header_func_;

};
typedef boost::shared_ptr<Connection> ConnectionPtr;

} // namespace ros

#endif // ROSCPP_CONNECTION_H
