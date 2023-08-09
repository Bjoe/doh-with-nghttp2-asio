/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2015 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef DOH_ASIO_CLIENT_SESSION_TLS_IMPL_H
#define DOH_ASIO_CLIENT_SESSION_TLS_IMPL_H

#include <nghttp2/asio_client_session_impl.h>

#include <nghttp2/asio_http2_client.h>

#include <botan/tls.h>
#include <botan/asio_stream.h>

#include <memory>

namespace doh {

class session_tls_impl : public nghttp2::asio_http2::client::session_impl {
public:
  session_tls_impl(boost::asio::io_service &io_service,
                   std::shared_ptr<Botan::TLS::Context> &tls_ctx, const std::string &host,
                   const std::string &service,
                   const boost::posix_time::time_duration &connect_timeout);
  ~session_tls_impl() override;

  void start_connect(boost::asio::ip::tcp::resolver::iterator endpoint_it) override;
  boost::asio::ip::tcp::socket &socket() override;
  void read_socket(
      std::function<void(const boost::system::error_code &ec, std::size_t n)>
      h) override;
  void write_socket(
      std::function<void(const boost::system::error_code &ec, std::size_t n)>
      h) override;
  void shutdown_socket() override;

private:
  Botan::TLS::Stream<boost::asio::ip::tcp::socket> socket_;
};

} // namespace doh

#endif // DOH_ASIO_CLIENT_SESSION_TLS_IMPL_H
