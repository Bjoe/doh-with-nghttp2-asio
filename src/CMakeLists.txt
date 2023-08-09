
add_executable(doh)
target_sources(doh
PRIVATE
    main.cpp
    asio_client_session_tls_impl.h
    asio_client_session_tls_impl.cc
)
target_link_libraries(
  doh
  PUBLIC project_options project_warnings

  Boost::headers
  Boost::program_options
  Microsoft.GSL::GSL
  #OpenSSL::SSL
  botan::botan
  nghttp2_asio
#  PRIVATE CLI11::CLI11 fmt::fmt spdlog::spdlog
)

target_include_directories(doh PRIVATE "${CMAKE_BINARY_DIR}/configured_files/include")
