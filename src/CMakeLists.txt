
add_executable(doh main.cpp)
target_link_libraries(
  doh
  PUBLIC project_options project_warnings

  Boost::headers
  Boost::program_options
  Microsoft.GSL::GSL
  OpenSSL::SSL
  nghttp2_asio
#  PRIVATE CLI11::CLI11 fmt::fmt spdlog::spdlog
)

target_include_directories(doh PRIVATE "${CMAKE_BINARY_DIR}/configured_files/include")
