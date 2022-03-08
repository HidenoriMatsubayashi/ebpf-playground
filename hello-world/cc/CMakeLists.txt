cmake_minimum_required(VERSION 3.15)

set(CMAKE_CXX_STANDARD 17)
project("hello_world" LANGUAGES CXX)

find_package(PkgConfig)
pkg_check_modules(LIBBCC REQUIRED IMPORTED_TARGET libbcc)

set(BINARY_NAME hello_world)
add_executable(${BINARY_NAME}
  "src/main.cc"
)

target_include_directories(${BINARY_NAME} PRIVATE "src")
target_include_directories(${BINARY_NAME} PRIVATE PkgConfig::LIBBCC)
target_link_libraries(${BINARY_NAME} PRIVATE bcc)
