cmake_minimum_required (VERSION 2.8)

project (pe-parse)

if(UNIX)
  set(CMAKE_CXX_FLAGS "-std=c++11")
endif(UNIX)

add_subdirectory(parser-library)
add_subdirectory(dump-prog)
