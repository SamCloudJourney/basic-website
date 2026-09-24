cmake_minimum_required(VERSION 3.16)
project(fireblocks_mpc_parser_research LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED MPC_SOURCE)
  message(FATAL_ERROR "MPC_SOURCE must point to fireblocks/mpc-lib")
endif()

set(MPC_LIB_SKIP_TESTS ON CACHE BOOL "" FORCE)
add_subdirectory("${MPC_SOURCE}" mpc-lib-build)

add_executable(parser_mutator parser_mutator.cpp)
target_link_libraries(parser_mutator PRIVATE cosigner)
target_compile_options(parser_mutator PRIVATE -Wall -Wextra -Wpedantic)
