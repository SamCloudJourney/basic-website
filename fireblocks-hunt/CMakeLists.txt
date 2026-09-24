cmake_minimum_required(VERSION 3.16)
project(fireblocks_mpc_research LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED MPC_SOURCE)
  message(FATAL_ERROR "MPC_SOURCE must point to the cloned fireblocks/mpc-lib tree")
endif()

set(MPC_LIB_SKIP_TESTS ON CACHE BOOL "" FORCE)
add_subdirectory("${MPC_SOURCE}" mpc-lib-build)

add_executable(protocol_mutator protocol_mutator.cpp)
target_link_libraries(protocol_mutator PRIVATE cosigner)
target_compile_options(protocol_mutator PRIVATE -Wall -Wextra -Wpedantic)

add_executable(bam_setup_bundle_oracle bam_setup_bundle_oracle.cpp)
target_link_libraries(bam_setup_bundle_oracle PRIVATE cosigner OpenSSL::Crypto)
target_compile_options(bam_setup_bundle_oracle PRIVATE -Wall -Wextra -Wpedantic)
