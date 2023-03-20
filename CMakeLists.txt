cmake_minimum_required(VERSION 3.25)
project(test_kp_tee)

set(CMAKE_CXX_STANDARD 14)
add_subdirectory(libboundscheck)

include(itrustee_sdk/build/cmake/common.cmake)
include(itrustee_sdk/build/cmake/aarch64_toolchain.cmake)

set(ITRUSTEE_BUILD_PATH ${CMAKE_SOURCE_DIR}/itrustee_sdk)
#message(${ITRUSTEE_BUILD_PATH})


set(Boost_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/boost159/include)
set(Boost_LIBRARY_DIR ${CMAKE_SOURCE_DIR}/boost159/lib)

include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIR})


add_subdirectory(itrustee_client)

add_subdirectory(rsa/CA)
add_subdirectory(rsa/TA)
