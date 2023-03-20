cmake_minimum_required(VERSION 3.16)
project(librsa-demo)

if (PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(FATAL_ERROR "Forbid compiling in the source tree")
endif()

# TEE flags
set(COMMON_CFLAGS -DAPI_LEVEL=1)
if ("${TARGET_IS_ARM64}" STREQUAL "")
    set(TARGET_IS_ARM64 y)
endif()


# USE_SMEE which indicates the feature of sram memory encryption
# set(USE_SMEE y) indicates the feature of sram memory encryption will be enabled
# If no USE_SMEE is specified, smee feature will be disabled
# If USE_SMEE is specified and a section is custimized,
# explicitly specify the segment to which the section belongs in the link script(ta_link_64.smee.ld)
set(USE_SMEE n)
if ("${USE_SMEE}" STREQUAL "")
    set(USE_SMEE n)
endif()

include_directories(include)

add_definitions(-fPIC)
include_directories(/usr/local/ssl/include)
include_directories(../../itrustee_sdk/include/TA)
include_directories(../../itrustee_sdk/include/TA/huawei_ext)
include_directories(../../libboundscheck/include)

set(LIBRARY_OUTPUT_PATH rsa-demo)
set(CURRENT_TARGET_SO "combine")

set(SDK_C_SOURCES
    ${SDK_C_SOURCES} ta_demo.c
)


add_definitions(-fPIC)
set(ITRUSTEE_BUILD_PATH ../../../../../itrustee_sdk)


add_library(${CURRENT_TARGET_SO} SHARED ${SDK_C_SOURCES})
target_include_directories(${CURRENT_TARGET_SO} PUBLIC ${COMMON_INCLUDES})
target_compile_options(${CURRENT_TARGET_SO} PRIVATE ${COMMON_CFLAGS})
target_link_options(${CURRENT_TARGET_SO} PRIVATE ${COMMON_LDFLAGS})

target_link_libraries(${CURRENT_TARGET_SO}  /usr/local/ssl/lib/libgm_ssl.a)
#
#target_link_libraries(${CURRENT_TARGET_SO}  find -static-libstdc++ )

install(TARGETS ${CURRENT_TARGET_SO} DESTINATION install)
install(FILES manifest.txt DESTINATION install)

#add_custom_command(
#   TARGET ${CURRENT_TARGET_SO} POST_BUILD
#   COMMAND ${CMAKE_OBJCOPY} libcombine.so
#   COMMAND python3 -B
#        ${ITRUSTEE_BUILD_PATH}/build/signtools/signtool_v3.py
#        ${ITRUSTEE_BUILD_PATH}/test/TA/rsa-demo
#        ${ITRUSTEE_BUILD_PATH}/test/TA/rsa-demo
#        --config ${ITRUSTEE_BUILD_PATH}/build/signtools/config_cloud.ini
#)
