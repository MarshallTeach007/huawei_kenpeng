cmake_minimum_required(VERSION 3.16)
project(encrypt_card)

set(CMAKE_CXX_STANDARD 14)

include_directories(
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/depend/boost159/include
)

message( ${CMAKE_SOURCE_DIR}/depend/boost159/include)

#add_definitions(-Wno-error=unused-but-set-variable)
#add_definitions(-Wno-warn=unused-but-set-variable)
add_definitions(-Wno-missing-field-initializers)
add_definitions(-Wno-error=format=)
add_definitions(-Wno-unused-result)
add_definitions(-Wno-parentheses)
add_definitions(-Wno-sign-compare)
add_definitions(-Wno-unused-variable)

include_directories(sdf)
include_directories(kp_tee_ca_include)
include_directories(.)
link_directories(${CMAKE_SOURCE_DIR}/depend/boost159/lib)  #fuckbugs

IF (CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
        include_directories(nvx_soft_sdf)
        add_library(nvx_soft_sdf_crypto STATIC nvx_soft_sdf/sdf_crypt.cpp)

        add_executable(multi-core-ta1
                kp_tee_test/test1.cpp
                kp_tee_encrypt.cpp kp_tee_encrypt.h
                #kp_tee_ca_src/libteec_adaptor.c
                )
        target_link_libraries(multi-core-ta1 -ldl -lpthread
                nvx_boundscheck nvx_teec /usr/local/ssl/lib/libgm_ssl.a)
        install(TARGETS multi-core-ta1 DESTINATION bin)

        add_executable(encrypt_card main.cpp  encryption_card.h encryption_card.cpp
                kp_tee_encrypt.cpp kp_tee_encrypt.h
                #kp_tee_ca_src/libteec_adaptor.c
                )
        target_link_libraries(encrypt_card
                nvx_boundscheck nvx_teec
                ${CMAKE_SOURCE_DIR}/depend/boost159/lib/libboost_system.a
                ${CMAKE_SOURCE_DIR}/depend/boost159/lib/libboost_thread.a
                nvx_soft_sdf_crypto -lpthread -lrt)

        add_executable(encrypt_card_clean encrypt_card_clean.cpp)
        target_link_libraries(encrypt_card_clean
                ${CMAKE_SOURCE_DIR}/depend/boost159/lib/libboost_system.a
                ${CMAKE_SOURCE_DIR}/depend/boost159/lib/libboost_thread.a
                nvx_soft_sdf_crypto -lpthread -lrt)

         install(TARGETS  nvx_soft_sdf_crypto  DESTINATION lib64)
ELSE ()

        message("x86")
        link_directories(${CMAKE_SOURCE_DIR}/mysys_ssl/encrypt_card/sdf/bin)

        add_executable(encrypt_card main.cpp encryption_card.h encryption_card.cpp)
        target_link_libraries(encrypt_card
                ${CMAKE_SOURCE_DIR}/depend/boost159/lib/libboost_system.a
                ${CMAKE_SOURCE_DIR}/depend/boost159/lib/libboost_thread.a
                ${CMAKE_SOURCE_DIR}/mysys_ssl/encrypt_card/sdf/bin/libsdf_crypto.so -lpthread -lrt)


        add_executable(encrypt_card_clean encrypt_card_clean.cpp)
        target_link_libraries(encrypt_card_clean
                ${CMAKE_SOURCE_DIR}/depend/boost159/lib/libboost_system.a
                ${CMAKE_SOURCE_DIR}/depend/boost159/lib/libboost_thread.a
                ${CMAKE_SOURCE_DIR}/mysys_ssl/encrypt_card/sdf/bin/libsdf_crypto.so -lpthread -lrt)

        install(FILES ${CMAKE_SOURCE_DIR}/mysys_ssl/encrypt_card/sdf/bin/libsdf_crypto.so  DESTINATION lib64)
ENDIF ()
