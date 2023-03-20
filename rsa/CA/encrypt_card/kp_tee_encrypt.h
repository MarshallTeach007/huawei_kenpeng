//
// Created by dongbo on 2023/3/6.
//

#ifndef TEST_KP_TEE_KP_TEE_ENCRYPT_H
#define TEST_KP_TEE_KP_TEE_ENCRYPT_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "tee_client_api.h"

struct tee_connect {

 public:
    void init();

    int sm4_cbc_encrypt(char *key, char *iv, char *data_, int data_len_, char *back_data_, size_t &back_data_len_, bool padding);

    int sm4_cbc_decrypt(char *key, char *iv, char *data_, int data_len_, char *back_data_, size_t &back_data_len_, bool padding);

    int sm4_ecb_encrypt(char *key, char *data_, int data_len_, char *back_data_, size_t &back_data_len_, bool padding);

    int sm4_ecb_decrypt(char *key, char *data_, int data_len_, char *back_data_, size_t &back_data_len_, bool padding);


    void test();

    ~tee_connect() {
        TEEC_CloseSession(&session);
        TEEC_FinalizeContext(&context);
    }

private:

//    static TEEC_Context context;
//    static TEEC_Session session;

    TEEC_Context context;
    TEEC_Session session;

    TEEC_Result result;
    TEEC_Operation operation;
    uint32_t origin;
    char versionBuf[256];
    unsigned int bufLen;
};

#endif //TEST_KP_TEE_KP_TEE_ENCRYPT_H
