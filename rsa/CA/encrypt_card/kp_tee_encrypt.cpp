/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: C file template for CA
 */

#include "kp_tee_encrypt.h"
#include <iostream>
#include <gmssl/hex.h>
#include <gmssl/sm4.h>
#include <gmssl/error.h>
#include <gmssl/rand.h>

#include "ca_proto.h"

#define VERSION_BUFFER_SIZE 256
#define OPERATION_START_FLAG 1
#define OUT_BUFF_INDEX 3

//static const TEEC_UUID g_demoTemplateUuid = {0xf68fd704, 0x6eb1, 0x4d14,
//                                             {0xb2, 0x18, 0x72, 0x28, 0x50, 0xeb, 0x3e, 0xf0}};
//


static const TEEC_UUID g_demoTemplateUuid = {
        0xebc87fc2, 0x05dc, 0x41b3,
        {0x85, 0xb9, 0xf9, 0xf0, 0xef, 0x48, 0x1b, 0xad}
};

enum {
    CMD_GET_TA_VERSION = 1,
    CMD_GET_SM4_ECB_ENCRYPT = 2,
    CMD_GET_SM4_ECB_DECRYPT = 3,
    CMD_GET_SM4_CBC_ENCRYPT = 4,
    CMD_GET_SM4_CBC_DECRYPT = 5,
};

static int ca_sm4_ecb_encrypt(TEEC_Session *session,
                              char *key_, char *iv,
                              char *data_, int data_len_,
                              char *back_data, size_t back_data_size, bool padding) {
    TEEC_Result result;
    TEEC_Operation operation = {0};
    uint32_t origin = 0;

    struct proto_msg pm_;
    memcpy(pm_._key, key_, sizeof(pm_._key));
    memset(pm_._iv, 0, sizeof(pm_._iv));
    pm_._len = data_len_;
    pm_._data = data_;
    pm_._padding = padding;

    int msg_str_len = 0;
    char *msg_str = make_msg(&pm_, &msg_str_len);

    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_NONE,
            TEEC_NONE,
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_MEMREF_TEMP_OUTPUT);

    operation.params[OUT_BUFF_INDEX - 1].tmpref.buffer = msg_str;
    operation.params[OUT_BUFF_INDEX - 1].tmpref.size = msg_str_len;
    operation.params[OUT_BUFF_INDEX].tmpref.buffer = back_data;
    operation.params[OUT_BUFF_INDEX].tmpref.size = back_data_size;

    result = TEEC_InvokeCommand(session, CMD_GET_SM4_ECB_ENCRYPT, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        printf("invoke failed, codes=0x%x, origin=0x%x", result, origin);
    } else {
//        printf("sm4_ecb_encrypt Succeed to load TA, result: %s.  \n", back_data);
        free(msg_str);
        return 0;
    }
    free(msg_str);
    return -1;
}

static int ca_sm4_ecb_decrypt(TEEC_Session *session,
                              char *key_, char *iv,
                              char *data_, int data_len_,
                              char *back_data, size_t back_data_size, bool padding)  {
    TEEC_Result result;
    TEEC_Operation operation = {0};
    uint32_t origin = 0;

    struct proto_msg pm_;
    memcpy(pm_._key, key_, sizeof(pm_._key));
    memset(pm_._iv, 0, sizeof(pm_._iv));
    pm_._len = data_len_;
    pm_._data = data_;
    pm_._padding = padding;

    int msg_str_len = 0;
    char *msg_str = make_msg(&pm_, &msg_str_len);

    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_NONE,
            TEEC_NONE,
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_MEMREF_TEMP_OUTPUT);

    operation.params[OUT_BUFF_INDEX - 1].tmpref.buffer = msg_str;
    operation.params[OUT_BUFF_INDEX - 1].tmpref.size = msg_str_len;
    operation.params[OUT_BUFF_INDEX].tmpref.buffer = back_data;
    operation.params[OUT_BUFF_INDEX].tmpref.size = back_data_size;

    result = TEEC_InvokeCommand(session, CMD_GET_SM4_ECB_DECRYPT, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        printf("invoke failed, codes=0x%x, origin=0x%x", result, origin);
    } else {
//        printf("sm4_ecb_decrypt Succeed to load TA, result: %s.\n", back_data);
        free(msg_str);
        return 0;
    }
    free(msg_str);
    return -1;
}

static int ca_sm4_cbc_encrypt(TEEC_Session *session,
                              char *key_, char *iv,
                              char *data_, int data_len_,
                              char *back_data, size_t back_data_size, bool padding) {
    TEEC_Result result;
    TEEC_Operation operation = {0};
    uint32_t origin = 0;

    struct proto_msg pm_;
    memcpy(pm_._key, key_, sizeof(pm_._key));
    memcpy(pm_._iv, iv, sizeof(pm_._iv));
    pm_._len = data_len_;
    pm_._data = data_;
    pm_._padding = padding;

    int msg_str_len = 0;
    char *msg_str = make_msg(&pm_, &msg_str_len);

//    std::cout << msg_str_len<<","<< back_data_size  <<std::endl;

    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_NONE,
            TEEC_NONE,
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_MEMREF_TEMP_OUTPUT);

    operation.params[OUT_BUFF_INDEX - 1].tmpref.buffer = msg_str;
    operation.params[OUT_BUFF_INDEX - 1].tmpref.size = msg_str_len;
    operation.params[OUT_BUFF_INDEX].tmpref.buffer = back_data;
    operation.params[OUT_BUFF_INDEX].tmpref.size = back_data_size;

    result = TEEC_InvokeCommand(session, CMD_GET_SM4_CBC_ENCRYPT, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        printf("invoke failed, codes=0x%x, origin=0x%x", result, origin);
    } else {
//        printf("sm4_cbc_encrypt Succeed to load TA, result: %s.  \n", back_data);
        free(msg_str);
        return 0;
    }
    free(msg_str);
    return -1;
}

static int ca_sm4_cbc_decrypt(TEEC_Session *session,
                              char *key_, char *iv,
                              char *data_, int data_len_,
                              char *back_data, size_t back_data_size, bool padding) {
    TEEC_Result result;
    TEEC_Operation operation = {0};
    uint32_t origin = 0;

    struct proto_msg pm_;
    memcpy(pm_._key, key_, sizeof(pm_._key));
    memcpy(pm_._iv, iv, sizeof(pm_._iv));
    pm_._len = data_len_;
    pm_._data = data_;
    pm_._padding = padding;

    int msg_str_len = 0;
    char *msg_str = make_msg(&pm_, &msg_str_len);

    operation.started = OPERATION_START_FLAG;
    operation.paramTypes = TEEC_PARAM_TYPES(
            TEEC_NONE,
            TEEC_NONE,
            TEEC_MEMREF_TEMP_INOUT,
            TEEC_MEMREF_TEMP_OUTPUT);

    operation.params[OUT_BUFF_INDEX - 1].tmpref.buffer = msg_str;
    operation.params[OUT_BUFF_INDEX - 1].tmpref.size = msg_str_len;
    operation.params[OUT_BUFF_INDEX].tmpref.buffer = back_data;
    operation.params[OUT_BUFF_INDEX].tmpref.size = back_data_size;

    result = TEEC_InvokeCommand(session, CMD_GET_SM4_CBC_DECRYPT, &operation, &origin);
    if (result != TEEC_SUCCESS) {
        printf("invoke failed, codes=0x%x, origin=0x%x", result, origin);
    } else {
//        printf("sm4_cbc_decrypt Succeed to load TA, result: %s.\n", back_data);
        free(msg_str);
        return 0;
    }
    free(msg_str);
    return -1;
}


//TEEC_Context tee_connect::context;
//TEEC_Session tee_connect::session;

void tee_connect::init() {

//    static bool f_context = false;
//
//    if (!f_context) {
        context.ta_path = (uint8_t *) "/home/tee_install/rsa/install/ebc87fc2-05dc-41b3-85b9-f9f0ef481bad.sec";
        result = TEEC_InitializeContext(NULL, &context);
        if (result != TEEC_SUCCESS) {
            printf("teec initial failed");
            exit(-1);
        }


        /* MUST use TEEC_LOGIN_IDENTIFY method */
        operation.started = OPERATION_START_FLAG;
        operation.paramTypes = TEEC_PARAM_TYPES(
                TEEC_NONE,
                TEEC_NONE,
                TEEC_NONE,
                TEEC_NONE);

        result = TEEC_OpenSession(
                &context, &session,
                &g_demoTemplateUuid, TEEC_LOGIN_IDENTIFY, NULL, &operation, &origin);
        if (result != TEEC_SUCCESS) {
            TEEC_FinalizeContext(&context);
            printf("teec open session failed");
            exit(-2);
        }

//        f_context = true;
//    }

    bufLen = VERSION_BUFFER_SIZE;
    std::cout << "tee conn suc" << std::endl;
}

void tee_connect::test() {
    bool  padding  = true;
    std::string s;
    s.resize(67, '@');
    int len = s.length();

    for (int id = 0; id < 2; ++id) {
        char enc_cbc_back_return[1024];
        size_t enc_cbc_back_return_len;
        char dec_back_return[1024];
        size_t dec_back_return_len;



        this->sm4_cbc_encrypt((char*)"1234567890123456", (char*)"1234567890123456",
                              (char *) s.data(), len, enc_cbc_back_return, enc_cbc_back_return_len,padding);

        printf("back_return :%ld\n", enc_cbc_back_return_len);


        this->sm4_cbc_decrypt((char*)"1234567890123456", (char*)"1234567890123456",
                              enc_cbc_back_return, enc_cbc_back_return_len, dec_back_return, dec_back_return_len, padding);

        printf("%d cbc %s %ld\n", id, dec_back_return, dec_back_return_len);
    }


    for (int id = 0; id < 2; id++) {
        char enc_cbc_back_return[1024];
        size_t enc_cbc_back_return_len;
        char dec_back_return[1024];
        size_t dec_back_return_len;

        this->sm4_ecb_encrypt((char*)"1234567890123456",
                              (char *) s.data(), len, enc_cbc_back_return, enc_cbc_back_return_len, padding);

        printf("back_return :%ld\n", enc_cbc_back_return_len);


        this->sm4_ecb_decrypt((char*)"1234567890123456",
                              enc_cbc_back_return, enc_cbc_back_return_len, dec_back_return, dec_back_return_len, padding);

        printf("%d ecb %s %ld\n", id, dec_back_return, dec_back_return_len);

    }
}


int tee_connect::sm4_cbc_encrypt(char *key, char *iv, char *data_,
                                 int data_len_, char *back_data_, size_t &back_data_len_ ,bool padding) {

    std::string enc_data;
    enc_data.resize(data_len_ + 32, 0);
    ca_sm4_cbc_encrypt(&session, key, iv,
                       data_, data_len_, (char *) enc_data.data(), enc_data.length(), padding);

    memcpy(&back_data_len_, enc_data.data(), sizeof(size_t));
    memcpy(back_data_, enc_data.data() + sizeof(size_t), back_data_len_);

    return 0;
}

int tee_connect::sm4_cbc_decrypt(char *key, char *iv, char *data_,
                                 int data_len_, char *back_data_, size_t &back_data_len_,bool padding) {
    std::string dec_data;
    dec_data.resize(data_len_ + 32, 0);
    ca_sm4_cbc_decrypt(&session, key, iv,
                       data_, data_len_, (char *) dec_data.data(), dec_data.length(), padding);

    memcpy(&back_data_len_, dec_data.data(), sizeof(size_t));
    memcpy(back_data_, dec_data.data() + sizeof(size_t), back_data_len_);

    return -1;
}

int tee_connect::sm4_ecb_encrypt(char *key, char *data_, int data_len_,
                                 char *back_data_, size_t &back_data_len_, bool padding) {

    std::string enc_data;
    enc_data.resize(data_len_ + 32, 0);
    ca_sm4_ecb_encrypt(&session, key, NULL,
                       data_, data_len_, (char *) enc_data.data(), enc_data.length(), padding);

    memcpy(&back_data_len_, enc_data.data(), sizeof(size_t));
    memcpy(back_data_, enc_data.data() + sizeof(size_t), back_data_len_);
    return 0;

}

int tee_connect::sm4_ecb_decrypt(char *key, char *data_, int data_len_,
                                 char *back_data_, size_t &back_data_len_,bool padding){

    std::string dec_data;
    dec_data.resize(data_len_ + 32, 0);
    ca_sm4_ecb_decrypt(&session, key, NULL,
                       data_, data_len_, (char *) dec_data.data(), dec_data.length(), padding);

    memcpy(&back_data_len_, dec_data.data(), sizeof(size_t));
    memcpy(back_data_, dec_data.data() + sizeof(size_t), back_data_len_);

    return 0;
}
