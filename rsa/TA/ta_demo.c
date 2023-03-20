/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2023. All rights reserved.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: TA template code for reference
 */

#include "huawei_ext/tee_ext_api.h"
#include "huawei_ext/tee_log.h"
#include "./securec.h"
#include "../proto.h"

#include <gmssl/hex.h>
#include <gmssl/sm4.h>
#include <gmssl/error.h>
#include <gmssl/rand.h>


static int test_sm4_cbc(char *_tmp) {
    SM4_KEY sm4_key;
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    uint8_t buf1[32] = {0};
    uint8_t buf2[32] = {0};
    uint8_t buf3[32] = {0};

    sm4_set_encrypt_key(&sm4_key, key);
    sm4_cbc_encrypt(&sm4_key, iv, buf1, 2, buf2);
    sm4_set_decrypt_key(&sm4_key, key);
    sm4_cbc_decrypt(&sm4_key, iv, buf2, 2, buf3);

    if (memcmp(buf1, buf3, sizeof(buf3)) != 0) {
        fprintf(stderr, "%s %d: error\n", __FILE__, __LINE__);
        return -1;
    }

    return sprintf(_tmp, "%s() ok\n", "awfsadf_____________");
//    return 1;
}


#define TA_TEMPLATE_VERSION "demo_dasfa00601"
#define PARAM_COUNT      4
#define OUT_BUFFER_INDEX 3

enum {
    CMD_GET_TA_VERSION = 1,
    CMD_GET_SM4_ECB_ENCRYPT = 2,
    CMD_GET_SM4_ECB_DECRYPT = 3,
    CMD_GET_SM4_CBC_ENCRYPT = 4,
    CMD_GET_SM4_CBC_DECRYPT = 5,
};


static TEE_Result get_ta_version(char *buffer, size_t *buf_len) {
    const char *version = TA_TEMPLATE_VERSION;
    if (*buf_len < strlen(version) + 1) {
        tloge("buffer is too short for storing result");
        *buf_len = strlen(version) + 1;
        return TEE_ERROR_SHORT_BUFFER;
    }

    errno_t err = strncpy_s(buffer, *buf_len, version, strlen(version) + 1);
    if (err != EOK)
        return TEE_ERROR_SECURITY;

    *buf_len = strlen(version) + 1;
    return TEE_SUCCESS;
}


static TEE_Result ta_sm4_ecb_encrypt(char *buffer, size_t buf_len, char *out_buffer, size_t *out_buffer_size) {

    struct proto_msg *msg_ = split_msg(buffer, buf_len);
    if (msg_ == NULL) {
        printf("%s \n", "split msg err");
        return TEE_ERROR_EXCESS_DATA;
    }

    SM4_KEY sm4_key;
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    memcpy(key, msg_->_key, sizeof(key));
    memset(iv, 0, sizeof(iv));

    size_t out_buffer_len;
    sm4_set_encrypt_key(&sm4_key, key);

    if (msg_->_padding) {
        sm4_cbc_padding_encrypt(&sm4_key, iv,
                                (uint8_t *) msg_->_data, msg_->_len,
                                (uint8_t *) out_buffer + sizeof(size_t), &out_buffer_len);

    } else {
        sm4_cbc_encrypt(&sm4_key, iv,
                        (uint8_t *) msg_->_data, msg_->_len / 16,
                        (uint8_t *) out_buffer + sizeof(size_t));
        out_buffer_len = msg_->_len;
    }

    memcpy(out_buffer, &out_buffer_len, sizeof(size_t));

//    printf("ta_sm4_cbc_encrypt: %s %d out_buffer_len:%ld\n", msg_->_data, msg_->_len, out_buffer_len);

    free(msg_->_data);
    free(msg_);

    return TEE_SUCCESS;
}


static TEE_Result ta_sm4_ecb_decrypt(char *buffer, size_t buf_len, char *out_buffer, size_t *out_buffer_size) {
    struct proto_msg *msg_ = split_msg(buffer, buf_len);

    SM4_KEY sm4_key;
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    memcpy(key, msg_->_key, sizeof(key));
    memset(iv, 0, sizeof(iv));

    sm4_set_decrypt_key(&sm4_key, key);
    size_t out_buffer_len;
    if (msg_->_padding) {
        sm4_cbc_padding_decrypt(&sm4_key, iv,
                                (uint8_t *) msg_->_data, msg_->_len,
                                (uint8_t *) out_buffer + sizeof(size_t), &out_buffer_len);
    } else {
        sm4_cbc_decrypt(&sm4_key, iv,
                        (uint8_t *) msg_->_data, msg_->_len / 16,
                        (uint8_t *) out_buffer + sizeof(size_t));
        out_buffer_len = msg_->_len;
    }

    memcpy(out_buffer, &out_buffer_len, sizeof(size_t));

//    printf("--> %s %ld msg_->_len:%ld\n",out_buffer + sizeof(size_t), out_buffer_len,msg_->_len);
    free(msg_->_data);
    free(msg_);

    return TEE_SUCCESS;
}


static TEE_Result ta_sm4_cbc_encrypt(char *buffer, size_t buf_len, char *out_buffer, size_t *out_buffer_size) {

    struct proto_msg *msg_ = split_msg(buffer, buf_len);
    if (msg_ == NULL) {
        printf("%s \n", "split msg err");
        return TEE_ERROR_EXCESS_DATA;
    }

    SM4_KEY sm4_key;
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    memcpy(key, msg_->_key, sizeof(key));
    memcpy(iv, msg_->_iv, sizeof(iv));

    size_t out_buffer_len;
    sm4_set_encrypt_key(&sm4_key, key);
    if (msg_->_padding) {
        sm4_cbc_padding_encrypt(&sm4_key, iv,
                                (uint8_t *) msg_->_data, msg_->_len,
                                (uint8_t *) out_buffer + sizeof(size_t), &out_buffer_len);
    } else {
        sm4_cbc_encrypt(&sm4_key, iv,
                        (uint8_t *) msg_->_data, msg_->_len / 16,
                        (uint8_t *) out_buffer + sizeof(size_t));
        out_buffer_len = msg_->_len;
    }

    memcpy(out_buffer, &out_buffer_len, sizeof(size_t));

//    printf("ta_sm4_cbc_encrypt: %s %d out_buffer_len:%ld\n", msg_->_data, msg_->_len, out_buffer_len);

    free(msg_->_data);
    free(msg_);

    return TEE_SUCCESS;
}


static TEE_Result ta_sm4_cbc_decrypt(char *buffer, size_t buf_len, char *out_buffer, size_t *out_buffer_size) {
    struct proto_msg *msg_ = split_msg(buffer, buf_len);

    SM4_KEY sm4_key;
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    memcpy(key, msg_->_key, sizeof(key));
    memcpy(iv, msg_->_iv, sizeof(iv));

    sm4_set_decrypt_key(&sm4_key, key);
    size_t out_buffer_len;
    if (msg_->_padding) {
        sm4_cbc_padding_decrypt(&sm4_key, iv,
                                (uint8_t *) msg_->_data, msg_->_len,
                                (uint8_t *) out_buffer + sizeof(size_t), &out_buffer_len);
    } else {
        sm4_cbc_decrypt(&sm4_key, iv,
                        (uint8_t *) msg_->_data, msg_->_len / 16,
                        (uint8_t *) out_buffer + sizeof(size_t));
        out_buffer_len = msg_->_len;
    }

    memcpy(out_buffer, &out_buffer_len, sizeof(size_t));

//    printf("--> %s %ld msg_->_len:%ld\n",out_buffer + sizeof(size_t), out_buffer_len,msg_->_len);
    free(msg_->_data);
    free(msg_);

    return TEE_SUCCESS;
}


/**
 * Function TA_CreateEntryPoint
 * Description:
 *   The function TA_CreateEntryPoint is the Trusted Application's constructor,
 *   which the Framework calls when it creates a new instance of this Trusted Application.
 */
TEE_Result TA_CreateEntryPoint(void) {
    TEE_Result ret;

    tlogd("----- TA entry point ----- ");
    tlogd("TA version: %s", TA_TEMPLATE_VERSION);

    ret = addcaller_ca_exec(
            "/usr/local/nvx_mysql_5.7/bin/multi-core-ta",
            "root");
    if (ret == TEE_SUCCESS) {
        tlogd("TA entry point: add ca whitelist success");
    } else {
        tloge("TA entry point: add ca whitelist failed");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

/**
 * Function TA_OpenSessionEntryPoint
 * Description:
 *   The Framework calls the function TA_OpenSessionEntryPoint
 *   when a client requests to open a session with the Trusted Application.
 *   The open session request may result in a new Trusted Application instance
 *   being created.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t parm_type,
                                    TEE_Param params[PARAM_COUNT], void **session_context) {
    (void) parm_type;
    (void) params;
    (void) session_context;
    tlogd("---- TA open session -------- ");

    return TEE_SUCCESS;
}

/**
 * Function TA_InvokeCommandEntryPoint:
 * Description:
 *   The Framework calls this function when the client invokes a command
 *   within the given session.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t cmd,
                                      uint32_t parm_type, TEE_Param params[PARAM_COUNT]) {
    TEE_Result ret;
    (void) session_context;

    tlogd("---- TA invoke command ----------- ");
    switch (cmd) {
        case CMD_GET_TA_VERSION:
            if (!check_param_type(parm_type,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_MEMREF_INOUT,
                                  TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
                tloge("Bad expected parameter types");
                return TEE_ERROR_BAD_PARAMETERS;
            }
            if (params[OUT_BUFFER_INDEX].memref.buffer == NULL ||
                params[OUT_BUFFER_INDEX].memref.size == 0) {
                tloge("InvokeCommand with bad, cmd is %u", cmd);
                return TEE_ERROR_BAD_PARAMETERS;
            }

            ret = get_ta_version(params[OUT_BUFFER_INDEX - 1].memref.buffer,
                                 &params[OUT_BUFFER_INDEX - 1].memref.size);
            if (ret != TEE_SUCCESS) {
                tloge("InvokeCommand Failed 0x%x. cmd is %u", ret, cmd);
                return ret;
            }
            break;

        case CMD_GET_SM4_ECB_ENCRYPT:
            if (!check_param_type(parm_type,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_MEMREF_INOUT,
                                  TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
                tloge("Bad expected parameter types");
                return TEE_ERROR_BAD_PARAMETERS;
            }
            if (params[OUT_BUFFER_INDEX].memref.buffer == NULL ||
                params[OUT_BUFFER_INDEX].memref.size == 0) {
                tloge("InvokeCommand with bad, cmd is %u", cmd);
                return TEE_ERROR_BAD_PARAMETERS;
            }

            ret = ta_sm4_ecb_encrypt(params[OUT_BUFFER_INDEX - 1].memref.buffer,
                                     params[OUT_BUFFER_INDEX - 1].memref.size,
                                     params[OUT_BUFFER_INDEX].memref.buffer,
                                     &params[OUT_BUFFER_INDEX].memref.size);
            if (ret != TEE_SUCCESS) {
                tloge("InvokeCommand ta_sm4_ecb_encrypt Failed 0x%x. cmd is %u", ret, cmd);
                return ret;
            }
            break;


        case CMD_GET_SM4_ECB_DECRYPT:
            if (!check_param_type(parm_type,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_MEMREF_INOUT,
                                  TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
                tloge("Bad expected parameter types");
                return TEE_ERROR_BAD_PARAMETERS;
            }
            if (params[OUT_BUFFER_INDEX].memref.buffer == NULL ||
                params[OUT_BUFFER_INDEX].memref.size == 0) {
                tloge("InvokeCommand with bad, cmd is %u", cmd);
                return TEE_ERROR_BAD_PARAMETERS;
            }

            ret = ta_sm4_ecb_decrypt(params[OUT_BUFFER_INDEX - 1].memref.buffer,
                                     params[OUT_BUFFER_INDEX - 1].memref.size,
                                     params[OUT_BUFFER_INDEX].memref.buffer,
                                     &params[OUT_BUFFER_INDEX].memref.size);
            if (ret != TEE_SUCCESS) {
                tloge("InvokeCommand ta_sm4_ecb_decrypt Failed 0x%x. cmd is %u", ret, cmd);
                return ret;
            }
            break;
        case CMD_GET_SM4_CBC_ENCRYPT:
            if (!check_param_type(parm_type,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_MEMREF_INOUT,
                                  TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
                tloge("Bad expected parameter types");
                return TEE_ERROR_BAD_PARAMETERS;
            }
            if (params[OUT_BUFFER_INDEX].memref.buffer == NULL ||
                params[OUT_BUFFER_INDEX].memref.size == 0) {
                tloge("InvokeCommand with bad, cmd is %u", cmd);
                return TEE_ERROR_BAD_PARAMETERS;
            }

            ret = ta_sm4_cbc_encrypt(params[OUT_BUFFER_INDEX - 1].memref.buffer,
                                     params[OUT_BUFFER_INDEX - 1].memref.size,
                                     params[OUT_BUFFER_INDEX].memref.buffer,
                                     &params[OUT_BUFFER_INDEX].memref.size);
            if (ret != TEE_SUCCESS) {
                tloge("InvokeCommand ta_sm4_cbc_encrypt Failed 0x%x. cmd is %u", ret, cmd);
                return ret;
            }
            break;


        case CMD_GET_SM4_CBC_DECRYPT:
            if (!check_param_type(parm_type,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_MEMREF_INOUT,
                                  TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
                tloge("Bad expected parameter types");
                return TEE_ERROR_BAD_PARAMETERS;
            }
            if (params[OUT_BUFFER_INDEX].memref.buffer == NULL ||
                params[OUT_BUFFER_INDEX].memref.size == 0) {
                tloge("InvokeCommand with bad, cmd is %u", cmd);
                return TEE_ERROR_BAD_PARAMETERS;
            }

            ret = ta_sm4_cbc_decrypt(params[OUT_BUFFER_INDEX - 1].memref.buffer,
                                     params[OUT_BUFFER_INDEX - 1].memref.size,
                                     params[OUT_BUFFER_INDEX].memref.buffer,
                                     &params[OUT_BUFFER_INDEX].memref.size);
            if (ret != TEE_SUCCESS) {
                tloge("InvokeCommand ta_sm4_cbc_decrypt Failed 0x%x. cmd is %u", ret, cmd);
                return ret;
            }
            break;
        default:
            tloge("Unknown cmd is %u", cmd);
            ret = TEE_ERROR_BAD_PARAMETERS;
    }

    return ret;
}

/**
 * Function TA_CloseSessionEntryPoint:
 * Description:
 *   The Framework calls this function to close a client session.
 *   During the call to this function the implementation can use
 *   any session functions.
 */
void TA_CloseSessionEntryPoint(void *session_context) {
    (void) session_context;
    tlogd("---- close session ----- ");
}

/**
 * Function TA_DestroyEntryPoint
 * Description:
 *   The function TA_DestroyEntryPoint is the Trusted Application's destructor,
 *   which the Framework calls when the instance is being destroyed.
 */
void TA_DestroyEntryPoint(void) {
    tlogd("---- destroy TA ---- ");
}
