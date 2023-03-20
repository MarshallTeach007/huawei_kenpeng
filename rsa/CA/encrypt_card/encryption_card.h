
// Created by dongbo on 2022/11/24.
//

#ifndef MYSQL_ENCRYPTION_CARD_H
#define MYSQL_ENCRYPTION_CARD_H

#include "sdf/sdf.h"
#include "sdf/sdb_sdf.h"
#include "sdf/sdf_type.h"
#include "sdf/sdf_dev_manage.h"

#include "my_aes_opmode.h"
//#include <my_global.h>

//#include "sdf/my_aes_opmode.h"
typedef unsigned int uint32;
typedef char my_bool; /* Small bool */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <malloc.h>

#include <iostream>
#include <boost/functional/hash.hpp>
#include <boost/unordered_map.hpp>
#include <boost/thread.hpp>
#include <boost/thread/shared_mutex.hpp>
#include <boost/unordered_map.hpp>
#include <boost/uuid/detail/sha1.hpp>

#include "kp_tee_encrypt.h"


struct encryption_card_device {
    encryption_card_device() {
        _device_handle = NULL;
        _session_handle = NULL;
        uiKeyLength = 0;
        key_init = false;
        _id = -1;
        _keyhandle = NULL;
    }

public:
    void *_device_handle;
    void *_session_handle;
    u8 ucKey[16];
    u32 uiKeyLength;
    bool key_init;
    unsigned int _id;
    void *_keyhandle;
    //lock
    long _pool_id;
    tee_connect *tee_conn;
};

const static std::string _key_fuck("1234567890123456");
extern std::string user_pin;

const int unique_enc_key_size = 48;
const int key_worker_size = 2;
// unique_enc_key_size*key_worker_size should be less than the total allowed threads offered by the encryption card.


struct encryption_card_device_pool {
    static encryption_card_device *get(unsigned int id_, const std::string &key_ = _key_fuck) {
        boost::lock_guard<boost::mutex> m(_mx);
        int _key_id = boost::hash<std::string>()(key_) % unique_enc_key_size;
        assert(_key_id < 1024);

        std::string key_id((char *) &_key_id, sizeof(int));
        key_id += user_pin;
        boost::uuids::detail::sha1 sha;
        sha.process_bytes(key_id.data(), key_id.length());
        unsigned int digest[5];
        sha.get_digest(digest);

        key_id.assign((char *) digest, sizeof(digest));
        key_id.resize(16, '-');

        int _pool_id = _key_id * key_worker_size + rand() % key_worker_size;
        boost::unordered_map<int, encryption_card_device>::iterator it = _pool.find(_pool_id);

        if (it != _pool.end()) {
            return &it->second;
        }

        {
            encryption_card_device _device;
            _device._id = id_;

            u32 r = SDF_OpenDevice(&_device._device_handle);
            if (r) {
                printf("SDF_OpenDevice failed:%x\n", r);
                return NULL;
            }
            r = SDF_OpenSession(_device._device_handle, &_device._session_handle);
            if (r) {
                printf("SDF_OpenSession failed:%x\n", r);
                return NULL;
            }

            r = SDF_GetPrivateKeyAccessRight(_device._session_handle, _device._id,
                                             (unsigned char *) user_pin.c_str(),
                                             (unsigned int) user_pin.length());
            if (r) {
                std::cout << user_pin << std::endl;
                printf("SDF_GetPrivateKeyAccessRight failed:%x\n", r);
                return NULL;
            }


            if (key_id.empty()) {

                r = SDF_GenerateKeyWithKEK(_device._session_handle,
                                           DEK_LEN, (unsigned int) SGD_SMS4_ECB,
                                           _device._id, _device.ucKey,
                                           &_device.uiKeyLength, &_device._keyhandle);
                if (r) {
                    printf("SDF_GenerateKeyWithKEK failed:%x\n", r);
                    return NULL;
                }
                _device.key_init = true;

            } else {
                const std::string &tmp_key = key_id; // fuck bugs , length == 16
                memcpy(_device.ucKey, tmp_key.c_str(), tmp_key.length());
                _device.uiKeyLength = tmp_key.length();
                r = SDF_ImportKeyWithKEK(_device._session_handle,
                                         (unsigned int) SGD_SMS4_ECB,
                                         _device._id, _device.ucKey,
                                         _device.uiKeyLength, &_device._keyhandle);
                if (r) {
                    printf("SDF_ImportKeyWithKEK failed:%x\n", r);
                    return NULL;
                }
                _device.key_init = true;
            }
            _device.tee_conn = new tee_connect;
            _device.tee_conn->init();
//            _device.tee_conn.test();
//            _device.tee_conn.test();

            _device._pool_id = _pool_id;
            encryption_card_device &device = _pool[_pool_id] = _device;
            std::cout << "card key _pool size:" << _pool.size() << std::endl;
            return &device;
        }
    }


private:
    static boost::mutex _mx;
    static boost::unordered_map<int, encryption_card_device> _pool;
};


struct encryption_card {
    encryption_card(unsigned int id_ = 1,
                    unsigned int mode_ = SGD_SMS4_ECB, const std::string &key_ = "") {
        _id = id_;
        _SM4_MODE = mode_;
        _keyhandle = NULL;
        _device_handle = NULL;
        _session_handle = NULL;
        _is_login = false;
        _key = key_;
    }

    void login() {
        encryption_card_device *_device = NULL;
        if (_key.empty())
            _device = encryption_card_device_pool::get(_id);
        else {
            _device = encryption_card_device_pool::get(_id, _key);
        }
        if (_device == NULL)
            return;

        _device_handle = _device->_device_handle;
        _session_handle = _device->_session_handle;
        _keyhandle = _device->_keyhandle;
        _is_login = true;
        _key.clear();
        _key = _key.assign((char *) _device->ucKey, _device->uiKeyLength);

        _tee_conn = _device->tee_conn;

//        std::cout<<"_pool_id:" << _device->_pool_id <<std::endl;
    }

    int encrypt(const std::string &iv, std::string &src_data,
                std::string &enc_data, unsigned int &len, bool padding = false) {
        //        boost::lock_guard<boost::mutex> lk(lock);
        if (!_is_login) {
            return -1;
        }

        enc_data.resize(src_data.length() + 32, 0);
        size_t back_len;
        if (_SM4_MODE == SGD_SMS4_ECB) {
            _tee_conn->sm4_ecb_encrypt((char *) _key.c_str(),
                                       (char *) src_data.c_str(), int(src_data.length()),
                                       (char *) enc_data.c_str(), back_len, padding);
        } else {

//            std::cout << src_data <<"-"<<_key<< "," << iv <<std::endl;
            _tee_conn->sm4_cbc_encrypt((char*)_key.data(), (char*)iv.data(),
                                       (char *) src_data.c_str(), int(src_data.length()),
                                       (char *) enc_data.data(), back_len, padding);

        }

        if(int(back_len - src_data.length()) > 16)
          return -1;

        len = back_len;
        enc_data.resize(len);

        return 0;
    }

    int decrypt(const std::string &iv, std::string &src_data,
                std::string &dec_data, unsigned int &len, bool padding = false) {
        //        boost::lock_guard<boost::mutex> lk(lock);
        if (!_is_login) {
            return -1;
        }

        dec_data.resize(src_data.length() + 32, 0);
        size_t back_len;
        if (_SM4_MODE == SGD_SMS4_ECB) {
            _tee_conn->sm4_ecb_decrypt((char *) _key.c_str(),
                                       (char *) src_data.c_str(), int(src_data.length()),
                                       (char *) dec_data.c_str(), back_len, padding);
        } else {
            _tee_conn->sm4_cbc_decrypt((char *) _key.c_str(), (char *) iv.data(),
                                       (char *) src_data.c_str(), int(src_data.length()),
                                       (char *) dec_data.c_str(), back_len, padding);
        }
        if(int(back_len - src_data.length()) > 16)
          return -1;

        len = back_len;
        dec_data.resize(len);
        return 0;
    }

    ~encryption_card() {
        //        boost::lock_guard<boost::mutex> lk(lock);
    }

private:
    u32 GetAccessRight(void *hSessionHandle, unsigned int uiPinIndex, unsigned char *uiPin, unsigned int uiPinLength) {
        u32 r;

        r = SDF_GetPrivateKeyAccessRight(hSessionHandle, uiPinIndex, uiPin, uiPinLength);
        if (r) {
            printf("get access right failed:%x\n", r);
            return r;
        }

        return 0;
    }

    int GenerateDEK(void *hSessionHandle, unsigned int uiKeyBits, unsigned int uiAlgID, unsigned int uiKEKIndex,
                    unsigned char *pucKey, unsigned int *puiKeyLength, void **phKeyHandle) {
        int r;

        r = SDF_GenerateKeyWithKEK(hSessionHandle, uiKeyBits, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, phKeyHandle);
        if (r) {
            printf("generate dek failed:%x\n", r);
        }
        return r;
    }

    int ImportEncryptedDEK(void *hSessionHandle, unsigned int uiAlgID, unsigned int uiKEKIndex, unsigned char *pucKey,
                           unsigned int puiKeyLength, void **phKeyHandle) {
        int r;

        r = SDF_ImportKeyWithKEK(hSessionHandle, uiAlgID, uiKEKIndex, pucKey, puiKeyLength, phKeyHandle);
        if (r) {
            printf("import encrypted dek failed:%x\n", r);
        }
        return r;
    }

    int DEKEncrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
                   unsigned char *pucData,
                   unsigned int uiDataLength, unsigned char *pucEncData, unsigned int *puiEncDataLength) {
        int r;

        r = SDF_Encrypt(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucData, uiDataLength, pucEncData,
                        puiEncDataLength);
        if (r) {
            printf("Encrypt failed:%x\n", r);
        }
        return r;
    }

    int DEKDecrypt(void *hSessionHandle, void *hKeyHandle, unsigned int uiAlgID, unsigned char *pucIV,
                   unsigned char *pucEncData, unsigned int uiEncDataLength, unsigned char *pucData,
                   unsigned int *puiDataLength) {
        int r;

        r = SDF_Decrypt(hSessionHandle, hKeyHandle, uiAlgID, pucIV, pucEncData, uiEncDataLength, pucData,
                        puiDataLength);
        if (r) {
            printf("Decrypt failed:%x\n", r);
        }
        return r;
    }

    int DestroyDEK(void *hSessionHandle, void *hKeyHandle) {
        int r;
        r = SDF_DestroyKey(hSessionHandle, hKeyHandle);
        if (r) {
            printf("destroy DEK failed:%x\n", r);
        }
        return r;
    }


public:
    bool _is_login;
    std::string _key;
    tee_connect *_tee_conn;
private:

    unsigned int _id;
    void *_device_handle;
    void *_session_handle;
    void *_keyhandle;

    unsigned int _SM4_MODE;
private:
    std::string _admin_pin;
    int _admin_pin_len;
};


int my_aes_encrypt_card(const unsigned char *source, uint32 source_length,
                        unsigned char *dest,
                        const unsigned char *key, uint32 key_length,
                        enum my_aes_opmode mode, const unsigned char *iv,
                        my_bool padding);

int my_aes_decrypt_card(const unsigned char *source, uint32 source_length,
                        unsigned char *dest,
                        const unsigned char *key, uint32 key_length,
                        enum my_aes_opmode mode, const unsigned char *iv,
                        my_bool padding);

#endif //MYSQL_ENCRYPTION_CARD_H
