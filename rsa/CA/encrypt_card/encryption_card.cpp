//
// Created by dongbo on 2022/11/24.
//

#include "encryption_card.h"

boost::mutex encryption_card_device_pool::_mx;
boost::unordered_map<int, encryption_card_device> encryption_card_device_pool::_pool;

std::string user_pin = ADMIN_PIN;

int my_aes_encrypt_card(const unsigned char *source, uint32 source_length,
                        unsigned char *dest,
                        const unsigned char *key, uint32 key_length,
                        enum my_aes_opmode mode, const unsigned char *iv,
                        my_bool padding) {

//    std::cout << "my_aes_encrypt_card" <<std::endl;

    if (mode == my_sm4_cbc) {
        encryption_card encryption1(1, SGD_SMS4_CBC,std::string((char *)key, key_length));
        encryption1.login();

        std::string _src_data((char *) source, source_length);
        std::string data;
        unsigned int len;
        std::string _iv((char *) iv, 16);
        int r = encryption1.encrypt(_iv, _src_data, data, len, padding);
        if(r!=0)
            return -100;

        memcpy(dest, data.data(), data.length());
        return data.length();
    } else if (mode == my_sm4_ecb) {
        encryption_card encryption1(1,SGD_SMS4_ECB,std::string((char *)key, key_length));
        encryption1.login();

        std::string _src_data((char *) source, source_length);
        std::string data;
        unsigned int len;
        int r =encryption1.encrypt("", _src_data, data, len, padding);
        if(r!=0)
            return -101;

        memcpy(dest, data.data(), data.length());

        return data.length();
    }

    return -1;
}




int my_aes_decrypt_card(const unsigned char *source, uint32 source_length,
                        unsigned char *dest,
                        const unsigned char *key, uint32 key_length,
                        enum my_aes_opmode mode, const unsigned char *iv,
                        my_bool padding) {

//    std::cout << "my_aes_decrypt_card" <<std::endl;

    if (mode == my_sm4_cbc) {
        encryption_card encryption1(1, SGD_SMS4_CBC,std::string((char *)key, key_length));
        encryption1.login();

        std::string _src_data((char *) source, source_length);
        std::string data;
        unsigned int len;
        std::string _iv((char *) iv, 16);
        int r = encryption1.decrypt(_iv, _src_data, data, len,  padding);
        if(r!=0)
            return -102;

        memcpy(dest, data.data(), data.length());
        return data.length();
    } else if (mode == my_sm4_ecb) {
        encryption_card encryption1(1, SGD_SMS4_ECB,std::string((char *)key, key_length));
        encryption1.login();

        std::string _src_data((char *) source, source_length);
        std::string data;
        unsigned int len;
        int r = encryption1.decrypt("", _src_data, data, len,  padding);
        if(r!=0)
            return -103;

        memcpy(dest, data.data(), data.length());
        return data.length();
    }

    return -1;
}



