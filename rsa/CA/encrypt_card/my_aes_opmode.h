//
// Created by dongbo on 2022/11/24.
//

#ifndef MYSQL_MY_AES_OPMODE_H
#define MYSQL_MY_AES_OPMODE_H

enum my_aes_opmode
{
    my_aes_128_ecb,
    my_aes_192_ecb,
    my_aes_256_ecb,
    my_aes_128_cbc,
    my_aes_192_cbc,
    my_aes_256_cbc,
    my_aes_128_cfb1,
    my_aes_192_cfb1,
    my_aes_256_cfb1,
    my_aes_128_cfb8,
    my_aes_192_cfb8,
    my_aes_256_cfb8,
    my_aes_128_cfb128,
    my_aes_192_cfb128,
    my_aes_256_cfb128,
    my_aes_128_ofb,
    my_aes_192_ofb,
    my_aes_256_ofb,
    my_sm4_ecb,
    my_sm4_cbc,
};

#endif //MYSQL_MY_AES_OPMODE_H
