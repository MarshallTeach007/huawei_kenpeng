//
// Created by dongbo on 2023/3/6.
//

#ifndef TEST_KP_TEE_PROTO_H
#define TEST_KP_TEE_PROTO_H

#include <stdio.h>
#include <stdlib.h>

const unsigned long proto_magic = 0xAD12F31098;

struct proto_msg {
    char _key[32];
    char _iv[16];
    char _type;
    char _padding;
    int _len;
    char *_data;
};

char *make_msg(struct proto_msg *msg_ , int * back_len_) {
    int _len = sizeof(struct proto_msg) + msg_->_len + 8;
    char *str = (char*)malloc(_len);
    if (!str) return NULL;

    int len = 0;
    memcpy(str + len, (char *) &proto_magic, sizeof(proto_magic));
    len += sizeof(proto_magic);

    memcpy(str + len, (char *) &_len, sizeof(int));
    len += sizeof(int);

    memcpy(str + len, (char *) msg_->_key, sizeof(msg_->_key));
    len += sizeof(msg_->_key);

    memcpy(str + len, (char *) msg_->_iv, sizeof(msg_->_iv));
    len += sizeof(msg_->_iv);

    memcpy(str + len, (char *) &msg_->_type, sizeof(msg_->_type));
    len += sizeof(msg_->_type);

    memcpy(str + len, (char *) &msg_->_padding, sizeof(msg_->_padding));
    len += sizeof(msg_->_padding);

    memcpy(str + len, (char *) &msg_->_len, sizeof(msg_->_len));
    len += sizeof(msg_->_len);

    memcpy(str + len, (char *) msg_->_data, msg_->_len);

    *back_len_ = _len;

    return str;
}

struct proto_msg *split_msg(char *buffer, size_t buf_len) {
    struct proto_msg *_msg = (struct  proto_msg*)malloc(sizeof(struct proto_msg));

    int len = 0;
    unsigned long _proto_magic = 0;
    memcpy(&_proto_magic, buffer + len, sizeof(unsigned long));
    len += sizeof(unsigned long);

    if (_proto_magic != proto_magic) {
        return NULL;
    }

    int _len = 0;
    memcpy(&_len, buffer + len, sizeof(int));
    len += sizeof(int );

    size_t _len_ = _len;
    if(_len_> buf_len)
        return NULL;

    memcpy(_msg->_key, buffer + len, sizeof(_msg->_key));
    len += sizeof(_msg->_key);

    memcpy(_msg->_iv, buffer + len, sizeof(_msg->_iv));
    len += sizeof(_msg->_iv);

    memcpy(&(_msg->_type), buffer + len, sizeof(_msg->_type));
    len += sizeof(_msg->_type);

    memcpy(&(_msg->_padding), buffer + len, sizeof(_msg->_padding));
    len += sizeof(_msg->_padding);

    memcpy(&(_msg->_len), buffer + len, sizeof(_msg->_len));
    len += sizeof(_msg->_len);

    _msg->_data = (char*)malloc(_msg->_len);
    memcpy(_msg->_data, buffer + len, _msg->_len);

    return _msg;
}

#endif //TEST_KP_TEE_PROTO_H
