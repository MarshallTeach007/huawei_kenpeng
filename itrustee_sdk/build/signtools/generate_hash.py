#!/usr/bin/env python
# coding=utf-8
#----------------------------------------------------------------------------
# Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# Description: cal hash for generating a trusted application load image
#----------------------------------------------------------------------------

import struct
import os
import hashlib
import stat

HASH256 = 0
HASH512 = 1


def gen_hash(hash_type, in_data, out_file_path):
    # Initialize a SHA256 object from the Python hash library
    if int(hash_type) == HASH256:
        hash_op = hashlib.sha256()
    elif int(hash_type) == HASH512:
        hash_op = hashlib.sha512()
    hash_op.update(in_data)

    #-----hash file used for ras sign---
    fd_hash = os.open(out_file_path, os.O_WRONLY | os.O_CREAT, \
        stat.S_IWUSR | stat.S_IRUSR)
    hash_fp = os.fdopen(fd_hash, "wb")
    # fixed hash prefix value
    if int(hash_type) == HASH256:
        hash_fp.write(struct.pack('B' * 19, 0x30, 0x31, 0x30, 0x0d, 0x06, \
            0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, \
            0x05, 0x00, 0x04, 0x20))
    elif int(hash_type) == HASH512:
        hash_fp.write(struct.pack('B' * 19, 0x30, 0x51, 0x30, 0x0d, 0x06, \
            0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, \
            0x05, 0x00, 0x04, 0x40))
    hash_fp.write(hash_op.digest())
    hash_fp.close()
    return


