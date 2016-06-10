/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年4月16日
 */
#ifndef SRC_KERNAL_ALG_HASH_MD5_HPP_
#define SRC_KERNAL_ALG_HASH_MD5_HPP_
#include <openssl/md5.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include "../core/core.hpp"
/*
 *
 */
class Alg_Hash_MD5: public IAlg_Hash
{
public:
    Alg_Hash_MD5();
    virtual ~Alg_Hash_MD5();
public:
    void hash_init();
    void hash_update(uint8_t *M, size_t msg_len);
    void hash_final(uint8_t *out);
    void hash(uint8_t *in, size_t in_length, uint8_t *out);
    void hmac(const uint8_t *key, size_t key_length, const uint8_t *in, size_t in_length, uint8_t *output);
    int get_hash_out_size();
private:
    MD5_CTX ctx;
};

#endif /* SRC_KERNAL_ALG_HASH_MD5_HPP_ */
