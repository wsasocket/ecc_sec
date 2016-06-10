/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年4月16日
 */
#ifndef SRC_KERNAL_ALG_HASH_SHA256_HPP_
#define SRC_KERNAL_ALG_HASH_SHA256_HPP_
#include "../core/core.hpp"
#include<openssl/sha.h>
/*
 *SHA256 function
 */
class Alg_Hash_SHA256: virtual public IAlg_Hash
{
public:
    Alg_Hash_SHA256();
    virtual ~Alg_Hash_SHA256();

public:
    void hash_init();
    void hash_update(const uint8_t *M, size_t msg_len);
    void hash_final(uint8_t *out);
    void hash(const uint8_t *in, size_t in_length, uint8_t *out);
    void hmac(const uint8_t *key, size_t key_length, const uint8_t *in, size_t in_length, uint8_t *output);
    int get_hash_out_size();
private:
    SHA256_CTX ctx;
};

#endif /* SRC_KERNAL_ALG_HASH_SHA256_HPP_ */
