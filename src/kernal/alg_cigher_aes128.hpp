/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年4月16日
 */
#ifndef SRC_KERNAL_ALG_CIGHER_AES128_HPP_
#define SRC_KERNAL_ALG_CIGHER_AES128_HPP_
#include <openssl/aes.h>
#include "../core/core.hpp"
/*
 *
 */
class Alg_Cigher_AES128: public IAlg_Cipher
{
public:
    Alg_Cigher_AES128();
    virtual ~Alg_Cigher_AES128();

public:
    int get_cipher_block_size();
    int encrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *in, uint32_t in_length, uint8_t *out);
    int decrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *in, uint32_t in_length, uint8_t *out);

private:
    int aes_encrypt(const uint8_t *in, uint8_t *out, size_t length, const uint8_t *key, const uint8_t *ivec);
    int aes_decrypt(const uint8_t *in, uint8_t *out, size_t length, const uint8_t *key, const uint8_t *ivec);
};

#endif /* SRC_KERNAL_ALG_CIGHER_AES128_HPP_ */
