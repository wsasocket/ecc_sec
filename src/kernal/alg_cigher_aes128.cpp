/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年4月16日
 */
#include "alg_cigher_aes128.hpp"
#include <string.h>
Alg_Cigher_AES128::Alg_Cigher_AES128()
{
    cihper_block_size = CIPHER_BLOCK_BYTES;
}

Alg_Cigher_AES128::~Alg_Cigher_AES128()
{
}

int Alg_Cigher_AES128::get_cipher_block_size()
{
    return cihper_block_size;
}

int Alg_Cigher_AES128::encrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *in, uint32_t in_length, uint8_t *out)
{
    return aes_encrypt(in, out, in_length, key, iv);
}

int Alg_Cigher_AES128::decrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *in, uint32_t in_length, uint8_t *out)
{
    return aes_decrypt(in, out, in_length, key, iv);
}

int Alg_Cigher_AES128::aes_encrypt(const uint8_t *in, uint8_t *out, size_t length, const uint8_t *key, const uint8_t *ivec)
{
    AES_KEY encrypt_key;
    uint8_t iv[CIPHER_BLOCK_BYTES];
    memcpy(iv, ivec, CIPHER_BLOCK_BYTES);
    if(AES_set_encrypt_key(key, 128, &encrypt_key) != 0)
        return ALGORITHM_KEY_ERROR;
    AES_cbc_encrypt(in, out, length, &encrypt_key, iv, AES_ENCRYPT);
    return length;
}

int Alg_Cigher_AES128::aes_decrypt(const uint8_t *in, uint8_t *out, size_t length, const uint8_t *key, const uint8_t *ivec)
{
    AES_KEY decrypt_key;
    uint8_t iv[CIPHER_BLOCK_BYTES];
    memcpy(iv, ivec, CIPHER_BLOCK_BYTES);
    if(AES_set_decrypt_key(key, 128, &decrypt_key) != 0)
        return ALGORITHM_KEY_ERROR;
    AES_cbc_encrypt(in, out, length, &decrypt_key, iv, AES_DECRYPT);
    return length;
}
