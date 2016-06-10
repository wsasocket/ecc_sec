/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年4月16日
 */
#include "../kernal/alg_hash_SHA256.hpp"

#include <openssl/hmac.h>
Alg_Hash_SHA256::Alg_Hash_SHA256()
{
    hash_out_size = 32;
}

Alg_Hash_SHA256::~Alg_Hash_SHA256()
{
}

void Alg_Hash_SHA256::hash_init()
{
    SHA256_Init(&ctx);
}

void Alg_Hash_SHA256::hash_update(const uint8_t *M, size_t msg_len)
{
    SHA256_Update(&ctx, M, msg_len);
}

void Alg_Hash_SHA256::hash_final(uint8_t *out)
{
    SHA256_Final(out, &ctx);

}
void Alg_Hash_SHA256::hash(const uint8_t *in, size_t in_length, uint8_t *out)
{
    SHA256(in, in_length, out);
}

void Alg_Hash_SHA256::hmac(const uint8_t *key, size_t key_length, const uint8_t *in, size_t in_length, uint8_t *output)
{
    uint32_t output_length;
    const EVP_MD * engine = EVP_sha256();
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key, key_length, engine, NULL);
    HMAC_Update(&ctx, in, in_length);
    HMAC_Final(&ctx, output, &output_length);
    HMAC_CTX_cleanup(&ctx);
}

int Alg_Hash_SHA256::get_hash_out_size()
{
    return hash_out_size;
}
