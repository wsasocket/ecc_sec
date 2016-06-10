/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年4月16日
 */
#include "../kernal/alg_hash_MD5.hpp"

Alg_Hash_MD5::Alg_Hash_MD5()
{
    // TODO Auto-generated constructor stub
    hash_out_size = 16;
}

Alg_Hash_MD5::~Alg_Hash_MD5()
{
    // TODO Auto-generated destructor stub
}

void Alg_Hash_MD5::hash_init()
{
    MD5_Init(&ctx);
}

void Alg_Hash_MD5::hash_update(uint8_t *M, size_t msg_len)
{
    MD5_Update(&ctx, M, msg_len);
}

void Alg_Hash_MD5::hash_final(uint8_t *out)
{
    MD5_Final(out, &ctx);

}
void Alg_Hash_MD5::hash(uint8_t *in, size_t in_length, uint8_t *out)
{
    MD5(in, in_length, out);
}

int Alg_Hash_MD5::get_hash_out_size()
{
    return hash_out_size;
}

void Alg_Hash_MD5::hmac(const uint8_t *key, size_t key_length, const uint8_t *in, size_t in_length, uint8_t *output)
{
    uint32_t output_length;
    const EVP_MD * engine = EVP_md5();
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, key, key_length, engine, NULL);
    HMAC_Update(&ctx, in, in_length);
    HMAC_Final(&ctx, output, &output_length);
    HMAC_CTX_cleanup(&ctx);
}
