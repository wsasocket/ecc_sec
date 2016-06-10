/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年5月4日
 */
#include "../core/utility.hpp"
#include "../core/core_define.hpp"
#include "alg_hash_SHA256.hpp"
#include "alg_digital_envelope.hpp"
#include <string.h>


Alg_Digital_Envelope::Alg_Digital_Envelope(CURVE_GROUP_ID oid)
{
	this->oid = oid;
}

Alg_Digital_Envelope::~Alg_Digital_Envelope()
{

}

int Alg_Digital_Envelope::seal_digital_envelope_ex(const uint8_t *msg, size_t msg_len,
		const uint8_t *self_private,
		const uint8_t *peer_public_x, const uint8_t *peer_public_y,
        uint8_t *cipher_hash,
		uint8_t *sign_r, uint8_t *sign_s,
		uint8_t *envelope)
{
    size_t out_len ;
    uint8_t hash_value[ECC_KEY_BYTES + 1];
    Alg_Hash_SHA256 alg_hash;
    IAlg_Ecc alg_ecc(oid);

    alg_hash.hash(msg, msg_len, hash_value);
    alg_ecc.ecc_sign(hash_value, alg_hash.get_hash_out_size(),self_private, sign_r, sign_s);
    out_len = alg_ecc.ecc_encrypt(msg, msg_len, peer_public_x, peer_public_y, envelope);

    if(out_len != msg_len + (ECC_KEY_BYTES << 1))
        return ALGORITHM_CALC_ERROR;
    alg_hash.hash(envelope, out_len, cipher_hash);
    return out_len;
}


int Alg_Digital_Envelope::tear_digital_envelope_ex(const uint8_t *env, size_t env_len,
		const uint8_t *self_private,
		const uint8_t *peer_public_x, const uint8_t *peer_public_y,
        const uint8_t *cipher_hash,
		const uint8_t *sign_r, const uint8_t *sign_s,
		uint8_t *msg_out)
{
    int ret ;
    size_t out_len;
    uint8_t hash_value[ECC_KEY_BYTES + 1];

    Alg_Hash_SHA256 alg_hash;
    IAlg_Ecc alg_ecc(oid);

    alg_hash.hash(env, env_len, hash_value);
    ret = memcmp(hash_value, cipher_hash, alg_hash.get_hash_out_size());
    if(ret != 0)
        return ENVENLOPE_TAMPERED;

    out_len = alg_ecc.ecc_decrypt(env, env_len, self_private, msg_out);
    if(out_len != env_len - (ECC_KEY_BYTES << 1))
        return ALGORITHM_CALC_ERROR;

    alg_hash.hash(msg_out, out_len, hash_value);
    ret = alg_ecc.ecc_verify(hash_value,alg_hash.get_hash_out_size(),peer_public_x,peer_public_y,sign_r,sign_s);
    if(ret != VERIFY_SUCCESS)
        return ENVENLOPE_MESSAGE_TAMPERED;
    return out_len;
}

