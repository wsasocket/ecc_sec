/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年4月27日
 */
#include "../kernal/alg_hash_SHA256.hpp"
#include "../kernal/configure.hpp"
#include "../core/utility.hpp"
#include "../core/core.hpp"
#include "../kernal/alg_digital_envelope.hpp"
#include <string.h>
#include <iostream>
#include <string>


#include "interface.hpp"

int build_csr_hash(const char *token, const char *public_key_x, const char *public_key_y,
		const char *extend1, const char *extend2, const char *extend3,
		char *base64_out)
{
    std::string buffer;
    uint8_t hash_value[33];
    uint8_t * p;
    char * pp;
    int decode_len;
    if(strlen(token) > TOKEN_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(strlen(public_key_x) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(strlen(public_key_y) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(extend1)
        if(strlen(extend1) > ECC_BASE64_MAX_SIZE)
            return INPUT_DATA_INVALID;
    if(extend2)
        if(strlen(extend2) > ECC_BASE64_MAX_SIZE)
            return INPUT_DATA_INVALID;
    if(extend3)
        if(strlen(extend3) > ECC_BASE64_MAX_SIZE)
            return INPUT_DATA_INVALID;
    buffer.append(token);
    p = utility::base64_decoder(public_key_x, false);
    buffer.append((const char *) p, ECC_KEY_BYTES);
    delete[] p;
    p = utility::base64_decoder(public_key_y, false);
    buffer.append((const char *) p, ECC_KEY_BYTES);
    delete[] p;
    if(extend1){
        ;
        p = utility::base64_decoder(extend1, false);
        decode_len = utility::get_base64_decode_len(extend1);
        buffer.append((const char *) p, decode_len);
        delete[] p;
    }
    if(extend2){
        p = utility::base64_decoder(extend2, false);
        decode_len = utility::get_base64_decode_len(extend2);
        buffer.append((const char *) p, decode_len);
        delete[] p;
    }
    if(extend3){
        p = utility::base64_decoder(extend3, false);
        decode_len = utility::get_base64_decode_len(extend3);
        buffer.append((const char *) p, decode_len);
        delete[] p;
    }

    Alg_Hash_SHA256 sha256;

    sha256.hash((uint8_t*) buffer.c_str(), buffer.length(), hash_value);
    pp = utility::base64_encoder(hash_value, ECC_KEY_BYTES, false);
    strcpy(base64_out, pp);
    delete pp;
    return RESULT_SUCCESS;
}

int sign_csr(const char *hash_value, char *sign_r, char *sign_s)
{

    int ret = RESULT_SUCCESS;
    uint8_t *h;
    char * rs;
    uint8_t r[ECC_KEY_BYTES + 1];
    uint8_t s[ECC_KEY_BYTES + 1];
    if(strlen(hash_value) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;

    IKey_Manager key_manager(X962_SECG);
    IAlg_Ecc ecc(X962_SECG);
    Configure *conf = Configure::GetConfigure();

    if(key_manager.load_private_key(conf->get_private_token()) != RESULT_SUCCESS)
    	return KEY_INITIALIZE_FAIL;

    h = utility::base64_decoder(hash_value, false);
    ret = ecc.ecc_sign(h, SHA_256, key_manager.get_private_key(), r, s);

    if(ret != RESULT_SUCCESS){
        delete[] h;
        return ret;
    }
    delete[] h;
    rs = utility::base64_encoder(r, ECC_KEY_BYTES, false);
    strcpy(sign_r, rs);
    delete[] rs;
    rs = utility::base64_encoder(s, ECC_KEY_BYTES, false);
    strcpy(sign_s, rs);
    delete[] rs;
    return ret;
}

int verify_csr(const char *hash_value, const char *public_key_x, const char *public_key_y,
		const char *sign_r, const char *sign_s)
{
    uint8_t *h, *x, *y, *r, *s;
    int ret = VERIFY_FAIL;
    if(strlen(hash_value) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(strlen(public_key_x) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(strlen(public_key_y) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(strlen(sign_r) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(strlen(sign_s) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;

    h = utility::base64_decoder(hash_value, false);
    x = utility::base64_decoder(public_key_x, false);
    y = utility::base64_decoder(public_key_y, false);
    r = utility::base64_decoder(sign_r, false);
    s = utility::base64_decoder(sign_s, false);
    IAlg_Ecc ecc(X962_SECG);
    ret = ecc.ecc_verify(h, ECC_KEY_BYTES, x, y, r, s);
    delete[] h;
    delete[] x;
    delete[] y;
    delete[] r;
    delete[] s;
    return ret;
}

int build_crt_hash(const char *token, const char *public_key_x, const char *public_key_y,
		const char * SN, const char * expire,
		const char *extend1, const char *extend2, const char *extend3,
		char *base64_out)
{
    std::string buffer;
    uint8_t hash_value[33];
    uint8_t * p;
    char * pp;
    int decode_len;
    if(strlen(token) > TOKEN_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(strlen(public_key_x) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(strlen(public_key_y) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(strlen(SN) > SN_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(strlen(expire) > EXPIRE_TIME_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(extend1)
        if(strlen(extend1) > ECC_BASE64_MAX_SIZE)
            return INPUT_DATA_INVALID;
    if(extend2)
        if(strlen(extend2) > ECC_BASE64_MAX_SIZE)
            return INPUT_DATA_INVALID;
    if(extend3)
        if(strlen(extend3) > ECC_BASE64_MAX_SIZE)
            return INPUT_DATA_INVALID;
    buffer.append(token);
    buffer.append(SN);
    buffer.append(expire);
    p = utility::base64_decoder(public_key_x, false);
    buffer.append((const char *) p, ECC_KEY_BYTES);
    delete[] p;
    p = utility::base64_decoder(public_key_y, false);
    buffer.append((const char *) p, ECC_KEY_BYTES);
    delete[] p;
    if(extend1){
        ;
        p = utility::base64_decoder(extend1, false);
        decode_len = utility::get_base64_decode_len(extend1);
        buffer.append((const char *) p, decode_len);
        delete[] p;
    }
    if(extend2){
        p = utility::base64_decoder(extend2, false);
        decode_len = utility::get_base64_decode_len(extend2);
        buffer.append((const char *) p, decode_len);
        delete[] p;
    }
    if(extend3){
        p = utility::base64_decoder(extend3, false);
        decode_len = utility::get_base64_decode_len(extend3);
        buffer.append((const char *) p, decode_len);
        delete[] p;
    }

    Alg_Hash_SHA256 sha256;

    sha256.hash((uint8_t*) buffer.c_str(), buffer.length(), hash_value);
    pp = utility::base64_encoder(hash_value, ECC_KEY_BYTES, false);
    strcpy(base64_out, pp);
    delete pp;
    return RESULT_SUCCESS;
}

int sign_crt(const char *hash_value, char *sign_r, char *sign_s)
{

    int ret = RESULT_SUCCESS;
    uint8_t *h;
    char * rs;
    uint8_t r[ECC_KEY_BYTES + 1];
    uint8_t s[ECC_KEY_BYTES + 1];
    uint8_t p[ECC_KEY_BYTES + 1];

    if(strlen(hash_value) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;

    IKey_Base_Manager keybase_manager(SHA_256,X962_SECG);
    IAlg_Ecc ecc(X962_SECG);
    Configure *conf = Configure::GetConfigure();
    keybase_manager.set_passwd(NULL);
    if(keybase_manager.load_private_key_base(conf->get_private_base_token()) != RESULT_SUCCESS)
    	return KEY_INITIALIZE_FAIL;

    h = utility::base64_decoder(hash_value, false);
    ret = keybase_manager.get_mixed_private_key(h,p);
    if(ret != RESULT_SUCCESS){
        delete[] h;
        return ret;
    }
    ret = ecc.ecc_sign(h, SHA_256, p, r, s);
    if(ret != RESULT_SUCCESS){
        delete[] h;
        return ret;
    }
    delete[] h;
    rs = utility::base64_encoder(r, ECC_KEY_BYTES, false);
    strcpy(sign_r, rs);
    delete[] rs;
    rs = utility::base64_encoder(s, ECC_KEY_BYTES, false);
    strcpy(sign_s, rs);
    delete[] rs;
    return ret;
}

int verify_crt(const char *hash_value, const char *sign_r, const char *sign_s)
{

    uint8_t *h, *r, *s;
    uint8_t px[ECC_KEY_BYTES + 1];
    uint8_t py[ECC_KEY_BYTES + 1];

    int ret = VERIFY_FAIL;
    if(strlen(hash_value) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(strlen(sign_r) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;
    if(strlen(sign_s) != ECC_BASE64_MAX_SIZE)
        return INPUT_DATA_INVALID;

    IKey_Base_Manager keybase_manager(SHA_256, X962_SECG);
    IAlg_Ecc ecc(X962_SECG);
    Configure *conf = Configure::GetConfigure();
    keybase_manager.set_passwd(NULL);
    if(keybase_manager.load_public_key_base(conf->get_private_base_token()) != RESULT_SUCCESS)
      	return KEY_INITIALIZE_FAIL;

    h = utility::base64_decoder(hash_value, false);
    ret = keybase_manager.get_mixed_public_key(h, px, py);
    if(ret != RESULT_SUCCESS)
    {
    	delete []h;
    	return ret;
    }

    r = utility::base64_decoder(sign_r, false);
    s = utility::base64_decoder(sign_s, false);
    ret = ecc.ecc_verify(h, ECC_KEY_BYTES, px, py, r, s);
    delete[] h;
    delete[] r;
    delete[] s;
    return ret;

}

int seal_digital_envelope(const char *msg, const char *peer_public_x, const char *peer_public_y,
		char *cipher_hash, char *sign_r, char *sign_s, char *env)
{

    int ret;
    uint8_t *m, *x, *y;
    uint8_t *s, *r,*ch, *om;
    char * p;
    size_t ml;
    IKey_Manager km(X962_SECG);
    Alg_Digital_Envelope envelope(X962_SECG);

    Configure *conf = Configure::GetConfigure();
    km.load_private_key(conf->get_private_token());
    ml = utility::get_base64_decode_len(msg);
    m = utility::base64_decoder(msg);
    x = utility::base64_decoder(peer_public_x, false);
    y = utility::base64_decoder(peer_public_y, false);

    r = new uint8_t[ECC_KEY_BYTES + 1];
    s = new uint8_t[ECC_KEY_BYTES + 1];
    ch = new uint8_t[SHA_256 + 1];
    om = new uint8_t[(ml + ECC_KEY_BYTES) * 2];

    ret = envelope.seal_digital_envelope_ex(m, ml, km.get_private_key(), x, y, ch, r, s, om);
    delete[] m;
    delete[] x;
    delete[] y;

    p = utility::base64_encoder(r, ECC_KEY_BYTES, false);
    strcpy(sign_r, p);
    delete[] p;
    p = utility::base64_encoder(s, ECC_KEY_BYTES, false);
    strcpy(sign_s, p);
    delete[] p;
    p = utility::base64_encoder(ch, SHA_256, false);
    strcpy(cipher_hash, p);
    delete[] p;
    p = utility::base64_encoder(om, ret);
    strcpy(env, p);
    delete[] p;

    delete[] r;
    delete[] s;
    delete[] ch;
    delete[] om;
    return ret;
}

int tear_digital_envelope_ex(const char *msg, const char *peer_public_x, const char *peer_public_y,
		const char *cipher_hash, const char *sign_r, const char *sign_s,
		char *msg_out)
{

    int ret;
    uint8_t *m;
    uint8_t *ch, *om, *x, *y, *s, *r;
    char * p;
    size_t ml;
    IKey_Manager km(X962_SECG);

    Alg_Digital_Envelope envelope(X962_SECG);
    Configure *conf = Configure::GetConfigure();
    km.load_private_key(conf->get_private_token());

    ml = utility::get_base64_decode_len(msg);
    m = utility::base64_decoder(msg);
    ch = utility::base64_decoder(cipher_hash,  false);
    x = utility::base64_decoder(peer_public_x, false);
    y = utility::base64_decoder(peer_public_y, false);
    r = utility::base64_decoder(sign_r, false);
    s = utility::base64_decoder(sign_s, false);
    om = new uint8_t[ml + (ECC_KEY_BYTES << 1)];
    ret = envelope.tear_digital_envelope_ex(m, ml, km.get_private_key(),x, y, ch, r, s, om);
    delete[] m;
    delete[] ch;
    delete[] x;
    delete[] y;
    delete[] r;
    delete[] s;

    p = utility::base64_encoder(om, ret);
    strcpy(msg_out, p);
    delete[] p;
    delete[] om;
    return ret;
}

