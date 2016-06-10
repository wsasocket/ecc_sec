/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年4月27日
 */

#ifndef SRC_APP_INTERFACE_HPP_
#define SRC_APP_INTERFACE_HPP_

// we should define csr and crt struct
// in this case we define csr(certificate request):
// Token:system defined Token,ASCII NULL terminal string
// public_key_x/y:base64 encode
// sign_r/s:base64 encode
// extend1~3 base64 encode perhaps NULL
// hash to be verify format:Token||public_key_x/y||extend1~3 if not NULL NOTE,must decode base64 before hash

// we define crt as below
// Token:system defined Token,equal to csr
// public_key_x/y:base64 encode equal to csr
// sign_r/s:base64 encode ,this value is replaced by CA sign value
// extend1~3: base64 encode perhaps NULL equal to csr
// expire time: like this 2016/02/29
// SN:CA define a unique serial number
// hash to be sign format:Token||SN||expire time||public_key_x/y||extend1~3 if not NULL NOTE,must decode base64
// except "Token", "SN" and "expire" field, other field use base64 format to ensure avoid use uint8_t


//define input size to limit overflow attack
#define TOKEN_MAX_SIZE 16
#define SN_MAX_SIZE 16
#define ECC_BASE64_MAX_SIZE 44
#define EXPIRE_TIME_MAX_SIZE 10
#define INPUT_DATA_INVALID -10;

// pre_computer hash for csr except token other are all base64 format
int build_csr_hash(const char *token, const char *public_key_x, const char *public_key_y,
		const char *extend1, const char *extend2, const char *extend3,
		char *base64_out);

// pre_computer hash for crt except token SN expire other are all base64 format
int build_crt_hash(const char *token, const char *public_key_x, const char *public_key_y,
		const char * SN, const char * expire,
		const char *extend1, const char *extend2, const char *extend3,
		char *base64_out);

//verify usr self signed certification
int verify_csr(const char *hash_value, const char *public_key_x, const char *public_key_y, const char *sign_r, const char *sign_s);

//sign user self signed certification into CA signed certification
int sign_crt(const char *hash_value, char *sign_r, char *sign_s);

// verify CA signed certification
int verify_crt(const char *hash_value, const char *sign_r, const char *sign_s);

// user build self signed certification
int sign_csr(const char *hash_value, char *sign_r, char *sign_s);

// sign substitude hash
int seal_digital_envelope(const char *msg, const char *peer_public_x, const char *peer_public_y,
		char *cipher_hash, char *sign_r, char *sign_s, char *env);

// sign substitude hash
int tear_digital_envelope_ex(const char *msg, const char *peer_public_x, const char *peer_public_y,
		const char *cipher_hash, const char *sign_r, const char *sign_s,
		char *msg_out);
#endif /* SRC_APP_INTERFACE_HPP_ */
