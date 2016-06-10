/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年5月4日
 */
#ifndef SRC_CORE_CORE_HPP_
#define SRC_CORE_CORE_HPP_

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include "core_define.hpp"
#include "utility.hpp"
#include "keystore.hpp"
/*
 *
 */
class IAlg_Cipher {
public:
	IAlg_Cipher();
	virtual ~IAlg_Cipher();
public:
	int get_cipher_block_size();
	virtual int encrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *in,
			uint32_t in_length, uint8_t *out) = 0;
	virtual int decrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *in,
			uint32_t in_length, uint8_t *out) = 0;
protected:
	size_t cihper_block_size;
};

/*
 *
 */
class IAlg_Ecc {
public:
	IAlg_Ecc(CURVE_GROUP_ID oid);
	IAlg_Ecc();
	virtual ~IAlg_Ecc();
public:
	int init(CURVE_GROUP_ID oid);
	virtual int ecc_sign(const uint8_t *hash, size_t hash_len,
			const uint8_t *private_key, uint8_t *sign_r, uint8_t *sign_s);
	virtual int ecc_verify(const uint8_t *origin_hash, size_t hash_len,
			const uint8_t *public_key_x, const uint8_t *public_key_y,
			const uint8_t *sign_r, const uint8_t *sign_s);
//	virtual int ecc_dh_exchange_key(const uint8_t *Pub_r_x,
//			const uint8_t *Pub_r_y, //peer random number K-point
//			const uint8_t *Pub_x, const uint8_t *Pub_y,  //peer public key
//			const uint8_t *self_r, //self random number
//			const uint8_t *self_Pri, // self private key
//			uint8_t *shared_key  // result ,for ECC 256,out size is 256 bit
//			) = 0;
	// for ECC 256,returned result length should increase 64 bytes for package
	virtual int ecc_encrypt(const uint8_t *in, size_t in_length,
			const uint8_t *public_key_x, const uint8_t *public_key_y,
			uint8_t *out);
	// see above and think
	virtual int ecc_decrypt(const uint8_t *in, size_t in_length,
			const uint8_t *private_key, uint8_t *out);
protected:
	int generate_ecc_encrypt_scramble(const uint8_t *public_key_x,
			const uint8_t *public_key_y, uint8_t *prefix, uint8_t *scramble);
	int generate_ecc_decrypt_scramble(const uint8_t *private_key,
			const uint8_t *prefix, uint8_t *scramble);
protected:
	EC_GROUP * group;
	BIGNUM * order;
	CURVE_GROUP_ID oid;
};

/*
 *
 */
class IAlg_Hash {
public:
	IAlg_Hash();
	virtual ~IAlg_Hash();
public:
	virtual void hash_init() = 0;
	virtual void hash_update(const uint8_t *M, size_t msg_len) = 0;
	virtual void hash_final(uint8_t *out) = 0;
	virtual void hash(const uint8_t *in, size_t in_length, uint8_t *out) = 0;
	virtual void hmac(const uint8_t *key, size_t key_length, const uint8_t *in,
			size_t in_length, uint8_t *output) = 0;
	virtual int get_hash_out_size() = 0;
protected:
	size_t hash_out_size;
};

/*
 * key base manager is used to manager mixed key
 * user can use mixed key to verify and sign
 */
class IKey_Base_Manager {
public:
	// key base manager must have  HASH_ALG_ID and CURVE_GROUP_ID parameter
	IKey_Base_Manager(HASH_ALG_ID hid, CURVE_GROUP_ID oid);
	virtual ~IKey_Base_Manager();

public:
	// generate key pair if token is no null means keys must be save into key store
	// this function only need run once in CA initialize.
	// you'd better overwrite this function,at least you should check keys quality
	virtual int generate_key_pair_base(uint32_t *private_token = NULL,
			uint32_t *public_token = NULL);
	//if use password protect key store not machine code,you must set password at first
	char *set_passwd(const char * in);
	// load_XXX only open key store and load keys into memory
	int load_public_key_base(uint32_t token);
#ifdef __SERVER__
	int load_private_key_base(uint32_t token);
	int get_mixed_private_key(const uint8_t *hash_value, uint8_t* private_key);
#endif
	int get_mixed_public_key(const uint8_t *hash_value, uint8_t* public_key_x,
			uint8_t* public_key_y);

private:
	// kernel function to calculate mixed key
	int public_key_mix(uint8_t *Point_rx, uint8_t *Point_ry,
			const uint8_t *Point_x, const uint8_t *Point_y);
#ifdef __SERVER__
	int private_key_mix(uint8_t * r, const uint8_t * a);
#endif
	//getter and setter
	const uint8_t *get_public_key_base_x(uint32_t index);
	const uint8_t *get_public_key_base_y(uint32_t index);
#ifdef __SERVER__
	const uint8_t *get_private_key_base(uint32_t index);
	void set_private_key_base(const uint8_t *in, uint32_t index);
#endif
	void set_public_key_base_x(const uint8_t *in, uint32_t index);
	void set_public_key_base_y(const uint8_t *in, uint32_t index);

protected:
	// this is kernel function of class in deliver class can be overwrite it
	virtual uint16_t *get_selected_seq(const uint8_t *hash_seq);
protected:
	EC_GROUP *group;
	BIGNUM *order;
	CURVE_GROUP_ID oid;
	HASH_ALG_ID hid;

private:
#ifdef __SERVER__
	bool b_load_private_key;
	uint8_t *private_key_base;
#endif
	bool b_load_public_key;
	uint8_t *public_key_base_x;
	uint8_t *public_key_base_y;
	char * passwd;
};

/*
 *
 */
class IKey_Manager {
public:
	IKey_Manager(CURVE_GROUP_ID oid);
	virtual ~IKey_Manager();
public:
	virtual int generate_key_pair(uint32_t *private_token = NULL,
			uint32_t *public_token = NULL);
	virtual int generate_cipher_key(uint32_t *cipher_toke = NULL);
	virtual int load_public_key(uint32_t token);
	virtual int load_private_key(uint32_t token);
	virtual int load_cipher_key(uint32_t token);

	char *set_passwd(const char * in);
	const uint8_t *get_public_key_x();
	const uint8_t *get_public_key_y();
	const uint8_t *get_private_key();
	const uint8_t *get_cipher_key();
	void set_public_key_x(const uint8_t *in);
	void set_public_key_y(const uint8_t *in);
	void set_private_key(const uint8_t *in);
	void set_cipher_key(const uint8_t *in);
	CURVE_GROUP_ID oid;

protected:
	EC_GROUP *group;
	BIGNUM *order;

private:
	bool b_load_private_key;
	bool b_load_public_key;
	bool b_load_cipher_key;
	uint8_t *private_key;
	uint8_t *public_key_x;
	uint8_t *public_key_y;
	uint8_t *cipher_key;
	char * passwd;
};
#endif /* SRC_CORE_CORE_HPP_ */
