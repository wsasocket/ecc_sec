/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年5月4日
 */
#include "core.hpp"

IAlg_Cipher::IAlg_Cipher() {
	cihper_block_size = 16;
}

IAlg_Cipher::~IAlg_Cipher() {
}

IAlg_Hash::IAlg_Hash() {
	hash_out_size = 32;
}

IAlg_Hash::~IAlg_Hash() {
}

IAlg_Ecc::IAlg_Ecc(CURVE_GROUP_ID oid) {
	group = NULL;
	order = NULL;
	this->oid = oid;
	group = EC_GROUP_new_by_curve_name(oid);
	order = BN_new();
	EC_GROUP_get_order(group, order, NULL);
}

IAlg_Ecc::~IAlg_Ecc() {
	if (group)
		EC_GROUP_clear_free(group);
	if (order)
		BN_clear_free(order);
}

// for ECC 256,returned result length should increase 64 bytes for package
int IAlg_Ecc::ecc_encrypt(const uint8_t *in, size_t in_length,
		const uint8_t *public_key_x, const uint8_t *public_key_y,
		uint8_t *out) {
	uint8_t prefix[65];
	uint8_t scramble[65];
	uint8_t * t;
	int ret;

	ret = generate_ecc_encrypt_scramble(public_key_x, public_key_y, prefix,
			scramble);
	if (ret != RESULT_SUCCESS)
		return ret;
	memcpy(out, prefix, ECC_KEY_BYTES << 1);
	t = utility::kdf_with_sha256(scramble, ECC_KEY_BYTES << 1, in_length);
	for (size_t i = 0; i < in_length; i++)
		out[i + 64] = in[i] ^ t[i];
	ret = in_length + 64;
	delete[] t;
	return ret;
}
// see above and think
int IAlg_Ecc::ecc_decrypt(const uint8_t *in, size_t in_length,
		const uint8_t *private_key, uint8_t *out) {
	//M = x1||y1||MSG
	// in_length - 64 = mag_length
	uint8_t prefix[65];
	uint8_t scramble[65];
	uint8_t * t;
	int ret;

	memcpy(prefix, in, ECC_KEY_BYTES << 1);
	ret = generate_ecc_decrypt_scramble(private_key, prefix, scramble);
	if (ret != RESULT_SUCCESS)
		return ret;
	t = utility::kdf_with_sha256(scramble, ECC_KEY_BYTES << 1, in_length - 64);
	for (size_t i = 0; i < in_length - 64; i++)
		out[i] = in[i + 64] ^ t[i];
	ret = in_length - 64;
	delete[] t;
	return ret;
}

int IAlg_Ecc::ecc_sign(const uint8_t *hash, size_t hash_len,
		const uint8_t *private_key, uint8_t *sign_r, uint8_t *sign_s) {
	EC_KEY * eckey = NULL;
	ECDSA_SIG * sig = NULL;
	BIGNUM * bn_private_key = NULL;
	BIGNUM * bn_sign_r = NULL;
	BIGNUM * bn_sign_s = NULL;
	int ret = RESULT_SUCCESS;

	if (group == NULL)
		return ALGORITHM_ECC_GROUP_INIT_FAIL;

	bn_private_key = BN_new();
	bn_sign_r = BN_new();
	bn_sign_s = BN_new();
	BN_bin2bn(private_key, ECC_KEY_BYTES, bn_private_key);

	eckey = EC_KEY_new();
	EC_KEY_set_group(eckey, group);
	EC_KEY_set_private_key(eckey, bn_private_key);

	sig = ECDSA_do_sign(hash, hash_len, eckey);
	if (sig == NULL) {
		ret = ALGORITH_ECC_SIGN_FAIL;
		goto error;
	}
	bzero(sign_r, SIGN_BYTES);
	bzero(sign_s, SIGN_BYTES);

	BN_copy(bn_sign_r, sig->r);
	BN_copy(bn_sign_s, sig->s);

	int o;
	bzero(sign_r, ECC_KEY_BYTES);
	bzero(sign_s, ECC_KEY_BYTES);
	o = ((SIGN_BYTES << 3) - BN_num_bits(bn_sign_r)) >> 3;
	BN_bn2bin(bn_sign_r, sign_r + o);
	o = ((SIGN_BYTES << 3) - BN_num_bits(bn_sign_s)) >> 3;
	BN_bn2bin(bn_sign_s, sign_s + o);

	error: EC_KEY_free(eckey);
	ECDSA_SIG_free(sig);
	BN_free(bn_private_key);
	BN_free(bn_sign_r);
	BN_free(bn_sign_s);
	return ret;
}

int IAlg_Ecc::ecc_verify(const uint8_t *origin_hash, size_t hash_len,
		const uint8_t *public_key_x, const uint8_t *public_key_y,
		const uint8_t *sign_r, const uint8_t *sign_s) {
	EC_KEY * eckey = NULL;
	ECDSA_SIG * sig = NULL;
	BIGNUM * bn_public_key_x = NULL;
	BIGNUM * bn_public_key_y = NULL;
	BIGNUM * bn_sign_r = NULL;
	BIGNUM * bn_sign_s = NULL;
	int ret = VERIFY_FAIL;

	if (group == NULL)
		return ALGORITHM_ECC_GROUP_INIT_FAIL;

	bn_public_key_x = BN_new();
	bn_public_key_y = BN_new();
	bn_sign_r = BN_new();
	bn_sign_s = BN_new();
	BN_bin2bn(public_key_x, ECC_KEY_BYTES, bn_public_key_x);
	BN_bin2bn(public_key_y, ECC_KEY_BYTES, bn_public_key_y);
	BN_bin2bn(sign_r, ECC_KEY_BYTES, bn_sign_r);
	BN_bin2bn(sign_s, ECC_KEY_BYTES, bn_sign_s);
	eckey = EC_KEY_new();
	EC_KEY_set_group(eckey, group);
	EC_KEY_set_public_key_affine_coordinates(eckey, bn_public_key_x,
			bn_public_key_y);

	sig = ECDSA_SIG_new();

	BN_copy(sig->r, bn_sign_r);
	BN_copy(sig->s, bn_sign_s);

	ret = ECDSA_do_verify(origin_hash, hash_len, sig, eckey);
	if (ret == -1)
		return ALGORITH_ECC_VERIFY_FAIL;
	EC_KEY_free(eckey);
	ECDSA_SIG_free(sig);
	BN_free(bn_public_key_x);
	BN_free(bn_public_key_y);
	BN_free(bn_sign_r);
	BN_free(bn_sign_s);
	return ret;
}

int IAlg_Ecc::generate_ecc_encrypt_scramble(const uint8_t *public_key_x,
		const uint8_t *public_key_y, uint8_t *prefix, uint8_t *scramble) {
	int ret = RESULT_SUCCESS;
	EC_POINT *C1, *C2, *public_key;
	BIGNUM *k, *x, *y, *bn_public_key_x, *bn_public_key_y;

	x = BN_new();
	y = BN_new();
	C1 = EC_POINT_new(group);
	C2 = EC_POINT_new(group);
	public_key = EC_POINT_new(group);
	bn_public_key_x = BN_new();
	bn_public_key_y = BN_new();

	BN_bin2bn(public_key_x, ECC_KEY_BYTES, bn_public_key_x);
	BN_bin2bn(public_key_y, ECC_KEY_BYTES, bn_public_key_y);
	EC_POINT_set_affine_coordinates_GFp(group, public_key, bn_public_key_x,
			bn_public_key_y, NULL);

	k = utility::get_random(order);
	EC_POINT_mul(group, C1, k, 0, 0, NULL);
	EC_POINT_mul(group, C2, 0, public_key, k, NULL);

	if (EC_POINT_get_affine_coordinates_GFp(group, C1, x, y, NULL) == 0) {
		goto error;
		ret = ALGORITHM_CALC_ERROR;
	}
	BN_bn2bin(x, prefix);
	BN_bn2bin(y, prefix + ECC_KEY_BYTES);

	if (EC_POINT_get_affine_coordinates_GFp(group, C2, x, y, NULL) == 0) {
		goto error;
		ret = ALGORITHM_CALC_ERROR;
	}
	BN_bn2bin(x, scramble);
	BN_bn2bin(y, scramble + ECC_KEY_BYTES);

	error: BN_clear_free(x);
	BN_clear_free(y);
	BN_clear_free(k);
	BN_clear_free(bn_public_key_x);
	BN_clear_free(bn_public_key_y);
	EC_POINT_free(C1);
	EC_POINT_free(C2);
	EC_POINT_free(public_key);
	return ret;
}

int IAlg_Ecc::generate_ecc_decrypt_scramble(const uint8_t *private_key,
		const uint8_t *prefix, uint8_t *scramble) {
	int ret = RESULT_SUCCESS;
	EC_POINT *C1, *C2;
	BIGNUM *x, *y, *bn_private_key;

	x = BN_new();
	y = BN_new();
	bn_private_key = BN_new();
	C1 = EC_POINT_new(group);
	C2 = EC_POINT_new(group);

	BN_bin2bn(private_key, ECC_KEY_BYTES, bn_private_key);
	BN_bin2bn(prefix, ECC_KEY_BYTES, x);
	BN_bin2bn(prefix + ECC_KEY_BYTES, ECC_KEY_BYTES, y);
	if (EC_POINT_set_affine_coordinates_GFp(group, C1, x, y, NULL) == 0) {
		goto error;
		ret = ALGORITHM_CALC_ERROR;
	}

	EC_POINT_mul(group, C2, 0, C1, bn_private_key, NULL);

	if (EC_POINT_get_affine_coordinates_GFp(group, C2, x, y, NULL) == 0) {
		goto error;
		ret = ALGORITHM_CALC_ERROR;
	}
	BN_bn2bin(x, scramble);
	BN_bn2bin(y, scramble + ECC_KEY_BYTES);

	error: BN_free(x);
	BN_free(y);
	BN_free(bn_private_key);
	EC_POINT_free(C1);
	EC_POINT_free(C2);
	return ret;
}

uint16_t *IKey_Base_Manager::get_selected_seq(const uint8_t *hash_seq) {
	uint16_t *selected_seq;
	if (hash_seq == NULL)
		return NULL;
	selected_seq = new uint16_t[hid + 1];
	for (size_t i = 0; i < hid; i++)
		selected_seq[i] = (i << 5) + hash_seq[i];
	return selected_seq;
}

IKey_Base_Manager::IKey_Base_Manager(HASH_ALG_ID hid, CURVE_GROUP_ID oid) {
	this->oid = oid;
	this->hid = hid;
	group = NULL;
	order = NULL;
	group = EC_GROUP_new_by_curve_name(oid);
	order = BN_new();
	EC_GROUP_get_order(group, order, NULL);
	public_key_base_x = new uint8_t[ECC_KEY_BASE_COUNT * ECC_KEY_BYTES];
	public_key_base_y = new uint8_t[ECC_KEY_BASE_COUNT * ECC_KEY_BYTES];
	private_key_base = new uint8_t[ECC_KEY_BASE_COUNT * ECC_KEY_BYTES];
	b_load_private_key = false;
	b_load_public_key = false;
	passwd = NULL;
}

IKey_Base_Manager::~IKey_Base_Manager() {
	if (public_key_base_x)
		delete[] public_key_base_x;
	if (public_key_base_y)
		delete[] public_key_base_y;
	if (private_key_base)
		delete[] private_key_base;
	if (passwd)
		delete[] passwd;
	if (group != NULL)
		EC_GROUP_clear_free(group);
	if (order != NULL)
		BN_free(order);
	order = NULL;
	group = NULL;
}

char * IKey_Base_Manager::set_passwd(const char * in) {
	if (in == NULL)
		return NULL;
	int len = strlen(in);
	if (passwd)
		delete[] passwd;
	passwd = new char[len + 1];
	strcpy(passwd, in);
	return passwd;
}

const uint8_t *IKey_Base_Manager::get_private_key_base(uint32_t index) {
	if (index >= ECC_KEY_BASE_COUNT || private_key_base == NULL)
		return NULL;
	return &private_key_base[index << 5];
}

void IKey_Base_Manager::set_private_key_base(const uint8_t *in,
		uint32_t index) {
	if (index >= ECC_KEY_BASE_COUNT || private_key_base == NULL)
		return;
	memcpy(&private_key_base[index << 5], in, ECC_KEY_BYTES);
}

const uint8_t *IKey_Base_Manager::get_public_key_base_x(uint32_t index) {
	if (index >= ECC_KEY_BASE_COUNT || public_key_base_x == NULL)
		return NULL;
	return &public_key_base_x[index << 5];
}

void IKey_Base_Manager::set_public_key_base_x(const uint8_t *in,
		uint32_t index) {
	if (index >= ECC_KEY_BASE_COUNT || public_key_base_x == NULL)
		return;
	memcpy(&public_key_base_x[index << 5], in, ECC_KEY_BYTES);
}

const uint8_t *IKey_Base_Manager::get_public_key_base_y(uint32_t index) {
	if (index >= ECC_KEY_BASE_COUNT || public_key_base_y == NULL)
		return NULL;
	return &public_key_base_y[index << 5];
}

void IKey_Base_Manager::set_public_key_base_y(const uint8_t *in,
		uint32_t index) {
	if (index >= ECC_KEY_BASE_COUNT || public_key_base_y == NULL)
		return;
	memcpy(&public_key_base_y[index << 5], in, ECC_KEY_BYTES);
}

int IKey_Base_Manager::public_key_mix(uint8_t *Point_rx, uint8_t *Point_ry,
		const uint8_t *Point_x, const uint8_t *Point_y) {
	BIGNUM *rx, *ry, *x, *y;
	EC_POINT *P, *R, *S;
	BN_CTX * ctx;
	int ret = 1;
	int offset;

	ret = RESULT_SUCCESS;
	ctx = BN_CTX_new();
	rx = BN_new();
	ry = BN_new();
	x = BN_new();
	y = BN_new();
	BN_bin2bn(Point_rx, 32, rx);
	BN_bin2bn(Point_ry, 32, ry);
	BN_bin2bn(Point_x, 32, x);
	BN_bin2bn(Point_y, 32, y);
	P = EC_POINT_new(group);
	R = EC_POINT_new(group);
	S = EC_POINT_new(group);

	if (EC_POINT_set_affine_coordinates_GFp(group, R, rx, ry, NULL) != 1) {
		ret = ALGORITHM_CALC_ERROR;
		goto _error;
	}

	if (EC_POINT_set_affine_coordinates_GFp(group, S, x, y, NULL) != 1) {
		ret = ALGORITHM_CALC_ERROR;
		goto _error;
	}

	if (EC_POINT_add(group, R, S, R, NULL) != 1) {
		ret = ALGORITHM_CALC_ERROR;
		goto _error;
	}

	EC_POINT_make_affine(group, R, ctx);
	if (EC_POINT_get_affine_coordinates_GFp(group, R, rx, ry, ctx) != 1) {
		ret = ALGORITHM_CALC_ERROR;
		goto _error;
	}

	offset = (256 - BN_num_bits(rx)) >> 3;
	bzero(Point_rx, 32);
	BN_bn2bin(rx, Point_rx + offset);
	offset = (256 - BN_num_bits(ry)) >> 3;
	memset(Point_ry, 0, 32);
	BN_bn2bin(ry, Point_ry + offset);

	_error: BN_free(rx);
	BN_free(ry);
	BN_free(x);
	BN_free(y);
	BN_CTX_free(ctx);
	EC_POINT_free(P);
	EC_POINT_free(S);
	EC_POINT_free(R);

	return ret;
}

int IKey_Base_Manager::private_key_mix(uint8_t * r, const uint8_t * a) { //r = (r + a) mod m
	BIGNUM * bn_r, *bn_a, *bn_b, *bn_m;
	BN_CTX * ctx;
	int ret = RESULT_SUCCESS;
	int offset;
	ctx = BN_CTX_new();
	bn_m = BN_new();
	bn_r = BN_new();
	bn_a = BN_new();
	bn_b = BN_new();

	BN_bin2bn(a, 32, bn_a);
	BN_bin2bn(r, 32, bn_r);

	if (EC_GROUP_get_order(group, bn_m, ctx) != 1) {
		ret = ALGORITHM_CALC_ERROR;
		goto error;
	}
	BN_mod_add(bn_b, bn_a, bn_r, bn_m, ctx);

	offset = (256 - BN_num_bits(bn_b)) >> 3;
	bzero(r, 32);
	BN_bn2bin(bn_b, r + offset);
	error: BN_free(bn_m);
	BN_free(bn_a);
	BN_free(bn_b);
	BN_free(bn_r);
	BN_CTX_free(ctx);
	return ret;
}

int IKey_Base_Manager::generate_key_pair_base(uint32_t *private_token,
		uint32_t *public_token) {
	int ret = RESULT_SUCCESS;
	int offset;
	const BIGNUM * bn_private_key = NULL;
	const EC_POINT * pt_public_key = NULL;
	BIGNUM *x, *y;
	EC_KEY *key_pair;
	uint8_t public_key_x[ECC_KEY_BYTES], public_key_y[ECC_KEY_BYTES];
	uint8_t private_key[ECC_KEY_BYTES];

	key_pair = EC_KEY_new();
	x = BN_new();
	y = BN_new();

	if (EC_KEY_set_group(key_pair, group) != 1) {
		ret = ALGORITHM_CALC_ERROR;
		goto error;
	}
	for (int i = 0; i < ECC_KEY_BASE_COUNT; i++) {
		if (EC_KEY_generate_key(key_pair) != 1) {
			ret = ALGORITHM_CALC_ERROR;
			goto error;
		}
		bn_private_key = EC_KEY_get0_private_key(key_pair);
		pt_public_key = EC_KEY_get0_public_key(key_pair);
		if (!bn_private_key || !pt_public_key) {
			ret = ALGORITHM_CALC_ERROR;
			goto error;
		}

		EC_POINT_get_affine_coordinates_GFp(group, pt_public_key, x, y, NULL);

		bzero(public_key_x, ECC_KEY_BYTES);
		bzero(public_key_y, ECC_KEY_BYTES);
		bzero(private_key, ECC_KEY_BYTES);

		offset = ((ECC_KEY_BYTES << 3) - BN_num_bits(x)) >> 3;
		BN_bn2bin(x, public_key_x + offset);
		offset = ((ECC_KEY_BYTES << 3) - BN_num_bits(y)) >> 3;
		BN_bn2bin(y, public_key_y + offset);
		offset = ((ECC_KEY_BYTES << 3) - BN_num_bits(bn_private_key)) >> 3;
		BN_bn2bin(bn_private_key, private_key + offset);
		set_private_key_base(private_key, i);
		set_public_key_base_x(public_key_x, i);
		set_public_key_base_y(public_key_y, i);
	}
	b_load_private_key = true;
	b_load_public_key = true;
	// if token ptr is null means do not add to key store,this only for test
	// else use key store to store key
	if (private_token && public_token) {
		KeyStore ks;
		if ((ret = ks.open_store(passwd)) == RESULT_SUCCESS) {
			*private_token = ks.add_key_base(private_key_base, NULL);
			*public_token = ks.add_key_base(public_key_base_x, public_key_base_y);
		} else
			return ret;
	}
	error: EC_KEY_free(key_pair);
	BN_clear_free(x);
	BN_clear_free(y);

	return ret;
}

int IKey_Base_Manager::get_mixed_private_key(const uint8_t *hash_value,
		uint8_t* private_key) {
	uint16_t *seq;
	bzero(private_key, ECC_KEY_BYTES);
	seq = get_selected_seq(hash_value);

	for (size_t i = 0; i < this->hid; i++)
		private_key_mix(private_key, get_private_key_base(seq[i]));

	delete[] seq;
	seq = NULL;
	return RESULT_SUCCESS;
}

int IKey_Base_Manager::get_mixed_public_key(const uint8_t *hash_value,
		uint8_t* public_key_x, uint8_t* public_key_y) {
	uint16_t *seq;

	bzero(public_key_x, ECC_KEY_BYTES);
	bzero(public_key_y, ECC_KEY_BYTES);
	seq = get_selected_seq(hash_value);

	memcpy(public_key_x, get_public_key_base_x(seq[0]), ECC_KEY_BYTES);
	memcpy(public_key_y, get_public_key_base_y(seq[0]), ECC_KEY_BYTES);

	for (size_t i = 1; i < this->hid; i++)
		public_key_mix(public_key_x, public_key_y,
				get_public_key_base_x(seq[i]), get_public_key_base_y(seq[i]));

	delete[] seq;
	seq = NULL;
	return RESULT_SUCCESS;
}

int IKey_Base_Manager::load_public_key_base(uint32_t token) {

	int ret;

	if (!b_load_public_key) {
		KeyStore ks;
		if ((ret = ks.open_store(passwd)) != RESULT_SUCCESS)
			return ret;
		if ((ret = ks.get_key_base(this->public_key_base_x,
				this->public_key_base_y, token)) != RESULT_SUCCESS)
			return ret;
		b_load_public_key = true;
	}
	return RESULT_SUCCESS;
}

int IKey_Base_Manager::load_private_key_base(uint32_t token) {
	int ret;
	if (!b_load_private_key) {
		KeyStore ks;
		if ((ret = ks.open_store(passwd)) != RESULT_SUCCESS)
			return ret;
		if ((ret = ks.get_key_base(this->private_key_base, NULL, token))
				!= RESULT_SUCCESS)
			return ret;
		b_load_private_key = true;
	}
	return RESULT_SUCCESS;
}

IKey_Manager::IKey_Manager(CURVE_GROUP_ID oid) {
	this->oid = oid;
	group = NULL;
	group = EC_GROUP_new_by_curve_name(oid);
	order = BN_new();
	EC_GROUP_get_order(group, order, NULL);
	private_key = new uint8_t[ECC_KEY_BYTES];
	public_key_x = new uint8_t[ECC_KEY_BYTES];
	public_key_y = new uint8_t[ECC_KEY_BYTES];
	cipher_key = NULL;
	passwd = NULL;
	b_load_private_key = false;
	b_load_public_key = false;
	b_load_cipher_key = false;
}

IKey_Manager::~IKey_Manager() {
	EC_GROUP_clear_free(group);
	BN_clear_free(order);
	if (private_key)
		delete []private_key;
	if (public_key_x)
		delete []public_key_x;
	if (public_key_y)
		delete []public_key_y;
	if (passwd)
		delete []passwd;
	if(cipher_key)
		delete []cipher_key;
}

int IKey_Manager::generate_cipher_key(uint32_t *cipher_toke)
{
	int ret;
	if(cipher_key == NULL)
		cipher_key = new uint8_t[CIPHER_KEY_BYTES];
	do{
		ret = utility::get_random(cipher_key,CIPHER_KEY_BYTES);
		if(ret != CIPHER_KEY_BYTES)
			return KEY_INITIALIZE_FAIL;
	}while(cipher_key[0] < 0x80);

	b_load_cipher_key = true;

	if(cipher_toke == NULL)
		return RESULT_SUCCESS;

	KeyStore ks;
	if ((ret = ks.open_store(passwd)) == RESULT_SUCCESS)
		*cipher_toke = ks.add_key(cipher_key, NULL,CIPHER_KEY);
	else
		return ret;
	return RESULT_SUCCESS;
}

int IKey_Manager::generate_key_pair(uint32_t *private_token,
		uint32_t *public_token) {
	int ret = RESULT_SUCCESS;
	int offset;
	const BIGNUM * bn_private_key = NULL;
	const EC_POINT * pt_public_key = NULL;
	BIGNUM *x, *y;
	EC_KEY *key_pair;

	key_pair = EC_KEY_new();
	x = BN_new();
	y = BN_new();

	if (EC_KEY_set_group(key_pair, group) != 1) {
		ret = ALGORITHM_CALC_ERROR;
		goto error;
	}
	if (EC_KEY_generate_key(key_pair) != 1) {
		ret = ALGORITHM_CALC_ERROR;
		goto error;
	}
	bn_private_key = EC_KEY_get0_private_key(key_pair);
	pt_public_key = EC_KEY_get0_public_key(key_pair);
	if (!bn_private_key || !pt_public_key) {
		ret = ALGORITHM_CALC_ERROR;
		goto error;
	}

	EC_POINT_get_affine_coordinates_GFp(group, pt_public_key, x, y, NULL);
	if (public_key_x != NULL) {
		delete[] public_key_x;
		public_key_x = new uint8_t[ECC_KEY_BYTES];
	} else
		public_key_x = new uint8_t[ECC_KEY_BYTES];
	if (public_key_y != NULL) {
		delete[] public_key_y;
		public_key_y = new uint8_t[ECC_KEY_BYTES];
	} else
		public_key_y = new uint8_t[ECC_KEY_BYTES];
	if (private_key != NULL) {
		delete[] private_key;
		private_key = new uint8_t[ECC_KEY_BYTES];
	} else
		private_key = new uint8_t[ECC_KEY_BYTES];
	bzero(public_key_x, ECC_KEY_BYTES);
	bzero(public_key_y, ECC_KEY_BYTES);
	bzero(private_key, ECC_KEY_BYTES);
	offset = ((ECC_KEY_BYTES << 3) - BN_num_bits(x)) >> 3;
	BN_bn2bin(x, public_key_x + offset);
	offset = ((ECC_KEY_BYTES << 3) - BN_num_bits(y)) >> 3;
	BN_bn2bin(y, public_key_y + offset);
	offset = ((ECC_KEY_BYTES << 3) - BN_num_bits(bn_private_key)) >> 3;
	BN_bn2bin(bn_private_key, private_key + offset);
	b_load_private_key = true;
	b_load_public_key = true;
	// if token ptr is null means do not add to key store,this only for test
	// else use key store to store key
	if (private_token && public_token) {
		KeyStore ks;
		if ((ret = ks.open_store(passwd)) == RESULT_SUCCESS) {
			*private_token = ks.add_key(private_key, NULL, PRIVATE_KEY);
			*public_token = ks.add_key(public_key_x, public_key_y, PUBLIC_KEY);
		} else
			return ret;
	}
	error: EC_KEY_free(key_pair);
	BN_clear_free(x);
	BN_clear_free(y);
	return ret;
}

int IKey_Manager::load_cipher_key(uint32_t token) {
	int ret;
	KeyStore ks;
	if ((ret = ks.open_store(passwd)) != RESULT_SUCCESS)
		return ret;
	if(cipher_key == NULL)
		cipher_key = new uint8_t[CIPHER_KEY_BYTES];

	if ((ret = ks.get_key(cipher_key,NULL,CIPHER_KEY,token)) != RESULT_SUCCESS)
		return ret;
	b_load_cipher_key = true;
	return RESULT_SUCCESS;
}

int IKey_Manager::load_public_key(uint32_t token) {
	int ret;
	KeyStore ks;
	if ((ret = ks.open_store(passwd)) != RESULT_SUCCESS)
		return ret;
	if ((ret = ks.get_key(this->public_key_x, this->public_key_y, PUBLIC_KEY,
			token)) != RESULT_SUCCESS)
		return ret;
	b_load_public_key = true;
	return RESULT_SUCCESS;
}

int IKey_Manager::load_private_key(uint32_t token) {
	int ret;

	KeyStore ks;
	if ((ret = ks.open_store(passwd)) != RESULT_SUCCESS)
		return ret;
	if ((ret = ks.get_key(this->private_key, NULL, PRIVATE_KEY, token))
			!= RESULT_SUCCESS)
		return ret;
	b_load_private_key = true;
	return RESULT_SUCCESS;
}

char * IKey_Manager::set_passwd(const char * in) {
	if (in == NULL)
		return NULL;

	int len = strlen(in);
	if (passwd)
		delete[] passwd;
	passwd = new char[len + 1];
	strcpy(passwd, in);
	return passwd;
}

const uint8_t *IKey_Manager::get_cipher_key() {
	return cipher_key;
}

const uint8_t *IKey_Manager::get_public_key_x() {
	return public_key_x;
}

const uint8_t *IKey_Manager::get_public_key_y() {
	return public_key_y;
}


const uint8_t *IKey_Manager::get_private_key() {
	return private_key;
}

void IKey_Manager::set_cipher_key(const uint8_t *in) {
	if (cipher_key == NULL)
			return;
	memcpy(cipher_key, in, CIPHER_KEY_BYTES);
}

void IKey_Manager::set_public_key_x(const uint8_t *in) {
	if (public_key_x == NULL)
		return;
	memcpy(public_key_x, in, ECC_KEY_BYTES);
}

void IKey_Manager::set_public_key_y(const uint8_t *in) {
	if (public_key_y == NULL)
		return;
	memcpy(public_key_y, in, ECC_KEY_BYTES);
}

void IKey_Manager::set_private_key(const uint8_t *in) {
	if (private_key == NULL)
		return;
	memcpy(private_key, in, ECC_KEY_BYTES);
}
