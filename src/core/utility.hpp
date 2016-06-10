/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年4月22日
 */
#ifndef SRC_CORE_UTILITY_HPP_
#define SRC_CORE_UTILITY_HPP_
#include <openssl/bn.h>
#include "core_define.hpp"
/*
 * common function collector class
 */
class utility {
public:
	utility();
	virtual ~utility();
	// random
	static int get_random(uint8_t * random, size_t random_len_byte);
	static BIGNUM* get_random(const BIGNUM *order);
	//base64
	static char *base64_encoder(const uint8_t * input, int length,
			bool with_new_line = true);
	static uint8_t *base64_decoder(const char * input,
			bool with_new_line = true);
	static int get_base64_decode_len(const char *base64);
	// kdf
	static uint8_t *kdf_with_md5(const uint8_t *msg, size_t msg_len,
			size_t key_len);
	static uint8_t *kdf_with_sha256(const uint8_t *msg, size_t msg_len,
			size_t key_len);
};

#endif /* SRC_CORE_UTILITY_HPP_ */
