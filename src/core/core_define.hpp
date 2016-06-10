/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年4月15日
 */

#ifndef SRC_CORE_CORE_DEFINE_HPP_
#define SRC_CORE_CORE_DEFINE_HPP_

#define __DEBUG__
#define __SERVER__

#include <stdint.h>
#include <stdio.h>

static const int _ERROR_ = 0;
static const int SALT_BYTES = 8;
static const int SIGN_BYTES = 32;
static const int ECC_KEY_BYTES = 32;
static const int CIPHER_KEY_BYTES = 16;
static const int ECC_KEY_BASE_COUNT = 8192;
static const int MAX_HASH_BYTES = 32;
static const int CIPHER_BLOCK_BYTES = 16;

static const int RESULT_SUCCESS = 0;
static const int RESULT_ERROR = -1;

static const int ALGORITHM_CALC_ERROR = _ERROR_ - 1;
static const int ALGORITHM_NOT_INITILIZE = _ERROR_ - 2;
static const int ALGORITHM_NOT_DEFINE = _ERROR_ - 3;
static const int ALGORITHM_KEY_ERROR = _ERROR_ - 4;
static const int ALGORITHM_ECC_GROUP_INIT_FAIL = _ERROR_ - 5;
static const int ALGORITH_ECC_VERIFY_FAIL = _ERROR_ - 6;
static const int ALGORITH_ECC_SIGN_FAIL = _ERROR_ - 7;
static const int ALGORITHM_ALLREADY_INITILIZE = _ERROR_ - 8;

static const int KEY_INITIALIZE_FAIL = _ERROR_ - 13;
static const int BUFFER_IS_TOO_SMALL = _ERROR_ - 9;

static const int ENVENLOPE_TAMPERED = _ERROR_ - 11;
static const int ENVENLOPE_MESSAGE_TAMPERED = _ERROR_ - 12;

static const int NO_ACCESS_PRIVILEGE = _ERROR_ - 14;
static const int CREATE_FILE_ERROR = _ERROR_ - 15;
static const int OPEN_FILE_ERROR = _ERROR_ - 10;
static const int OVERWRITE_PASS_FILE_FALSE = _ERROR_ - 16;
static const int KEY_STROE_LOCKED = _ERROR_ - 17;
static const int KEY_STROE_OPEN_FAIL = _ERROR_ - 18;
static const int CONF_FILE_NOT_FOUND = _ERROR_ - 18;
static const int VERIFY_FAIL = 0;
static const int VERIFY_SUCCESS = 1;

//#ifdef __DEBUG__
//static const char store_dir[] = "/home/james/keystore";
//static const char passwd_file[] = "/home/james/keystore/passwd";
//#else
//static const char store_dir[] = "/etc/keystore";
//static const char passwd_file [] = "/etc/keystore/passwd";
//#endif

enum KEY_TYPE {
	PRIVATE_KEY = 1, PUBLIC_KEY, PRIVATE_KEY_BASE, PUBLIC_KEY_BASE, CIPHER_KEY
};
enum CURVE_GROUP_ID {
	SM_2 = 1, X962_SECG = 415, SECG = 714, RFC3639_1 = 927, RFC3639_2 = 928
};

enum HASH_ALG_ID {
	HASH_NOT_DEF = 0, SM_3 = 32, SHA_256 = 32, MD_5 = 16
};

enum SYMMETRIC_ALG_ID {
	SM_4_CBC = 0x20, AES_128_CBC,
};

#endif /* SRC_CORE_CORE_DEFINE_HPP_ */
