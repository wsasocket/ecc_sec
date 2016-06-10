/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年5月6日
 */
#ifndef KEYSTORE_HPP_
#define KEYSTORE_HPP_

/*
 * This class is used to store keys in file format
 * you can rewrite this class in different ways.
 * In key store directory,there is a file named "passwd"
 * this file contain salt and hash,open_store() will transmit password
 * if passwd is correct you can get private key,if password is NULL
 * default passwd is you machine name.
 */
#include <dirent.h>
#include "core_define.hpp"

class KeyStore {
public:
	KeyStore();
	virtual ~KeyStore();

public:
	int open_store(char *pass = NULL);
	void close_store();
	// delete key in store token identify which key is to be delete
	int delete_key(KEY_TYPE type, uint32_t token);
	// return token
	uint32_t add_key(uint8_t * key1, uint8_t * key2, KEY_TYPE type);
	uint32_t add_key_base(uint8_t * key1, uint8_t * key2);
	// iterator get all token
	uint32_t get_key_token(KEY_TYPE type);
	uint32_t find_first_token(KEY_TYPE type);
	uint32_t find_next_token(KEY_TYPE type);
	int get_key(uint8_t * key1, uint8_t * key2, KEY_TYPE type, uint32_t token);
	int get_key_base(uint8_t * key1, uint8_t * key2, uint32_t token);

protected:
	virtual int get_machine_code(uint8_t * code,int in_len);
private:
	int init_dir();
	int init_passwd_file(char *pass = NULL, bool overwrite = false);
	uint8_t *key_encrypt(const uint8_t *in,int in_len,uint32_t *token);
	uint8_t *key_decrypt(const uint8_t *in,int in_len,uint32_t token);
	inline uint32_t get_token(uint8_t * h);
	inline uint32_t parse_filename(char * file, KEY_TYPE t);

private:
	bool is_store_open;
	struct dirent *dp;
	DIR *dir_fd;
	char *store_dir;
	char *passwd_file;
};
#endif
