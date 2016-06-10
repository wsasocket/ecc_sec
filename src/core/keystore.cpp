/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年5月6日
 */
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include "../kernal/alg_cigher_aes128.hpp"
#include "../kernal/alg_hash_SHA256.hpp"
#include "utility.hpp"
#include "keystore.hpp"
#include "../kernal/configure.hpp"
using namespace std;

KeyStore::KeyStore() {
	dir_fd = NULL;
	dp = NULL;
	is_store_open = false;
	Configure *conf = Configure::GetConfigure();
	if(conf->get_keystore_path() != NULL)
	{
		this->store_dir = new char[strlen(conf->get_keystore_path()) + 1];
		this->passwd_file = new char[strlen(conf->get_keystore_path()) + 7];
		strcpy(store_dir,conf->get_keystore_path());
		strcpy(passwd_file,conf->get_keystore_path());
		strcat(passwd_file,"passwd");
	}
}

KeyStore::~KeyStore() {
	if(this->store_dir)
		delete []store_dir;
	if(this->passwd_file)
		delete []passwd_file;
}

int KeyStore::get_machine_code(uint8_t *code, int in_len) {
	//TODO this is a demo,you'd best generate more complex and unique code to improve security
	gethostname((char *) code, in_len);
	return strlen((char *)code);
}

int KeyStore::init_passwd_file(char *pass, bool overwrite) {
	if (access(passwd_file, F_OK | W_OK | R_OK) == 0) {
		if (!overwrite)
			return RESULT_SUCCESS;

		if (unlink(passwd_file) != 0)
			return OVERWRITE_PASS_FILE_FALSE;
	}

	ofstream passwdfile;
	char computer[255];

	if (pass == NULL) {
		if (get_machine_code((uint8_t *)computer, 255) <= 0)
			return RESULT_ERROR;
	} else {
		strcpy(computer, pass);
	}

	passwdfile.open(passwd_file);
	if (!passwdfile.is_open())
		return CREATE_FILE_ERROR;

	char salt[9];
	uint8_t *hash_value;
	char * p;
	utility::get_random((uint8_t*) salt, 8);
	p = utility::base64_encoder((uint8_t*) salt, 8);
	passwdfile << p;
	delete[] p;

	Alg_Hash_SHA256 sha;
	hash_value = new uint8_t[sha.get_hash_out_size() + 1];
	sha.hash_init();
	sha.hash_update((uint8_t*) salt, 8);
	sha.hash_update((uint8_t*) computer, strlen(computer));
	sha.hash_final(hash_value);
	p = utility::base64_encoder(hash_value, sha.get_hash_out_size());
	passwdfile << p;
	delete[] p;
	passwdfile.close();

	return RESULT_SUCCESS;
}

int KeyStore::init_dir() {
	int status = mkdir(store_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

	if (status < 0 && EACCES == errno)
		return NO_ACCESS_PRIVILEGE;

	if (status == 0 || (status < 0 && EEXIST == errno))
		return RESULT_SUCCESS;
	else
		return errno;
}

int KeyStore::open_store(char *pass) {
	ifstream passwdfile;
	uint8_t computer[128];
	int ret;

	if (is_store_open)
		return RESULT_SUCCESS;

	if ((ret = init_dir()) != RESULT_SUCCESS)
		return ret;

	if ((ret = init_passwd_file(pass)) != RESULT_SUCCESS)
		return ret;

	if (pass == NULL) {
		if (get_machine_code(computer, 128) <= 0)
			return RESULT_ERROR;
	} else {
		strcpy((char *) computer, pass);
	}

	passwdfile.open(passwd_file);
	if (!passwdfile.is_open())
		return OPEN_FILE_ERROR;

	char salt[SALT_BYTES + 1];
	uint8_t *hash_value;
	char buffer[255];
	uint8_t * p;
	char * pp;

	passwdfile >> buffer;
	p = utility::base64_decoder(buffer, false);
	memcpy(salt, p, SALT_BYTES);
	delete[] p;

	Alg_Hash_SHA256 sha;
	hash_value = new uint8_t[sha.get_hash_out_size() + 1];
	sha.hash_init();
	sha.hash_update((uint8_t*) salt, 8);
	sha.hash_update(computer, strlen((char *) computer));
	sha.hash_final(hash_value);
	pp = utility::base64_encoder(hash_value, sha.get_hash_out_size(), false);
	bzero(buffer, 255);
	passwdfile >> buffer;
	passwdfile.close();
	ret = strcmp(buffer, pp);
	delete[] pp;
	delete[] hash_value;
	if (RESULT_SUCCESS == ret) {
		is_store_open = true;
		return RESULT_SUCCESS;
	} else
		return RESULT_ERROR;
}

void KeyStore::close_store() {
	is_store_open = false;
}

uint32_t KeyStore::get_token(uint8_t * h) {
	uint32_t l;
	l = h[0];
	l <<= 8;
	l |= h[1];
	l <<= 8;
	l |= h[2];
	l <<= 8;
	l |= h[3];
	return l;
}


uint32_t KeyStore::find_first_token(KEY_TYPE type) {
	if (!is_store_open)
		return 0;
	if ((dir_fd = opendir(store_dir)) == NULL)
		return 0;
	return find_next_token(type);
}

uint32_t KeyStore::get_key_token(KEY_TYPE type) {
	uint32_t ret;
	if (!is_store_open)
		return 0;
	if ((dir_fd = opendir(store_dir)) == NULL)
		return 0;
	ret = find_next_token(type);
	if (ret != 0) {
		closedir(dir_fd);
		dp = NULL;
		dir_fd = NULL;
		return 0;
	}
	return ret;
}

uint32_t KeyStore::find_next_token(KEY_TYPE type) {
	uint32_t token;
	if (!is_store_open)
		return 0;
	dp = readdir(dir_fd);
	if (dp == NULL) {
		closedir(dir_fd);
		dp = NULL;
		dir_fd = NULL;
		return 0;
	}
	do {
		if ((token = parse_filename(dp->d_name, type)) != 0) {
			break;
		}
		dp = readdir(dir_fd);
	} while (dp != NULL);
	if (dp == NULL) {
		closedir(dir_fd);
		dp = NULL;
		dir_fd = NULL;
		return 0;
	}
	return token;
}

uint32_t KeyStore::parse_filename(char * f, KEY_TYPE t) {
	int itype;
	uint32_t token;
	if (sscanf(f, "%d_%08x.key", &itype, &token) != 2)
		return 0;
	if (itype == t)
		return token;
	return 0;
}

uint32_t KeyStore::add_key(uint8_t * key1, uint8_t * key2, KEY_TYPE type) {
	Alg_Hash_SHA256 sha;
	uint8_t k1[128];
	uint8_t k2[128];
	uint8_t *tmp = NULL;
	uint8_t hash_value[33];
	uint32_t token;
	ofstream keyfile;
	char path[255];
	char * p;
	if (!is_store_open)
		return 0;
	switch (type) {
	case PRIVATE_KEY: {
		tmp = key_encrypt(key1, ECC_KEY_BYTES, &token);
		if (tmp == NULL)
			return 0;
		memcpy(k1, tmp, ECC_KEY_BYTES);
		delete[] tmp;
		tmp = NULL;
		break;
	}
	case PUBLIC_KEY: {
		memcpy(k1, key1, ECC_KEY_BYTES);
		memcpy(k2, key2, ECC_KEY_BYTES);
		sha.hash_init();
		sha.hash_update(k1, ECC_KEY_BYTES);
		sha.hash_update(k2, ECC_KEY_BYTES);
		sha.hash_final(hash_value);
		token = get_token(hash_value);
		break;
	}
	case CIPHER_KEY: {
		tmp = key_encrypt(key1, CIPHER_KEY_BYTES, &token);
		if (tmp == NULL)
			return 0;
		memcpy(k1, tmp, CIPHER_KEY_BYTES);
		delete[] tmp;
		tmp = NULL;
		break;
	}
	default:
		return 0;
	}

	sprintf(path, "%s/%d_%08x.key", store_dir, type, token);
	keyfile.open(path);
	if (!keyfile.is_open())
		return 0;

	p = utility::base64_encoder(k1,
			(type == CIPHER_KEY) ? CIPHER_KEY_BYTES : ECC_KEY_BYTES);
	keyfile << p;
	delete[] p;
	if (PUBLIC_KEY == type) {
		p = utility::base64_encoder(k2, ECC_KEY_BYTES);
		keyfile << p;
		delete[] p;
	}
	keyfile.close();
	return token;
}

int KeyStore::get_key(uint8_t * key1, uint8_t * key2, KEY_TYPE type,
		uint32_t token) {
	char k1[128], k2[128];
	uint8_t *kp1 = NULL, *kp2 = NULL;
	ifstream keyfile;
	char path[255];
	if (!is_store_open)
		return KEY_STROE_LOCKED;
	sprintf(path, "%s/%d_%08x.key", store_dir, type, token);
	keyfile.open(path);
	if (!keyfile.is_open())
		return OPEN_FILE_ERROR;

	if (PUBLIC_KEY == type) {
		keyfile >> k1;
		kp1 = utility::base64_decoder(k1, false);
		memcpy(key1, kp1, ECC_KEY_BYTES);
		delete[] kp1;
		keyfile >> k2;
		kp2 = utility::base64_decoder(k2, false);
		memcpy(key2, kp2, ECC_KEY_BYTES);
		delete[] kp2;
	} else {
		keyfile >> k1;
		kp1 = utility::base64_decoder(k1, false);
		kp2 = key_decrypt(kp1,
				(type == CIPHER_KEY) ? CIPHER_KEY_BYTES : ECC_KEY_BYTES, token);
		delete[] kp1;
		if (kp2 == NULL)
			return KEY_INITIALIZE_FAIL;
		memcpy(key1, kp2,
				(type == CIPHER_KEY) ? CIPHER_KEY_BYTES : ECC_KEY_BYTES);
		delete[] kp2;
	}
	keyfile.close();
	return RESULT_SUCCESS;
}

uint32_t KeyStore::add_key_base(uint8_t * key1, uint8_t * key2) {
	Alg_Hash_SHA256 sha;
	uint8_t hash_value[33];
	uint8_t *tmp = NULL;
	uint32_t token;
	ofstream keyfile;
	char path[255];
	char * p;
	KEY_TYPE type = PRIVATE_KEY_BASE;
	if (!is_store_open)
		return 0;
	if (key1 && key2) {
		type = PUBLIC_KEY_BASE;
		sha.hash_init();
		sha.hash_update(key1, ECC_KEY_BASE_COUNT * ECC_KEY_BYTES);
		sha.hash_update(key2, ECC_KEY_BASE_COUNT * ECC_KEY_BYTES);
		sha.hash_final(hash_value);
		token = get_token(hash_value);
	} else {
		tmp = key_encrypt(key1, ECC_KEY_BASE_COUNT * ECC_KEY_BYTES, &token);
		if (tmp == NULL)
			return 0;
	}
	sprintf(path, "%s/%d_%08x.key", store_dir, type, token);
	keyfile.open(path);
	if (!keyfile.is_open())
		return 0;

	if (PUBLIC_KEY_BASE == type) {
		p = utility::base64_encoder(key1, ECC_KEY_BASE_COUNT * ECC_KEY_BYTES);
		keyfile << p;
		delete[] p;
		p = utility::base64_encoder(key2, ECC_KEY_BASE_COUNT * ECC_KEY_BYTES);
		keyfile << p;
		delete[] p;
	} else {
		p = utility::base64_encoder(tmp, ECC_KEY_BASE_COUNT * ECC_KEY_BYTES);
		keyfile << p;
		delete[] p;
		delete tmp;
	}
	keyfile.close();
	return token;
}

int KeyStore::get_key_base(uint8_t * key1, uint8_t * key2, uint32_t token) {
	char *buffer;
	char tmp[67];
	char *ptr;
	int decode_len;
	uint8_t *kp1, *kp2;
	ifstream keyfile;
	char path[255];
	KEY_TYPE type = PRIVATE_KEY_BASE;

	if (!is_store_open)
		return KEY_STROE_LOCKED;
	if (key1 && key2)
		type = PUBLIC_KEY_BASE;
	sprintf(path, "%s/%d_%08x.key", store_dir, type, token);
	keyfile.open(path);
	if (!keyfile.is_open())
		return OPEN_FILE_ERROR;

	buffer = new char[(ECC_KEY_BASE_COUNT * ECC_KEY_BYTES) * 2];
	ptr = buffer;
	if (PUBLIC_KEY_BASE == type) {
		do{
			keyfile >> tmp;
			memcpy(ptr,tmp,strlen(tmp));
			ptr += strlen(tmp);
		}while(strlen(tmp) == 64);
		decode_len = utility::get_base64_decode_len(buffer);
		if(decode_len != ECC_KEY_BASE_COUNT * ECC_KEY_BYTES)
		{
			delete []buffer;
			return KEY_INITIALIZE_FAIL;
		}
		kp1 = utility::base64_decoder(buffer,false);
		memcpy(key1, kp1, ECC_KEY_BASE_COUNT * ECC_KEY_BYTES);
		delete[] kp1;
		ptr = buffer;
		do{
			keyfile >> tmp;
			memcpy(ptr,tmp,strlen(tmp));
			ptr += strlen(tmp);
		}while(strlen(tmp) == 64);
		decode_len = utility::get_base64_decode_len(buffer);
		if(decode_len != ECC_KEY_BASE_COUNT * ECC_KEY_BYTES)
		{
			delete []buffer;
			return KEY_INITIALIZE_FAIL;
		}
		kp2 = utility::base64_decoder(buffer,false);
		memcpy(key2, kp2, ECC_KEY_BASE_COUNT * ECC_KEY_BYTES);
		delete[] kp2;
		delete[] buffer;
	} else {
		ptr = buffer;
		do{
			keyfile >> tmp;
			memcpy(ptr,tmp,strlen(tmp));
			ptr += strlen(tmp);
		}while(strlen(tmp) == 64);

		decode_len = utility::get_base64_decode_len(buffer);
		if(decode_len != ECC_KEY_BASE_COUNT * ECC_KEY_BYTES)
		{
			delete []buffer;
			return KEY_INITIALIZE_FAIL;
		}
		kp1 = utility::base64_decoder(buffer,false);
		kp2 = key_decrypt(kp1, ECC_KEY_BASE_COUNT * ECC_KEY_BYTES, token);
		if (kp2 == NULL) {
			delete[] kp1;
			delete[] buffer;
			return KEY_INITIALIZE_FAIL;
		}
		memcpy(key1, kp2, ECC_KEY_BASE_COUNT * ECC_KEY_BYTES);
		delete[] kp2;
		delete[] buffer;
	}
	keyfile.close();
	return RESULT_SUCCESS;
}

int KeyStore::delete_key(KEY_TYPE type, uint32_t token) {

	char path[255];
	if (!is_store_open)
		return 0;
	sprintf(path, "%s/%d_%08x.key", store_dir, type, token);
	return unlink(path);
}

uint8_t *KeyStore::key_encrypt(const uint8_t *in, int in_len, uint32_t *token) {
	if (in_len != ECC_KEY_BYTES && in_len != CIPHER_KEY_BYTES
			&& in_len != ECC_KEY_BASE_COUNT * ECC_KEY_BYTES)
		return NULL;
	int key_len;
	uint8_t *key = new uint8_t[256];
	if ((key_len = get_machine_code(key, 256)) <= 0) {
		delete[] key;
		return NULL;
	}

	uint8_t *iv = new uint8_t[CIPHER_KEY_BYTES];
	uint8_t *out = new uint8_t[in_len + 1];

	Alg_Hash_SHA256 sha;

	uint8_t *hash_value = new uint8_t[sha.get_hash_out_size() + 1];
	sha.hash(in, in_len , hash_value);
	*token = get_token(hash_value);


	if (in_len == ECC_KEY_BYTES)
		for (int i = 0; i < CIPHER_KEY_BYTES; i++)
			iv[i] = i << 1;

	if (in_len == CIPHER_KEY_BYTES)
		for (int i = 0; i < CIPHER_KEY_BYTES; i++)
			iv[i] = i;

	if (in_len == ECC_KEY_BASE_COUNT * ECC_KEY_BYTES)
		for (int i = 0; i < CIPHER_KEY_BYTES; i++)
			iv[i] = 0xaa;

	sha.hash(key,key_len,hash_value);
	for(int i = 0;i< CIPHER_KEY_BYTES;i++)
		hash_value[i] ^= hash_value[i + CIPHER_KEY_BYTES];

	Alg_Cigher_AES128 aes;
	if (aes.encrypt(hash_value, iv, in, in_len, out) != in_len) {
		delete[] key;
		delete[] iv;
		delete[] hash_value;
		return NULL;
	}
	delete[] hash_value;
	delete[] key;
	delete[] iv;
	return out;
}

uint8_t *KeyStore::key_decrypt(const uint8_t *in, int in_len, uint32_t token) {

	if (in_len != ECC_KEY_BYTES && in_len != CIPHER_KEY_BYTES
			&& in_len != ECC_KEY_BASE_COUNT * ECC_KEY_BYTES)
		return NULL;
	int key_len;
	uint8_t *key = new uint8_t[256];
	if ((key_len = get_machine_code(key, 256)) <= 0) {
		delete[] key;
		return NULL;
	}
	uint8_t *iv = new uint8_t[CIPHER_KEY_BYTES];
	uint8_t *out = new uint8_t[in_len + 1];

	if (in_len == ECC_KEY_BYTES)
		for (int i = 0; i < CIPHER_KEY_BYTES; i++)
			iv[i] = i << 1;

	if (in_len == CIPHER_KEY_BYTES)
		for (int i = 0; i < CIPHER_KEY_BYTES; i++)
			iv[i] = i;

	if (in_len == ECC_KEY_BASE_COUNT * ECC_KEY_BYTES)
		for (int i = 0; i < CIPHER_KEY_BYTES; i++)
			iv[i] = 0xaa;

	Alg_Cigher_AES128 aes;
	Alg_Hash_SHA256 sha;
	uint8_t *hash_value = new uint8_t[sha.get_hash_out_size() + 1];
	sha.hash(key, key_len, hash_value);
	for(int i = 0;i< CIPHER_KEY_BYTES;i++)
		hash_value[i] ^= hash_value[i + CIPHER_KEY_BYTES];

	if (aes.decrypt(hash_value, iv, in, in_len, out) != in_len) {
		delete []key;
		delete []iv;
		delete []out;
		delete []hash_value;
		return NULL;
	}
	delete []key;
	delete []iv;

	sha.hash(out, in_len, hash_value);
	uint32_t _token = get_token(hash_value);
	delete[] hash_value;
	if (_token != token) {
		delete[] out;
		return NULL;
	}
	return out;
}
