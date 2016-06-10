/*
 * test_keystore.cpp
 *
 *  Created on: 2016年5月14日
 *      Author: james
 */
#include "../core/keystore.hpp"
#include "../core/core_define.hpp"
#include "../core/core.hpp"
#include "../kernal/alg_hash_SHA256.hpp"
#include "../kernal/alg_digital_envelope.hpp"
#include "../kernal/configure.hpp"
#include <iostream>
#include <string.h>
using namespace std;

void test_keystore(bool init) {
	uint32_t token1, token2, token3, token4;
	uint8_t kk[64], kx[64], ky[64];
	uint8_t *kb, *kbx, *kby;
	int ret;
	IKey_Base_Manager *kbm = new IKey_Base_Manager(SHA_256, X962_SECG);
	IKey_Manager *km = new IKey_Manager(X962_SECG);
	Configure * conf;
	KeyStore ks;
	cout
			<< "--------------------------Test Key Store ---------------------------"
			<< endl;
	if (ks.open_store() != RESULT_SUCCESS) {
		cout << "Key Store open Error!" << endl;
		return;
	}
	if (init)
		km->generate_key_pair(&token3, &token4);
	else {
		conf = Configure::GetConfigure();
		token3 = conf->get_private_token();
		token4 = conf->get_public_token();
		km->load_private_key(token3);
		km->load_public_key(token4);
	}
	delete km;
	cout
			<< "-----------------Test Key Store with key manager generator--------------------"
			<< endl;
	printf("private key token : %08x    %ld\n", token3, token3);
	printf("public key token : %08x    %ld\n", token4, token4);

	ret = ks.get_key(kk, NULL, PRIVATE_KEY, token3);
	printf("get private key return %d\n", ret);
	ret = ks.get_key(kx, ky, PUBLIC_KEY, token4);
	printf("get public key return %d\n", ret);
	ks.close_store();

	cout
			<< "--------------Test Key Store with key base manager generator-----------------"
			<< endl;
	if (ks.open_store() != RESULT_SUCCESS) {
		cout << "Key Store open Error!" << endl;
		return;
	}
	if (init)
		kbm->generate_key_pair_base(&token1, &token2);
	else {
		conf = Configure::GetConfigure();
		token1 = conf->get_private_base_token();
		token2 = conf->get_public_base_token();
		kbm->load_private_key_base(token1);
		kbm->load_public_key_base(token2);
	}
	delete kbm;
	printf("private key base token : %08x    %ld\n", token1, token1);
	printf("public key base token : %08x    %ld\n", token2, token2);

	kb = new uint8_t[ECC_KEY_BASE_COUNT * ECC_KEY_BYTES];
	kbx = new uint8_t[ECC_KEY_BASE_COUNT * ECC_KEY_BYTES];
	kby = new uint8_t[ECC_KEY_BASE_COUNT * ECC_KEY_BYTES];
	ret = ks.get_key_base(kb, NULL, token1);
	printf("get private key base return %d\n", ret);
	ret = ks.get_key_base(kbx, kby, token2);
	printf("get public key base return %d\n", ret);
	delete[] kb;
	delete[] kbx;
	delete[] kby;

	cout
			<< "--------------Test Key Store with key base manager load-----------------"
			<< endl;
	char t[] = "helloworld";
	uint8_t h[32];
	uint8_t pr[32];
	uint8_t r[32], s[32];
	uint8_t pux[32], puy[32];
	kbm = new IKey_Base_Manager(SHA_256, X962_SECG);
	ret = kbm->load_private_key_base(token1);
	printf("get private key base return %d\n", ret);
	ret = kbm->load_public_key_base(token2);
	printf("get public key base return %d\n", ret);

	Alg_Hash_SHA256 sha;
	sha.hash((uint8_t *) t, strlen(t), h);
	ret = kbm->get_mixed_private_key(h, pr);
	printf("get private mixed key return %d\n", ret);
	ret = kbm->get_mixed_public_key(h, pux, puy);
	printf("get public mixed key return %d\n", ret);

	IAlg_Ecc ecc(X962_SECG);
	ecc.ecc_sign(h, 32, pr, r, s);
	ret = ecc.ecc_verify(h, 32, pux, puy, r, s);
	if (ret == VERIFY_SUCCESS)
		cout << "VERIFY_SUCCESS" << endl;
	else
		cout << "VERIFY_ERROR" << endl;
	delete kbm;

	cout
			<< "--------------Test Key Store with key manager load-----------------"
			<< endl;
	km = new IKey_Manager(X962_SECG);
	ret = km->load_private_key(token3);
	printf("get private key return %d\n", ret);
	ret = km->load_public_key(token4);
	printf("get public key  return %d\n", ret);

	sha.hash((uint8_t *) t, strlen(t), h);
	ecc.ecc_sign(h, 32, km->get_private_key(), r, s);
	ret = ecc.ecc_verify(h, 32, km->get_public_key_x(), km->get_public_key_y(),
			r, s);
	if (ret == VERIFY_SUCCESS)
		cout << "VERIFY_SUCCESS" << endl;
	else
		cout << "VERIFY_ERROR" << endl;
	delete km;
	if (init) {
		ks.delete_key(PRIVATE_KEY_BASE, token1);
		ks.delete_key(PUBLIC_KEY_BASE, token2);
		ks.delete_key(PRIVATE_KEY, token3);
		ks.delete_key(PUBLIC_KEY, token4);
	}
}

