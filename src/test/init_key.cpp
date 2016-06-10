/*
 * init_key.cpp
 *
 *  Created on: 2016年5月20日
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
#include <stdio.h>
using namespace std;

void init_key(bool is_ca) {
	uint32_t token1, token2, token3, token4, token5;
	IKey_Base_Manager *kbm = new IKey_Base_Manager(SHA_256, X962_SECG);
	IKey_Manager *km = new IKey_Manager(X962_SECG);

	cout << "<----- Begin initialize keys ----->" << endl;
	cout << "[O] Open key store." << endl;
	token1 = token2 = 0;
	km->generate_key_pair(&token1, &token2);
	if (token1 != 0 && token2 != 0)
		cout << "[O] Generate Elliptic Curve(ECC) Key pair SUCCESS." << endl;
	else
		cout << "[O] Generate Elliptic Curve(ECC) Key pair FAIL." << endl;

	token5 = 0;
	km->generate_cipher_key(&token5);
	if (token5 != 0)
		cout << "[O] Generate Cipher Key SUCCESS." << endl;
	else
		cout << "[x] Generate Cipher Key FAIL." << endl;
	delete km;

	if (is_ca) {
		token3 = token4 = 0;
		kbm->generate_key_pair_base(&token3, &token4);
		if (token1 != 0 && token2 != 0)
			cout << "[O] Generate Elliptic Curve(ECC) Key pair base SUCCESS."
					<< endl;
		else
			cout << "[x] Generate Elliptic Curve(ECC) Key pair base FAIL."
					<< endl;
		delete kbm;
	}
	cout << "<----- Final Result ----->" << endl;
	printf("%c:%s\n", 'p',"/etc/sec/");
	printf("%d:%08x\n", PRIVATE_KEY, token1);
	printf("%d:%08x\n", PUBLIC_KEY, token2);
	printf("%d:%08x\n", CIPHER_KEY, token5);
	if (is_ca) {
		printf("%d:%08x\n", PRIVATE_KEY_BASE, token3);
		printf("%d:%08x\n", PUBLIC_KEY_BASE, token4);
	}
	cout << "<----- copy above info in you conf file ----->" << endl;
}

