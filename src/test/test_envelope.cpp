/*
 * test_envelope.cpp
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
using namespace std;
void test_envelope() {
	uint32_t tokenA1, tokenA2;
	uint32_t tokenB1, tokenB2;
	uint8_t kka[64], kax[64], kay[64];
	uint8_t kkb[64], kbx[64], kby[64];
	uint8_t r[64], s[64];
	uint8_t ch[32];
	uint8_t *out;
	uint8_t *out2;
	int len;
	int ret;

	cout << "--------------------------Test Digital Envelope--------------------------"	<< endl;
	IKey_Manager *kma = new IKey_Manager(X962_SECG);
	kma->generate_key_pair(&tokenA1, &tokenA2);
	delete kma;
	IKey_Manager *kmb = new IKey_Manager(X962_SECG);
	kmb->generate_key_pair(&tokenB1, &tokenB2);
	delete kmb;

	printf("Alice private key token : %08x\n", tokenA1);
	printf("Alice public key token : %08x\n", tokenA2);
	printf("Bob private key token : %08x\n", tokenB1);
	printf("Bob public key token : %08x\n", tokenB2);

	KeyStore ks;
	if (ks.open_store() != RESULT_SUCCESS) {
		cout << "Key Store open Error!" << endl;
		return;
	}
	ret = ks.get_key(kka, NULL, PRIVATE_KEY, tokenA1);
	printf("Alice get private key return %d\n", ret);
	ret = ks.get_key(kax, kay, PUBLIC_KEY, tokenA2);
	printf("Alice get public key return %d\n", ret);

	ret = ks.get_key(kkb, NULL, PRIVATE_KEY, tokenB1);
	printf("Bob get private key return %d\n", ret);
	ret = ks.get_key(kbx, kby, PUBLIC_KEY, tokenB2);
	printf("Bob get public key return %d\n", ret);
	char content[] =
			"Epacris impressa, also known as common heath, is a plant of the heath family,Ericaceae, that is native to southeast Australia: the states of Victoria, Tasmania, South Australia and New South Wales.";
	len = strlen(content);
	printf("Alice send message size %d\n", len);
	cout << content << endl;
	out = new uint8_t[len + 64];
	out2 = new uint8_t[len + 1];
	Alg_Digital_Envelope envelope(X962_SECG);
	ret = envelope.seal_digital_envelope_ex((uint8_t *) content, len, kka, kbx,
			kby, ch, r, s, out);
	printf("Alice seal envelope size %d\n", ret);
	ret = envelope.tear_digital_envelope_ex(out, ret, kkb, kax, kay, ch, r, s,
			out2);
	printf("Bob get message size %d\n", ret);
	out2[ret] = 0;
	cout << out2 << endl;
//cleanup
	ks.delete_key(PRIVATE_KEY, tokenA1);
	ks.delete_key(PUBLIC_KEY, tokenA2);
	ks.delete_key(PRIVATE_KEY, tokenB1);
	ks.delete_key(PUBLIC_KEY, tokenB2);
}




