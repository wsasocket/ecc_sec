%module bravosec
%include <pybuffer.i>

%{
#include "interface.hpp"
%}


%pybuffer_string(const char *token);
%pybuffer_string(const char *public_key_x);
%pybuffer_string(const char *public_key_y);
%pybuffer_string(const char *extend1);
%pybuffer_string(const char *extend2);
%pybuffer_string(const char *extend3);
%pybuffer_mutable_string(char *base64_out);
int build_csr_hash(const char *token, const char *public_key_x,
		const char *public_key_y, const char *extend1, const char *extend2,
		const char *extend3, char *base64_out);

%pybuffer_string(const char *token);
%pybuffer_string(const char *public_key_x);
%pybuffer_string(const char *public_key_y);
%pybuffer_string(const char *SN);
%pybuffer_string(const char *expire);
%pybuffer_string(const char *extend1);
%pybuffer_string(const char *extend2);
%pybuffer_string(const char *extend3);
%pybuffer_mutable_string(char *base64_out);
int build_crt_hash(const char *token, const char *public_key_x,
		const char *public_key_y, const char *SN, const char *expire,
		const char *extend1, const char *extend2, const char *extend3,
		char *base64_out);

%pybuffer_string(const char *hash_value);
%pybuffer_string(const char *public_key_x);
%pybuffer_string(const char *public_key_y);
%pybuffer_string(const char *sign_r);
%pybuffer_string(const char *sign_s);
int verify_csr(const char *hash_value, const char *public_key_x, const char *public_key_y,
		const char *sign_r, const char *sign_s);

%pybuffer_string(const char *hash_value);
%pybuffer_mutable_string(char *sign_r);
%pybuffer_mutable_string(char *sign_s);
int sign_crt(const char *hash_value, char *sign_r, char *sign_s);

%pybuffer_string(const char *hash_value);
%pybuffer_string(const char *sign_r);
%pybuffer_string(const char *sign_s);
int verify_crt(const char *hash_value, const char *sign_r, const char *sign_s);

%pybuffer_string(const char *hash_value);
%pybuffer_mutable_string(char *sign_r);
%pybuffer_mutable_string(char *sign_s);
int sign_csr(const char *hash_value, char *sign_r, char *sign_s);

%pybuffer_string(const char *msg);
%pybuffer_string(const char *peer_public_x);
%pybuffer_string(const char *peer_public_y);
%pybuffer_mutable_string(char *cipher_hash);
%pybuffer_mutable_string(char *sign_r);
%pybuffer_mutable_string(char *sign_s);
%pybuffer_mutable_string(char *env);
int seal_digital_envelope(const char *msg, const char *peer_public_x,
		const char *peer_public_y, char *cipher_hash, char *sign_r,
		char *sign_s, char *env);

%pybuffer_string(const char *msg);
%pybuffer_string(const char *peer_public_x);
%pybuffer_string(const char *peer_public_y);
%pybuffer_string(const char *cipher_hash);
%pybuffer_string(const char *sign_r);
%pybuffer_string(const char *sign_s);
%pybuffer_mutable_string(char *msg_out);
int tear_digital_envelope_ex(const char *msg, const char *peer_public_x,
		const char *peer_public_y, const char *cipher_hash, const char *sign_r,
		const char *sign_s, char *msg_out);
		