/*
 * This file is part of BravoSystem.
 * Copyright(c) 2015 by bravovcloud.com
 * All rights reserved.
 *
 * Author
 *      - zouyeming <zouyeming@bravovcloud.com>
 * Create on 2016年5月4日
 */
#ifndef SRC_KERNAL_ALG_DIGITAL_ENVELOPE_HPP_
#define SRC_KERNAL_ALG_DIGITAL_ENVELOPE_HPP_
/*
 *
 */
class Alg_Digital_Envelope
{
public:
    Alg_Digital_Envelope(CURVE_GROUP_ID oid);
    virtual ~Alg_Digital_Envelope();

public:
    int seal_digital_envelope_ex(const uint8_t *msg, size_t msg_len,
    		const uint8_t *self_private,
    		const uint8_t *peer_public_x, const uint8_t *peer_public_y,
            uint8_t *cipher_hash,
			uint8_t *sign_r, uint8_t *sign_s,
			uint8_t *envelope);
    int tear_digital_envelope_ex(const uint8_t *env, size_t env_len, //envelope and envelope length
			const uint8_t *self_private,// self private key to tear the envelope
			const uint8_t *peer_public_x, const uint8_t *peer_public_y,// sender public key to verify the envelope
            const uint8_t *cipher_hash, // envelope hash to detect the data is correct
			const uint8_t *sign_r, const uint8_t *sign_s, // sender sign the envelope r and s to verify the envelope
			uint8_t *msg_out); // origin message
private:
    CURVE_GROUP_ID oid;
};

#endif /* SRC_KERNAL_ALG_DIGITAL_ENVELOPE_HPP_ */
