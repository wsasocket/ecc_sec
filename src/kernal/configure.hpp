/*
 * configure.hpp
 *
 *  Created on: 2016年5月20日
 *      Author: james
 */

#ifndef SRC_KERNAL_CONFIGURE_HPP_
#define SRC_KERNAL_CONFIGURE_HPP_
#include <stdint.h>
class Configure {
public:
	Configure();
	virtual ~Configure();

public:
	static Configure *GetConfigure();
	uint32_t get_private_token();
	uint32_t get_public_token();
	uint32_t get_private_base_token();
	uint32_t get_public_base_token();
	const char *get_keystore_path();
	virtual int setup_conf();

private:
	char * keystore_path;
	uint32_t self_private_token;
	uint32_t self_public_token;
	uint32_t public_base_token;
	uint32_t private_base_token;
	static Configure *m_pConf;
};

#endif /* SRC_KERNAL_CONFIGURE_HPP_ */
