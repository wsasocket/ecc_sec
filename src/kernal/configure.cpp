/*
 * configure.cpp
 *
 *  Created on: 2016年5月20日
 *      Author: james
 */

#include "configure.hpp"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <string.h>
#include "../core/core_define.hpp"

using namespace std;

Configure *Configure::m_pConf = NULL;

Configure::Configure() {
	keystore_path = NULL;
	self_private_token = 0;
	self_public_token = 0;
	public_base_token = 0;
	private_base_token = 0;
}

Configure::~Configure() {
	if(keystore_path)
		delete []keystore_path;
}

int Configure::setup_conf()
{
	char curdir[255];
	int  type;
	uint32_t token;
	if(getcwd(curdir,255) == NULL)
		return CONF_FILE_NOT_FOUND;

	strcat(curdir,"/sec.conf");
	ifstream conf;
	conf.open(curdir);
	if(!conf.is_open())
		return CONF_FILE_NOT_FOUND;
	//TODO parse conf file and setup value
	// this is only a demo
	while(true)
	{
		bzero(curdir,255);
		conf >> curdir;
		if(conf.eof())
			break;

		if(curdir[0] == 'p')
		{
			int len = strlen(&curdir[2]);
			keystore_path = new char[len + 2];
			strcpy(keystore_path,&curdir[2]);
			len = strlen(keystore_path);
			if(keystore_path[len] != '/')
			{
				keystore_path[len] = '/';
				keystore_path[len + 1] = 0;
			}
			continue;
		}
		sscanf(curdir,"%d:%08x;",&type,&token);
		switch(type)
		{
		case PRIVATE_KEY:
			this->self_private_token = token;
			break;
		case PRIVATE_KEY_BASE:
			this->private_base_token = token;
			break;
		case PUBLIC_KEY:
			this->self_public_token = token;
			break;
		case PUBLIC_KEY_BASE:
			this->public_base_token = token;
			break;
		default:
			break;
		}
	}
	conf.close();
	return RESULT_SUCCESS;
}

Configure *Configure::GetConfigure()
{
	if(m_pConf == NULL){
		m_pConf = new Configure();
		m_pConf->setup_conf();
	}
	return m_pConf;
}

uint32_t Configure::get_private_token()
{
	return self_private_token;
}

uint32_t Configure::get_public_token()
{
	return self_public_token;
}

uint32_t Configure::get_private_base_token()
{
	return private_base_token;
}

uint32_t Configure::get_public_base_token()
{
	return public_base_token;
}

const char *Configure::get_keystore_path()
{
	return keystore_path;
}
