/*
 * main.cpp
 *
 *  Created on: 2016年5月14日
 *      Author: james
 */
#include "../core/core_define.hpp"
#include <iostream>
using namespace std;

void test_keystore(bool init);
void test_envelope();
void init_key(bool is_ca);

int main(int argc ,char *argv[])
{

	if(argc == 1)
	{
		cout << " Test and Initialize tools usage:" << endl;
		cout << argv[0] << " T" << " test function."<< endl;
		cout << argv[0] << " U" << " initialize user/device keys."<< endl;
		cout << argv[0] << " C" << " initialize CA keys."<< endl;
		cout << "NOTE : If you CA is running ,<<<DO NOT>>> Initialize again !!!"<< endl;
		return RESULT_SUCCESS;
	}
	if(argc == 2)
	{
		if(argv[1][0] == 'T')
		{
			test_keystore(false);
			test_envelope();
			return RESULT_SUCCESS;
		}
		if(argv[1][0] == 'U')
		{
			init_key(false);
		}
		if(argv[1][0] == 'C')
		{
			init_key(true);
		}
	}
	return RESULT_SUCCESS;
}


