/*=============================================================================|
|  PROJECT SNAP7                                                         1.4.1 |
|==============================================================================|
|  Copyright (C) 2013, 2014, 2015, 2016 Davide Nardella                        |
|  All rights reserved.                                                        |
|==============================================================================|
|  SNAP7 is free software: you can redistribute it and/or modify               |
|  it under the terms of the Lesser GNU General Public License as published by |
|  the Free Software Foundation, either version 3 of the License, or           |
|  (at your option) any later version.                                         |
|                                                                              |
|  It means that you can distribute your commercial software linked with       |
|  SNAP7 without the requirement to distribute the source code of your         |
|  application and without the requirement that your application be itself     |
|  distributed under LGPL.                                                     |
|                                                                              |
|  SNAP7 is distributed in the hope that it will be useful,                    |
|  but WITHOUT ANY WARRANTY; without even the implied warranty of              |
|  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the               |
|  Lesser GNU General Public License for more details.                         |
|                                                                              |
|  You should have received a copy of the GNU General Public License and a     |
|  copy of Lesser GNU General Public License along with Snap7.                 |
|  If not, see  http://www.gnu.org/licenses/                                   |
|==============================================================================|
|                                                                              |
|  Embedded Client Example                                                     |
|                                                                              |
|=============================================================================*/
// Next line is a workaround to prevent to define _USE_32BIT_TIME_T in
// snap_platform.h which is a bug of VS2012 and below.
// It's necessary only compiling Win32 for VisualStudio2013 UP
// Win64 or other compiler (such C++Builder) don't need of it

#include <fstream>
#include <iostream>

#include "PLC.h"
#include "CryptoProvider.h"

int main(int argc, char* argv[])
{
	
	int nieuw = 0, oud = 0;
	//printf("1");
	if (argc < 2)
	{
		printf("gebruik --nieuw/--oud\n");
		exit(1);
	}

	if (strcmp(argv[1], "--nieuw") == 0)
	{
		nieuw = 1;
		printf("eerste Scan...\n");
	}
	else if (strcmp(argv[1], "--oud") == 0)
	{
		oud = 1;
		printf("test scan...\n");
	}

	if (nieuw)
	{
		ofstream file;
		file.open("hash.txt", ios::out | ios::app);

		std::cout << "Connecting to PLC...\n";
		PLC plc("192.168.0.150");

		std::cout << "Connected to PLC\nGetting code..\n";

		std::string plc_code = plc.getCode();
		//std::cout << "PLC hash: " << CryptoProvider::sha256(plc_code) << std::endl;
		file << CryptoProvider::sha256(plc_code) << endl;


		file.close();
	}
	else if (oud)
	{
		ifstream infile;
		std::string  data;
		infile.open("hash.txt");
		std::cout << "Connecting to PLC...\n";
		PLC plc("192.168.0.150");

		std::cout << "Connected to PLC\nGetting code..\n";

		std::string plc_code = plc.getCode();
		//std::cout << "PLC hash: " << CryptoProvider::sha256(plc_code) << std::endl;
		infile >> data;
		if (data.compare( CryptoProvider::sha256(plc_code)) == 0)
		{
			std::cout << "Er is een match" << endl;
		}
		else
			std::cout << "Er is geen match" << endl;

		std::cout << CryptoProvider::sha256(plc_code) << std::endl;

		infile.close();
	}
	//sleep();
	return 0;
}

