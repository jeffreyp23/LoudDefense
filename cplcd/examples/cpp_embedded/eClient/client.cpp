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

	if (argc < 2)
	{
		printf("gebruik --init/--hash\n");
		exit(1);
	}

	if (strcmp(argv[1], "--init") == 0)
	{
		nieuw = 1;
		printf("eerste Scan...\n");
	}
	else if (strcmp(argv[1], "--hash") == 0)
	{
		oud = 1;
		printf("test scan...\n");
	}


	if (nieuw)
	{
		ofstream file;
		file.open("InitialHash.txt");

		//std::cout << "Connecting to PLC...\n";
		PLC plc("192.168.0.150"); // verbind met PLC

		//std::cout << "Connected to PLC\nGetting code..\n";

		std::string plc_code = plc.getCode(); // verkrijg de code
		//std::cout << "PLC hash: " << CryptoProvider::sha256(plc_code) << std::endl;
		file << CryptoProvider::sha256(plc_code) << endl; // stop hash in de file


		file.close();
		plc.Disconnect();
	}
	else if (oud)
	{
		while (true)
		{
			ifstream infile;
			std::string  data;
			infile.open("InitialHash.txt");
			PLC plc("192.168.0.150"); // verbind met de PLC


			std::string plc_code = plc.getCode(); // vergrijg de code
			infile >> data; // lees hash uit file.
			if (data.compare(CryptoProvider::sha256(plc_code)) == 0) // vergelijk de data
			{
				std::cout << "Er is een match" << endl;
				system("python signal_bro.py 192.168.0.138 1"); // roep python script aan voor het versturen van een 1 naar de server
			}
			else {
				std::cout << "Er is geen match" << endl;
				system("python signal_bro.py 192.168.0.138 0"); //roep python script aan voor het versturen van een 0 naar de server
			}

			infile.close();
			plc.Disconnect();

			int seconds = 60; // 60 seconden voor 1 minuut
			Sleep(seconds * 1000); // slaap voor 1 minuut. 
		}
		
	}
	
	return 0;
}

