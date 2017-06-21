#include "PLC.h"
#include <vector>
#include <sstream>

PLC::PLC(std::string ipAddress)
{
	client = new TSnap7Client;
	int res = client->ConnectTo(ipAddress.c_str(), 0, 2);
	if (res != 0)
	{
		throw "geen verbinding";
	}
}

std::string PLC::getCode()
{
	TS7BlocksList *List;
	List = getBlockList();
	
	if (List == nullptr){
		return nullptr;
	}

	std::stringstream ss;

	if (List->OBCount > 0 ) // alleen OB blokken uitlezen om crash kans te verminderen.
	{
		std::cout << "OBcount = " << List->OBCount << endl;
		ss << this->processBlocks(Block_OB, List->OBCount); // stop block data in een stringstream			
	}

	//////////////////////////////////////////////////////////////
	/*Tijdelijk gecomentariseerd zolang uitleesprobleem bestaat	*/
	//////////////////////////////////////////////////////////////

	/*if (List->FBCount > 0)
	{
		std::cout << "FBcount = " << List->FBCount << endl;
		ss << this->processBlocks(Block_FB, List->FBCount);
	}

	if (List->FCCount > 0)
	{
		std::cout << "FCcount = " << List->FCCount << endl;
		ss << this->processBlocks(Block_FC, List->FCCount);
	}

	if (List->SFBCount > 0)
	{
		std::cout << "SFBcount = " << List->SFBCount << endl;
		ss << this->processBlocks(Block_SFC, List->SFBCount);
	}
	if (List->SFCCount > 0)
	{
		std::cout << "SFCcount = " << List->SFCCount << endl;
		ss << this->processBlocks(Block_SFC, List->SFCCount);
	}*/

	delete List;
	return ss.str();
}

TS7BlocksList* PLC::getBlockList()
{
	TS7BlocksList* List = new TS7BlocksList; // maak een lijst object
	int res = client->ListBlocks(List); // lees alle blokken uit de PLC

	if (res == 0) {
		return List; // return alle blokken als het is gelukt
	}
	else {
		delete List;
		return nullptr; // return 0 pointer als het niet is gelukt
	}
}

std::string PLC::processBlocks(byte Block_Type, int count)
{
	TS7BlocksOfType buffertje; //definier Block of type buffer.
	byte Buffer[65536]; // 64 K buffer
							
	std::stringstream ss;
	std::cout << "coutn = " << count << std::endl;

	//verkrijg alle block nummers van type block
	int res = client->ListBlocksOfType((int)Block_Type, &buffertje, count);

	if (res == 0)
	{
		std::cout << "blocks of type gekregen" << std::endl;
		for (int i = 0; i < count; i++)
		{
			int Size = sizeof(Buffer);
			int res = client->Upload((int)Block_Type, buffertje[i], &Buffer, Size); // lees alle blokken uit
			if (res == 0)
			{
				printf("Block nummer: %d.\n", buffertje[i]);
				ss << (char*)(Buffer);
			}
			else
				printf("Could not read Block Number: %d\n", buffertje[i]);
			SysSleep(50);
		}
	}
	printf("\n\n");
	return ss.str();
}

void PLC::Disconnect()
{
	client->Disconnect();
}
PLC::~PLC()
{
	client->Disconnect();
	delete client;
}
