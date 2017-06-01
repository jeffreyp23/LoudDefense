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
	TS7BlocksOfType buffertje;
	//char buffer[200];
	if (List == nullptr){
		return nullptr;
	}

	std::stringstream ss;

	if (List->OBCount > 0)
	{
		std::cout << "OBcount = " << List->OBCount << endl;
		ss << this->processBlocks(Block_OB, List->OBCount);	

		int res = client->ListBlocksOfType(Block_OB, &buffertje, List->FBCount);
		if (res == 0)
		{
			std::cout << "blocks of type gekregen" << std::endl;
			for (int i = 0; i < List->FBCount; i++)
			{
				printf("FB nummer: %d.\n", buffertje[i]);
			}
		}
		else
			std::cout << "Geen Blocks of type gekregen !!!!" << std::endl;
		//st1d::cout << blocks << std::endl;
	}

	if (List->FBCount > 0)
	{
		//std::cout << "FBcount = " << List->FBCount << endl;
		ss << this->processBlocks(Block_FB, List->FBCount);
	}

	if (List->FCCount > 0)
	{
		//std::cout << "FCcount = " << List->FCCount << endl;
		ss << this->processBlocks(Block_FC, List->FCCount);
	}

	if (List->SFBCount > 0)
	{
		//std::cout << "SFBcount = " << List->SFBCount << endl;
		ss << this->processBlocks(Block_SFC, List->SFBCount);
	}
	if (List->SFCCount > 0)
	{
		//std::cout << "SFCcount = " << List->SFCCount << endl;
		ss << this->processBlocks(Block_SFC, List->SFCCount);
	}

	delete List;
	return ss.str();
}

TS7BlocksList* PLC::getBlockList()
{
	TS7BlocksList* List = new TS7BlocksList;
	int res = client->ListBlocks(List);

	if (res == 0) {
		return List;
	}
	else {
		delete List;
		return nullptr;
	}
}

std::string PLC::processBlocks(byte Block_Type, int count)
{
	byte Buffer[65536]; // 64 K buffer
	int Size = sizeof(Buffer); // Size is IN/OUT par
							   // In input it tells the client the size available
							   // In output it tells us how many bytes were uploaded.
	std::stringstream ss;
	for (int i = 0; i < count; i++)
	{
		int res = client->Upload(Block_Type, i, &Buffer, Size);
		if (res == 0)
		{
			//std::cout << (char*)(Buffer) << endl;
			ss << (char*)(Buffer);
		}
		//else
			//std::cout << "ERROR" << std::endl;
	}

	return ss.str();
}

PLC::~PLC()
{
	client->Disconnect();
	delete client;
}
