#if defined(_WIN32)
#define _EMBEDDING_VS2013UP
#endif

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string>
#include "s7_client.h"
#include "s7_text.h"


#ifdef OS_WINDOWS
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#endif



class PLC
{
public:
	PLC(std::string ipAddress);
	std::string getCode();
	~PLC();


private:
	TS7BlocksList* getBlockList();
	std::string processBlocks(byte Block_Type, int count);

	TSnap7Client *client;
	
	
};

