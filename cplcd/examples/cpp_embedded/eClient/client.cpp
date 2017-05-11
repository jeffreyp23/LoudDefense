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
#if defined(_WIN32)
   #define _EMBEDDING_VS2013UP
#endif

#include <stdio.h>
#include <stdlib.h>
#include "s7_client.h"
#include "s7_text.h"

#ifdef OS_WINDOWS
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
#endif
TSnap7Client *Client;

byte Buffer[65536]; // 64 K buffer
int SampleDBNum = 1000;

char *Address;     // PLC IP Address
int Rack = 0, Slot = 2; // Default Rack and Slot

int ok = 0; // Number of test pass
int ko = 0; // Number of test failure

bool JobDone = false;
int JobResult = 0;

//------------------------------------------------------------------------------
//  Async completion callback 
//------------------------------------------------------------------------------
// This is a simply text demo, we use callback only to set an internal flag...
void S7API CliCompletion(void *usrPtr, int opCode, int opResult)
{
	JobResult = opResult;
	JobDone = true;
}
//------------------------------------------------------------------------------
//  Usage Syntax
//------------------------------------------------------------------------------
void Usage()
{
	printf("Usage\n");
	printf("  client <IP> [-param]\n");
	printf("Example\n");
	printf("  client 192.168.1.101 --start\n");
	printf("or\n");
	printf("  client 192.168.1.101 --stop\n");
	printf("or\n");
	printf("  client 192.168.1.101 --test\n");
	getchar();
}
//------------------------------------------------------------------------------
// hexdump, a very nice function, it's not mine.
// I found it on the net somewhere some time ago... thanks to the author ;-)
//------------------------------------------------------------------------------
#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif
void hexdump(void *mem, unsigned int len)
{
	unsigned int i, j;

	for (i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
	{
		/* print offset */
		if (i % HEXDUMP_COLS == 0)
		{
			printf("0x%04x: ", i);
		}

		/* print hex data */
		if (i < len)
		{
			printf("%02x ", 0xFF & ((char*)mem)[i]);
		}
		else /* end of block, just aligning for ASCII dump */
		{
			printf("   ");
		}

		/* print ASCII dump */
		if (i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
		{
			for (j = i - (HEXDUMP_COLS - 1); j <= i; j++)
			{
				if (j >= len) /* end of block, not really printing */
				{
					putchar(' ');
				}
				else if (isprint((((char*)mem)[j] & 0x7F))) /* printable char */
				{
					putchar(0xFF & ((char*)mem)[j]);
				}
				else /* other char */
				{
					putchar('.');
				}
			}
			putchar('\n');
		}
	}
}
//------------------------------------------------------------------------------
// Check error
//------------------------------------------------------------------------------
bool Check(int Result, const char * function)
{
	printf("\n");
	printf("+-----------------------------------------------------\n");
	printf("| %s\n", function);
	printf("+-----------------------------------------------------\n");
	if (Result == 0) {
		printf("| Result         : OK\n");
		printf("| Execution time : %d ms\n", Client->Time());
		printf("+-----------------------------------------------------\n");
		ok++;
	}
	else {
		printf("| ERROR !!! \n");
		if (Result<0)
			printf("| Library Error (-1)\n");
		else
			//printf("| %s\n", ErrCliText(Result).c_str());
		printf("+-----------------------------------------------------\n");
		ko++;
	}
	return Result == 0;
}
//------------------------------------------------------------------------------
// Multi Read
//------------------------------------------------------------------------------
void MultiRead()
{
	// Multiread buffers
	byte MB[16]; // 16 Merker bytes
	byte EB[16]; // 16 Digital Input bytes
	byte AB[16]; // 16 Digital Output bytes
	word TM[8];  // 8 timers
	word CT[8];  // 8 counters

	// Prepare struct
	TS7DataItem Items[5];

	// NOTE : *AMOUNT IS NOT SIZE* , it's the number of items

	// Merkers
	Items[0].Area = S7AreaMK;
	Items[0].WordLen = S7WLByte;
	Items[0].DBNumber = 0;        // Don't need DB
	Items[0].Start = 0;        // Starting from 0
	Items[0].Amount = 16;       // 16 Items (bytes)
	Items[0].pdata = &MB;
	// Digital Input bytes
	Items[1].Area = S7AreaPE;
	Items[1].WordLen = S7WLByte;
	Items[1].DBNumber = 0;        // Don't need DB
	Items[1].Start = 0;        // Starting from 0
	Items[1].Amount = 16;       // 16 Items (bytes)
	Items[1].pdata = &EB;
	// Digital Output bytes
	Items[2].Area = S7AreaPA;
	Items[2].WordLen = S7WLByte;
	Items[2].DBNumber = 0;        // Don't need DB
	Items[2].Start = 0;        // Starting from 0
	Items[2].Amount = 16;       // 16 Items (bytes)
	Items[2].pdata = &AB;
	// Timers
	Items[3].Area = S7AreaTM;
	Items[3].WordLen = S7WLTimer;
	Items[3].DBNumber = 0;        // Don't need DB
	Items[3].Start = 0;        // Starting from 0
	Items[3].Amount = 8;        // 8 Timers
	Items[3].pdata = &TM;
	// Counters
	Items[4].Area = S7AreaCT;
	Items[4].WordLen = S7WLCounter;
	Items[4].DBNumber = 0;        // Don't need DB
	Items[4].Start = 0;        // Starting from 0
	Items[4].Amount = 8;        // 8 Counters
	Items[4].pdata = &CT;

	int res = Client->ReadMultiVars(&Items[0], 5);
	if (Check(res, "Multiread Vars"))
	{
		// Result of Client->ReadMultivars is the "global result" of
		// the function, it's OK if something was exchanged.

		// But we need to check single Var results.
		// Let shall suppose that we ask for 5 vars, 4 of them are ok but
		// the 5th is inexistent, we will have 4 results ok and 1 not ok.

		printf("Dump MB0..MB15 - Var Result : %d\n", Items[0].Result);
		if (Items[0].Result == 0)
			hexdump(&MB, 16);
		printf("Dump EB0..EB15 - Var Result : %d\n", Items[1].Result);
		if (Items[1].Result == 0)
			hexdump(&EB, 16);
		printf("Dump AB0..AB15 - Var Result : %d\n", Items[2].Result);
		if (Items[2].Result == 0)
			hexdump(&AB, 16);
		printf("Dump T0..T7 - Var Result : %d\n", Items[3].Result);
		if (Items[3].Result == 0)
			hexdump(&TM, 16);         // 8 Timers -> 16 bytes
		printf("Dump Z0..Z7 - Var Result : %d\n", Items[4].Result);
		if (Items[4].Result == 0)
			hexdump(&CT, 16);         // 8 Counters -> 16 bytes
	};
}
//------------------------------------------------------------------------------
// List blocks in AG
//------------------------------------------------------------------------------
void ListBlocks()
{
	TS7BlocksList List;
	int res = Client->ListBlocks(&List);
	if (Check(res, "List Blocks in AG"))
	{
		printf("  OBCount  : %d\n", List.OBCount);
		printf("  FBCount  : %d\n", List.FBCount);
		printf("  FCCount  : %d\n", List.FCCount);
		printf("  SFBCount : %d\n", List.SFBCount);
		printf("  SFCCount : %d\n", List.SFCCount);
		printf("  DBCount  : %d\n", List.DBCount);
		printf("  SDBCount : %d\n", List.SDBCount);
	};
}
//------------------------------------------------------------------------------
// CPU Info : catalog
//------------------------------------------------------------------------------
void OrderCode()
{
	TS7OrderCode Info;
	int res = Client->GetOrderCode(&Info);
	if (Check(res, "Catalog"))
	{
		printf("  Order Code : %s\n", Info.Code);
		printf("  Version    : %d.%d.%d\n", Info.V1, Info.V2, Info.V3);
	};
}
//------------------------------------------------------------------------------
// CPU Info : unit info
//------------------------------------------------------------------------------
void CpuInfo()
{
	TS7CpuInfo Info;
	int res = Client->GetCpuInfo(&Info);
	if (Check(res, "Unit Info"))
	{
		printf("  Module Type Name : %s\n", Info.ModuleTypeName);
		printf("  Serial Number    : %s\n", Info.SerialNumber);
		printf("  AS Name          : %s\n", Info.ASName);
		printf("  Module Name      : %s\n", Info.ModuleName);
	};
}
//------------------------------------------------------------------------------
// CP Info
//------------------------------------------------------------------------------
void CpInfo()
{
	TS7CpInfo Info;
	int res = Client->GetCpInfo(&Info);
	if (Check(res, "Communication processor Info"))
	{
		printf("  Max PDU Length   : %d bytes\n", Info.MaxPduLengt);
		printf("  Max Connections  : %d \n", Info.MaxConnections);
		printf("  Max MPI Rate     : %d bps\n", Info.MaxMpiRate);
		printf("  Max Bus Rate     : %d bps\n", Info.MaxBusRate);
	};
}
//------------------------------------------------------------------------------
// PLC Status
//------------------------------------------------------------------------------
void UnitStatus()
{
	int res = 0;
	int Status;
	Client->GetPlcStatus(Status);
	if (Check(res, "CPU Status"))
	{
		switch (Status)
		{
		case S7CpuStatusRun: printf("  RUN\n"); break;
		case S7CpuStatusStop: printf("  STOP\n"); break;
		default: printf("  UNKNOWN\n"); break;
		}
	};
}
//------------------------------------------------------------------------------
// Upload DB0 (surely exists in AG)
//------------------------------------------------------------------------------
void UploadDB0()
{
	int Size = sizeof(Buffer); // Size is IN/OUT par
	// In input it tells the client the size available
	// In output it tells us how many bytes were uploaded.
	int res = Client->Upload(Block_SDB, 0, &Buffer, Size);
	if (Check(res, "Block Upload (SDB 0)"))
	{
		printf("Dump (%d bytes) :\n", Size);
		hexdump(&Buffer, Size);
	}
}
//------------------------------------------------------------------------------
// Async Upload DB0 (using callback as completion trigger)
//------------------------------------------------------------------------------
void AsCBUploadDB0()
{
	int Size = sizeof(Buffer); // Size is IN/OUT par
	// In input it tells the client the size available
	// In output it tells us how many bytes were uploaded.
	JobDone = false;
	int res = Client->AsUpload(Block_SDB, 0, &Buffer, Size);

	if (res == 0)
	{
		while (!JobDone)
		{
			SysSleep(100);
		}
		res = JobResult;
	}

	if (Check(res, "Async (callback) Block Upload (SDB 0)"))
	{
		printf("Dump (%d bytes) :\n", Size);
		hexdump(&Buffer, Size);
	}
}
//------------------------------------------------------------------------------
// Async Upload DB0 (using event wait as completion trigger)
//------------------------------------------------------------------------------
void AsEWUploadDB0()
{
	int Size = sizeof(Buffer); // Size is IN/OUT par
	// In input it tells the client the size available
	// In output it tells us how many bytes were uploaded.
	JobDone = false;
	int res = Client->AsUpload(Block_SDB, 0, &Buffer, Size);

	if (res == 0)
	{
		res = Client->WaitAsCompletion(3000);
	}

	if (Check(res, "Async (Wait event) Block Upload (SDB 0)"))
	{
		printf("Dump (%d bytes) :\n", Size);
		hexdump(&Buffer, Size);
	}
}
//------------------------------------------------------------------------------
// Async Upload DB0 (using polling as completion trigger)
//------------------------------------------------------------------------------
void AsPOUploadDB0()
{
	int Size = sizeof(Buffer); // Size is IN/OUT par
	// In input it tells the client the size available
	// In output it tells us how many bytes were uploaded.
	JobDone = false;
	int res = Client->AsUpload(Block_SDB, 0, &Buffer, Size);

	if (res == 0)
	{
		while (!Client->CheckAsCompletion(res))
		{
			SysSleep(100);
		};
	}

	if (Check(res, "Async (polling) Block Upload (SDB 0)"))
	{
		printf("Dump (%d bytes) :\n", Size);
		hexdump(&Buffer, Size);
	}
}
//------------------------------------------------------------------------------
// Read a SZL block                  
//------------------------------------------------------------------------------
void ReadSzl_0011_0000()
{
	PS7SZL SZL = PS7SZL(&Buffer);  // use our buffer casted as TS7SZL
	int Size = sizeof(Buffer);
	// Block ID 0x0011 IDX 0x0000 normally exists in every CPU
	int res = Client->ReadSZL(0x0011, 0x0000, SZL, Size);
	if (Check(res, "Read SZL - ID : 0x0011, IDX 0x0000"))
	{
		printf("  LENTHDR : %d\n", SZL->Header.LENTHDR);
		printf("  N_DR    : %d\n", SZL->Header.N_DR);
		printf("Dump (%d bytes) :\n", Size);
		hexdump(&Buffer, Size);
	}
}
//------------------------------------------------------------------------------
// Upload DB0 (surely exists in AG)
//------------------------------------------------------------------------------
void Up_DownloadFC1()
{
	int Size = sizeof(Buffer); // Size is IN/OUT par
	// In input it tells the client the size available
	// In output it tells us how many bytes were uploaded.
	int res = Client->FullUpload(Block_FC, 1, &Buffer, Size);
	if (Check(res, "Block Upload (FC1)"))
	{
		printf("Dump (%d bytes) :\n", Size);
		hexdump(&Buffer, Size);

		int res = Client->Download(2, &Buffer, Size);
		Check(res, "Block Download (FC1->FC2)");




	}
}
//------------------------------------------------------------------------------
// Unit Connection
//------------------------------------------------------------------------------
bool CliConnect()
{
	int res = Client->ConnectTo(Address, Rack, Slot);
	if (Check(res, "UNIT Connection")) {
		printf("  Connected to   : %s (Rack=%d, Slot=%d)\n", Address, Rack, Slot);
		printf("  PDU Requested  : %d bytes\n", Client->PDURequest);
		printf("  PDU Negotiated : %d bytes\n", Client->PDULength);
	};
	return res == 0;
}
//------------------------------------------------------------------------------
// Unit Disconnection
//------------------------------------------------------------------------------
void CliDisconnect()
{
	Client->Disconnect();
}
//------------------------------------------------------------------------------
// Perform readonly tests, no cpu status modification
//------------------------------------------------------------------------------
void PerformTests()
{
	OrderCode();
	CpuInfo();
	CpInfo();
	UnitStatus();
	ReadSzl_0011_0000();
	UploadDB0();
	AsCBUploadDB0();
	AsEWUploadDB0();
	AsPOUploadDB0();
	MultiRead();
	//Up_DownloadFC1();
}
//------------------------------------------------------------------------------
// Tests Summary
//------------------------------------------------------------------------------
void Summary()
{
	printf("\n");
	printf("+-----------------------------------------------------\n");
	printf("| Test Summary \n");
	printf("+-----------------------------------------------------\n");
	printf("| Performed : %d\n", (ok + ko));
	printf("| Passed    : %d\n", ok);
	printf("| Failed    : %d\n", ko);
	printf("+----------------------------------------[press a key]\n");
	getchar();
}
//------------------------------------------------------------------------------
// Main              
//------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
	int stop = 0;
	int start = 0;
	int test = 0;
	int adrPos = 2;

	// Get Progran args (we need the client address and optionally Rack and Slot)  
	if (argc<2)//argc != 2 && argc != 3)
	{
		Usage();
		printf("fout %d", argc);
		return 1;
	}
	Address = argv[1];
	//if (argc == 4)
	//{
	//	Rack = atoi(argv[2]);
	//	Slot = atoi(argv[3]);
	//}

	if (argc > 2)
	{
		if (strcmp(argv[adrPos], "--stop") == 0)
		{
			stop = 1;
			printf("stopping...\n");
		}
		else if (strcmp(argv[adrPos], "--start") == 0)
		{
			start = 1;
			printf("starting...\n");
		}
		else if (strcmp(argv[adrPos], "--test") == 0)
		{
			test = 1;
			printf("testing...\n");
		}
	}

	// Client Creation
	Client = new TSnap7Client();
	Client->SetAsCallback(CliCompletion, NULL);
	

	// Connection
	if (CliConnect())
	{
		if (test)
		{
			printf("testing...2\n");
			PerformTests();
			Summary();
		}
		else if (start)
		{
			printf("starting...2\n");
			int result = Client->PlcHotStart();
			printf("Resultaat van starten = %d.\n", result);
		}
		else if (stop)
		{
			printf("stopping...2\n");
			int result = Client->PlcStop();
			printf("Resultaat van stoppen = %d.\n", result);
		}
		CliDisconnect();
	};

	// Deletion
	delete Client;

	return 0;
}
