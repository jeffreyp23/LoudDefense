//#include <windows.h>
#include <winsock2.h>
//#include <ws2tcpip.h>
//#include <stdlib.h>
#include <stdio.h>

#include <iostream>
#pragma comment(lib,"ws2_32.lib") //Winsock Library

//#pragma comment (lib, "Ws2_32.lib")
//#pragma comment (lib, "Mswsock.lib")
//#pragma comment (lib, "AdvApi32.lib")


class HTTP
{
public:
	HTTP();
	~HTTP();
private:
	HINSTANCE hInst;
	WSADATA wsaData;
	//SOCKET socketfd;
	int socketfd;
	struct sockaddr_in server;
};

