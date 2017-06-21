#include "HTTP.h"



HTTP::HTTP()
{
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		throw "geen WSA";
	}
	socketfd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketfd == INVALID_SOCKET)
	{
		std::cout << "Kan geen Socket maken." << std::endl;
	}
	
	std::cout << "Socket gemaakt." << std::endl;

	server.sin_addr.s_addr	= inet_addr("192.168.2.2");
	server.sin_family		= AF_INET;
	server.sin_port			= htons( 8080 );

	if (connect(socketfd, (struct sockaddr *)&server, sizeof( server ) ) < 0)
	{
		throw "Connection error";
	}
	std::cout << "Connected" << std::endl;
}


HTTP::~HTTP()
{
}
