#pragma once
#include <string>


class CryptoProvider
{
public:
	CryptoProvider();
	static std::string sha256(std::string &code);
	~CryptoProvider();
};

