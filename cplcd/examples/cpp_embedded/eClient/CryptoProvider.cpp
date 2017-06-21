#include "CryptoProvider.h"
#include "sha256.h"


CryptoProvider::CryptoProvider()
{
}

std::string CryptoProvider::sha256(std::string &code)
{
	return picosha2::hash256_hex_string(code);
}

CryptoProvider::~CryptoProvider()
{
}
