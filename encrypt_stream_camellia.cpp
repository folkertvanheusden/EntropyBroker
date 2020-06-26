#include <string>
#include <vector>
#include <string.h>
#include <stdio.h>

#include "error.h"
#include "encrypt_stream.h"
#include "encrypt_stream_camellia.h"
#include "utils.h"

encrypt_stream_camellia::encrypt_stream_camellia()
{
	enc = NULL;
	dec = NULL;
}

encrypt_stream_camellia::~encrypt_stream_camellia()
{
	delete enc;
	delete dec;
}

int encrypt_stream_camellia::get_ivec_size()
{
	return CryptoPP::Camellia::BLOCKSIZE;
}

int encrypt_stream_camellia::get_key_size()
{
	return CryptoPP::Camellia::DEFAULT_KEYLENGTH;
}

bool encrypt_stream_camellia::init(unsigned char *key_in, int key_len, unsigned char *ivec_in, bool force)
{
	my_assert(key_len > 0);

#ifdef CRYPTO_DEBUG
	printf("KEY: "); hexdump(key_in, key_len);
#endif

	unsigned char temp_key[CryptoPP::Camellia::DEFAULT_KEYLENGTH] = { 0 };
	memcpy(temp_key, key_in, std::min((int)CryptoPP::Camellia::DEFAULT_KEYLENGTH, key_len));

	if (enc)
		delete enc;
	if (dec)
		delete dec;

	enc = new CryptoPP::CFB_Mode<CryptoPP::Camellia>::Encryption(temp_key, CryptoPP::Camellia::DEFAULT_KEYLENGTH, ivec_in);
	dec = new CryptoPP::CFB_Mode<CryptoPP::Camellia>::Decryption(temp_key, CryptoPP::Camellia::DEFAULT_KEYLENGTH, ivec_in);

	return true;
}

std::string encrypt_stream_camellia::get_name()
{
	return "camellia";
}

void encrypt_stream_camellia::encrypt(unsigned char *p, int len, unsigned char *p_out)
{
	my_assert(len > 0);

#ifdef CRYPTO_DEBUG
	printf("ORG: "); hexdump(p, len);
	printf("EIV %d before: ", ivec_offset); hexdump(ivec, 8);
#endif

	enc -> ProcessData(p_out, p, len);

#ifdef CRYPTO_DEBUG
	printf("EIV %d after: ", ivec_offset); hexdump(ivec, 8);
	printf("ENC: "); hexdump(p_out, len);
#endif
}

void encrypt_stream_camellia::decrypt(unsigned char *p, int len, unsigned char *p_out)
{
	my_assert(len > 0);

#ifdef CRYPTO_DEBUG
	printf("DEC: "); hexdump(p, len);
	printf("EIV %d before: ", ivec_offset); hexdump(ivec, 8);
#endif

	dec -> ProcessData(p_out, p, len);

#ifdef CRYPTO_DEBUG
	printf("EIV %d after: ", ivec_offset); hexdump(ivec, 8);
	printf("ORG: "); hexdump(p_out, len);
#endif
}
