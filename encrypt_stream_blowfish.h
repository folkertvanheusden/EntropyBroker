#include <crypto++/modes.h>
#include <crypto++/blowfish.h>

class encrypt_stream_blowfish : public encrypt_stream
{
private:
	CryptoPP::CFB_Mode<CryptoPP::Blowfish>::Encryption *enc;
	CryptoPP::CFB_Mode<CryptoPP::Blowfish>::Decryption *dec;

public:
	encrypt_stream_blowfish();
	~encrypt_stream_blowfish();

	int get_ivec_size();
	int get_key_size();

	bool init(unsigned char *key, int key_len, unsigned char *ivec, bool force=false);

	std::string get_name();

	void encrypt(unsigned char *p_in, int len, unsigned char *p_out);
	void decrypt(unsigned char *p_in, int len, unsigned char *p_out);
};
