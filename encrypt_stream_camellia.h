#include <crypto++/modes.h>
#include <crypto++/camellia.h>

class encrypt_stream_camellia : public encrypt_stream
{
private:
	CryptoPP::CFB_Mode<CryptoPP::Camellia>::Encryption *enc;
	CryptoPP::CFB_Mode<CryptoPP::Camellia>::Decryption *dec;

public:
	encrypt_stream_camellia();
	~encrypt_stream_camellia();

	int get_ivec_size();
	int get_key_size();

	bool init(unsigned char *key, int key_len, unsigned char *ivec, bool force=false);

	std::string get_name();

	void encrypt(unsigned char *p_in, int len, unsigned char *p_out);
	void decrypt(unsigned char *p_in, int len, unsigned char *p_out);
};
