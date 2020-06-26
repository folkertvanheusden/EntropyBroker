#include <crypto++/modes.h>
#include <crypto++/des.h>

class encrypt_stream_3des : public encrypt_stream
{
private:
	CryptoPP::CFB_Mode<CryptoPP::DES_EDE3>::Encryption *enc;
	CryptoPP::CFB_Mode<CryptoPP::DES_EDE3>::Decryption *dec;

public:
	encrypt_stream_3des();
	~encrypt_stream_3des();

	int get_ivec_size();
	int get_key_size();

	bool init(unsigned char *key, int key_len, unsigned char *ivec, bool force=false);

	std::string get_name();

	void encrypt(unsigned char *p_in, int len, unsigned char *p_out);
	void decrypt(unsigned char *p_in, int len, unsigned char *p_out);
};
