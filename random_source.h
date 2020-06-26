#include <crypto++/osrng.h>

typedef enum { RS_CRYPTOPP, RS_DEV_URANDOM, RS_DEV_RANDOM } random_source_t;

class random_source
{
private:
	const random_source_t rs;
	CryptoPP::AutoSeededRandomPool *rng;
	std::string state_file;
	bool notified_errors;

	void dump_state(const std::string & file);
	void retrieve_state(const std::string & file);

public:
	random_source(const random_source_t rst);
	random_source(const random_source_t rst, const std::string & dump_file_in);
	~random_source();

	void get(unsigned char *const p, const size_t n);
	bool check_empty() const;
	void seed(const unsigned char *const in, const size_t n, const double byte_count);
};
