#include <crypto++/sha.h>

class hasher_sha512 : public hasher
{
public:
	hasher_sha512();
	~hasher_sha512();

	std::string get_name();

	int get_hash_size() const;
	void do_hash(unsigned char *in, int in_size, unsigned char *dest);
};
