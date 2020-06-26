#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <crypto++/md5.h>

class hasher_md5 : public hasher
{
public:
	hasher_md5();
	~hasher_md5();

	std::string get_name();

	int get_hash_size() const;
	void do_hash(unsigned char *in, int in_size, unsigned char *dest);
};
