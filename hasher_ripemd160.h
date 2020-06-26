#include <crypto++/ripemd.h>

class hasher_ripemd160: public hasher
{
public:
	hasher_ripemd160();
	~hasher_ripemd160();

	std::string get_name();

	int get_hash_size() const;
	void do_hash(unsigned char *in, int in_size, unsigned char *dest);
};
