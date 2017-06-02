#include <string>
#include <vector>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include <linux/random.h>

#include "error.h"
#include "utils.h"
#include "kernel_prng_io.h"

int kernel_rng_get_entropy_count()
{
	int n_bits;
	int fd = open(DEV_RANDOM, O_RDONLY);
	if (fd == -1)
		error_exit("Failed to open %s", DEV_RANDOM);

	if (ioctl(fd, RNDGETENTCNT, &n_bits) == -1)
		error_exit("ioctl(RNDGETENTCNT) failed");

	close(fd);

	return n_bits;
}

int kernel_rng_add_entropy(unsigned char *data, int n, int n_bits)
{
	int total_size;
        struct rand_pool_info *output;
	int fd = open(DEV_RANDOM, O_WRONLY);
	if (fd == -1)
		error_exit("Failed to open %s", DEV_RANDOM);

	total_size = sizeof(struct rand_pool_info) + n;
        output = (struct rand_pool_info *)malloc(total_size);
        if (!output)
                error_exit("malloc failure in kernel_rng_add_entropy_no_bitcount_increase(%d)", n);

	output -> entropy_count = n_bits;
	output -> buf_size      = n;
	memcpy(&(output -> buf[0]), data, n);

	if (ioctl(fd, RNDADDENTROPY, output) == -1)
		error_exit("ioctl(RNDADDENTROPY) failed!");

	free(output);

	close(fd);

	return 0;
}

int get_file_value(const char *const file)
{
        FILE *fh = fopen(file, "r");
        if (!fh)
                error_exit("Failed to open %s", file);

        int value = -1;
        if (fscanf(fh, "%d", &value) != 1)
                error_exit("Failed to read from %s", file);

        fclose(fh);

        return value;
}

int kernel_rng_get_max_entropy_count(void)
{
        return get_file_value(PROC_POOLSIZE);
}

int kernel_rng_get_write_threshold(void)
{
        return get_file_value(PROC_WRITE_TH);
}
