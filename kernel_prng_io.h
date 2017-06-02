#define DEV_RANDOM	"/dev/random"
#define DEV_URANDOM	"/dev/urandom"
#define PROC_POOLSIZE	"/proc/sys/kernel/random/poolsize"
#define PROC_WRITE_TH   "/proc/sys/kernel/random/write_wakeup_threshold"

int kernel_rng_get_entropy_count();
int kernel_rng_add_entropy(unsigned char *data, int n, int n_bits);
int kernel_rng_get_max_entropy_count(void);
int kernel_rng_get_write_threshold(void);
