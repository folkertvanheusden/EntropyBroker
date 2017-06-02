#include <arpa/inet.h>
#include <string>
#include <vector>
#include <map>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "random_source.h"
#include "kernel_prng_io.h"
#include "utils.h"
#include "log.h"
#include "encrypt_stream.h"
#include "hasher.h"
#include "math.h"
#include "protocol.h"
#include "statistics.h"
#include "statistics_global.h"
#include "statistics_user.h"
#include "users.h"
#include "auth.h"

#define DEFAULT_COMM_TO 15
const char *pid_file = PID_DIR "/client_linux_kernel.pid";
const char *client_type = "client_linux_kernel " VERSION;

bool do_exit = false;

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	do_exit = true;
}

void help(void)
{
        printf("-I host   entropy_broker host to connect to\n");
        printf("          e.g. host\n");
        printf("               host:port\n");
        printf("               [ipv6 literal]:port\n");
        printf("          you can have multiple entries of this\n");
	printf("-l file   log to file 'file'\n");
	printf("-L x      log level, 0=nothing, 255=all\n");
	printf("-s        log to syslog\n");
	printf("-b x      interval in which data will check the entropy-level. in seconds. 0.1 is every 100ms.\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int main(int argc, char *argv[])
{
	int dev_random_fd = open(DEV_RANDOM, O_RDWR);
	const int max_bits_in_kernel_rng = kernel_rng_get_max_entropy_count();
	const int write_threshold = kernel_rng_get_write_threshold();
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	std::string username, password;
	int interval = -1;
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	printf("eb_client_linux_kernel v" VERSION ", (C) 2009-2015 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "b:hX:P:I:L:l:sn")) != -1)
	{
		switch(c)
		{
			case 'b':
				interval = atof(optarg);
				if (interval < 1)
					error_exit("Interval must be > 0");
				break;

			case 'X':
				get_auth_from_file(optarg, username, password);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'I':
				hosts.push_back(optarg);
				break;

			case 's':
				log_syslog = true;
				break;

			case 'L':
				log_level = atoi(optarg);
				break;

			case 'l':
				log_logfile = optarg;
				break;

			case 'n':
				do_not_fork = true;
				log_console = true;
				break;

			default:
				help();
				return 1;
		}
	}

	if (username.length() == 0 || password.length() == 0)
		error_exit("please select a file with authentication parameters (username + password) using the -X switch");

	if (hosts.empty())
		error_exit("no host to connect to selected");

	set_logging_parameters(log_console, log_logfile, log_syslog, log_level);

	if (!do_not_fork)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	protocol *p = new protocol(&hosts, username, password, false, client_type, DEFAULT_COMM_TO);

	(void)umask(0177);
	no_core();

	write_pid(pid_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	dolog(LOG_INFO, "started with %d bits in kernel rng", kernel_rng_get_entropy_count());

	if (dev_random_fd == -1)
		error_exit("failed to open %s", DEV_RANDOM);

	bit_count_estimator bce(BCE_SHANNON);

	for(;!do_exit;)
	{
		struct timeval tv, *ptv = NULL;

		if (interval > 0) {
			tv.tv_sec = interval / 1000;
			tv.tv_usec = int(interval * 1000) % 1000;
			ptv = &tv;
		}

		// wait for /dev/random te become writable which means the entropy-
		// level dropped below a certain threshold
		fd_set write_fd;
		FD_ZERO(&write_fd);
		FD_SET(dev_random_fd, &write_fd);

		dolog(LOG_DEBUG, "wait for low-event");
		for(;!do_exit;)
		{
			int rc = select(dev_random_fd + 1, NULL, &write_fd, NULL, ptv);
printf("%d\n", rc);
			if (rc >= 0)
				break;

			if (errno != EINTR && errno != EAGAIN)
				error_exit("Select error: %m");
		}

		if (do_exit)
			break;

		int n_bits_in_kernel_rng = kernel_rng_get_entropy_count();
		dolog(LOG_DEBUG, "kernel rng bit count: %d", n_bits_in_kernel_rng);

		if (n_bits_in_kernel_rng < write_threshold)
		{
			/* find out how many bits to add */
			int n_bits_to_get = max_bits_in_kernel_rng - n_bits_in_kernel_rng;
			if (n_bits_to_get <= 0)
			{
				dolog(LOG_DEBUG, "number of bits to get <= 0: %d", n_bits_to_get);
				continue;
			}
			if (n_bits_to_get > 9999)
				n_bits_to_get = 9999;
			if (n_bits_to_get < 8)
				n_bits_to_get = 8;

			dolog(LOG_INFO, "%d bits left (%d max), will get %d bits", n_bits_in_kernel_rng, max_bits_in_kernel_rng, n_bits_to_get);

			int n_bytes_to_get = (n_bits_to_get + 7) / 8;

			unsigned char *buffer = static_cast<unsigned char *>(malloc(n_bytes_to_get));
			if (!buffer)
				error_exit("out of memory allocating %d bytes", n_bytes_to_get);
			lock_mem(buffer, n_bytes_to_get);

			int n_bytes = p -> request_bytes(buffer, n_bits_to_get, false, &do_exit);
			if (do_exit)
				break;

			int is_n_bits = bce.get_bit_count(reinterpret_cast<unsigned char *>(buffer), n_bytes);

			int rc = kernel_rng_add_entropy(reinterpret_cast<unsigned char *>(buffer), n_bytes, is_n_bits);
			if (rc == -1)
				error_exit("error submiting entropy data to kernel");

			dolog(LOG_DEBUG, "new entropy count: %d", kernel_rng_get_entropy_count());

			memset(buffer, 0x00, n_bytes_to_get);
			unlock_mem(buffer, n_bytes_to_get);
			free(buffer);
		}
	}

	unlink(pid_file);

	delete p;

	return 0;
}
