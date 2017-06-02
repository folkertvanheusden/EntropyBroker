#include <arpa/inet.h>
#include <vector>
#include <string>
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
#include <signal.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libgen.h>

#include "error.h"
#include "random_source.h"
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
#include "kernel_prng_io.h"

#define DEFAULT_COMM_TO 15
const char *pid_file = PID_DIR "/client_file.pid";
const char *client_type = NULL;

bool do_exit = false;

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	do_exit = true;
}

void help(bool is_eb_client_file)
{
        printf("-I host   entropy_broker host to connect to\n");
        printf("          e.g. host\n");
        printf("               host:port\n");
        printf("               [ipv6 literal]:port\n");
        printf("          you can have multiple entries of this\n");
	if (is_eb_client_file)
		printf("-c count  number of BYTES, 0=no limit\n");
	if (is_eb_client_file)
		printf("-f file   write bytes to \"file\"\n");
	printf("-l file   log to file 'file'\n");
	printf("-L x      log level, 0=nothing, 255=all\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
	if (!is_eb_client_file)
	{
		printf("-S time   how long to sleep between each iteration\n");
		printf("-b x      how many BYTES to process each iteration\n");
	}
}

int main(int argc, char *argv[])
{
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	int count = 0;
	const char *file = NULL;
	int block_size = 4096;
	int sleep_time = 0;
	char *prog = basename(strdup(argv[0]));
	std::string username, password;
	bool is_eb_client_file = strstr(prog, "eb_client_file") != NULL;
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	if (!is_eb_client_file)
		file = "/dev/random";

	if (is_eb_client_file)
		client_type = "eb_client_file v" VERSION;
	else
		client_type = "eb_client_kernel_generic v" VERSION;
	printf("%s, (C) 2009-2017 by folkert@vanheusden.com\n", client_type);

	while((c = getopt(argc, argv, "b:S:hc:f:X:P:I:L:l:sn")) != -1)
	{
		switch(c)
		{
			case 'b':
				block_size = atoi(optarg);
				if (block_size < 1)
					error_exit("invalid block size");
				break;

			case 'S':
				sleep_time = atoi(optarg);
				if (sleep_time < 1)
					error_exit("invalid sleep time");
				break;

			case 'c':
				count = atoi(optarg);
				if (count <= 0)
					count = -1;
				break;

			case 'f':
				file = optarg;
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

			case 'h':
				help(is_eb_client_file);
				return 0;

			default:
				help(is_eb_client_file);
				return 1;
		}
	}

	if (username.length() == 0 || password.length() == 0)
		error_exit("password + username cannot be empty");

	if (hosts.empty())
		error_exit("No host to connect to selected");

	if (!file)
		error_exit("No file to write to selected");

	if (count < 1)
		error_exit("Count must be >= 1");

	(void)umask(0177);

	set_logging_parameters(log_console, log_logfile, log_syslog, log_level);

	protocol *p = new protocol(&hosts, username, password, false, client_type, DEFAULT_COMM_TO);

	FILE *fh = fopen(file, "wb");
	if (!fh)
		error_exit("Failed to create file %s", file);

	no_core();

	if (!do_not_fork)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	unsigned char buffer[4096];
	lock_mem(buffer, sizeof buffer);

	while((count > 0 || count == -1) && do_exit == false)
	{
		int n_bytes_to_get = std::min(block_size, std::min(count <= 0 ? 4096 : count, 4096));
		int n_bits_to_get = n_bytes_to_get * 8;

		dolog(LOG_INFO, "will get %d bits", n_bits_to_get);

		int n_bytes = p -> request_bytes(buffer, n_bits_to_get, false, &do_exit);
		if (do_exit)
			break;

		if (count == -1) { }
		else if (n_bytes >= count)
			count = 0;
		else
			count -= n_bytes;

		if (fwrite(buffer, 1, n_bytes, fh) != (size_t)n_bytes)
			error_exit("Failed to write %d bytes to file", n_bytes);

		if (sleep_time > 0)
			sleep(sleep_time);
	}

	memset(buffer, 0x00, sizeof buffer);
	unlock_mem(buffer, sizeof buffer);

	fclose(fh);

	unlink(pid_file);

	delete p;

	dolog(LOG_INFO, "Finished");

	return 0;
}
