#include <arpa/inet.h>
#include <string>
#include <map>
#include <vector>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

const char *server_type = "server_kernel v" VERSION;
const char *pid_file = PID_DIR "/server_kernel.pid";

#include "defines.h"
#include "error.h"
#include "random_source.h"
#include "utils.h"
#include "log.h"
#include "encrypt_stream.h"
#include "hasher.h"
#include "protocol.h"
#include "server_utils.h"
#include "statistics.h"
#include "statistics_global.h"
#include "statistics_user.h"
#include "users.h"
#include "auth.h"
#include "kernel_prng_io.h"
#include "kernel_prng_rw.h"

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
	printf("-o file   file to write entropy data to\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
	printf("-l file   log to file 'file'\n");
	printf("-L x      log level, 0=nothing, 255=all\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int main(int argc, char *argv[])
{
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *bytes_file = NULL;
	bool show_bps = false;
	std::string username, password;
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	fprintf(stderr, "%s, (C) 2009-2017 by folkert@vanheusden.com\n", server_type);
	printf("Please note: this program RETRIEVES entropy data from the kernel and feeds that to the entropybroker!\n");
	printf("If you want to ADD data to the kernel entropy buffer instead (which is what you most likely want to do), then use eb_client_linux_kernel\n");

	while((c = getopt(argc, argv, "I:hX:P:So:L:l:sn")) != -1)
	{
		switch(c)
		{
			case 'I':
				hosts.push_back(optarg);
				break;

			case 'X':
				get_auth_from_file(optarg, username, password);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'S':
				show_bps = true;
				break;

			case 'o':
				bytes_file = optarg;
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

	if (!hosts.empty() && (username.length() == 0 || password.length() == 0))
		error_exit("please select a file with authentication parameters (username + password) using the -X switch");

	if (hosts.empty() && !bytes_file)
		error_exit("no host to connect to or file to write to given");

	(void)umask(0177);
	no_core();

	set_logging_parameters(log_console, log_logfile, log_syslog, log_level);

	if (!do_not_fork && !show_bps)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	protocol *p = NULL;
	if (!hosts.empty())
		p = new protocol(&hosts, username, password, true, server_type, DEFAULT_COMM_TO);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	unsigned char bytes[4096];
	lock_mem(bytes, sizeof bytes);

	init_showbps();
	set_showbps_start_ts();
	for(;!do_exit;)
	{
		dolog(LOG_DEBUG, "Bits available: %d", kernel_rng_get_entropy_count());

		if (kernel_rng_read_blocking(bytes, sizeof bytes) == -1)
		{
			dolog(LOG_WARNING, "Problem reading from kernel entropy buffer!");

			if (p != NULL && p -> sleep_interruptable(5.0) != 0)
			{
				dolog(LOG_INFO, "connection closed");
				p -> drop();
				continue;
			}
		}

		if (do_exit)
			break;

		if (show_bps)
			update_showbps(sizeof bytes);

		if (bytes_file)
			emit_buffer_to_file(bytes_file, bytes, sizeof bytes);

		if (p && p -> message_transmit_entropy_data(bytes, sizeof bytes, &do_exit) == -1)
		{
			dolog(LOG_INFO, "connection closed");
			p -> drop();
			continue;
		}

		set_showbps_start_ts();
	}

	memset(bytes, 0x00, sizeof bytes);
	unlink(pid_file);

	delete p;

	return 0;
}
