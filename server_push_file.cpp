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
#include <fcntl.h>
#include <termios.h>

const char *server_type = "server_push_file v" VERSION;
const char *pid_file = PID_DIR "/server_push_file.pid";

bool do_exit = false;

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
	printf("-f file   file to read from\n");
        printf("-l file   log to file 'file'\n");
	printf("-L x      log level, 0=nothing, 255=all\n");
        printf("-s        log to syslog\n");
        printf("-n        do not fork\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int main(int argc, char *argv[])
{
	unsigned char bytes[4096];
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *file = NULL;
	std::string username, password;
	char *bytes_file = NULL;
	bool show_bps = false;
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	fprintf(stderr, "%s, (C) 2009-2017 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "S:I:f:hX:P:o:p:d:L:l:sn")) != -1)
	{
		switch(c)
		{
			case 'S':
				show_bps = true;
				break;

			case 'o':
				bytes_file = optarg;
				break;

			case 'X':
				get_auth_from_file(optarg, username, password);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'f':
				file = optarg;
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

	if (!hosts.empty() && (username.length() == 0 || password.length() == 0))
		error_exit("please select a file with authentication parameters (username + password) using the -X switch");

	if (hosts.empty() && !bytes_file)
		error_exit("no host to connect to or file to write to given");

	if (!file)
		error_exit("no file to read from selected");

	(void)umask(0177);

	set_logging_parameters(log_console, log_logfile, log_syslog, log_level);

	FILE *fh = fopen(file, "rb");
	if (!fh)
		error_exit("Failed to open file %s", file);

	(void)umask(0177);
	no_core();

	if (!do_not_fork)
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

	bool data = false;
	int got_bytes = -1;

	init_showbps();
	set_showbps_start_ts();
	for(;!feof(fh) && !do_exit;)
	{
		// gather random data
		if (!data)
		{
			got_bytes = fread(bytes, 1, sizeof bytes, fh);
			if (got_bytes <= 0)
				break;

			data = true;
		}

		if (data)
		{
			if (show_bps)
				update_showbps(got_bytes);

			if (bytes_file)
				emit_buffer_to_file(bytes_file, bytes, got_bytes);

			if (p && p -> message_transmit_entropy_data(bytes, got_bytes, &do_exit) == -1)
			{
				dolog(LOG_INFO, "connection closed");

				p -> drop();
			}

			set_showbps_start_ts();

			data = false;
		}
	}

	fclose(fh);

	unlink(pid_file);

	delete p;

	return 0;
}
