#include <qwqng.hpp>

#include <arpa/inet.h>
#include <string>
#include <vector>
#include <map>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/un.h>

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

const char *pid_file = PID_DIR "/server_qwqng.pid";

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
	printf("-o file   file to write entropy data to (mututal exclusive with -i)\n");
	printf("-l file   log to file 'file'\n");
	printf("-L x      log level, 0=nothing, 255=all\n");
	printf("-s        log to syslog\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int main(int argc, char *argv[])
{
	unsigned char bytes[4096];
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *bytes_file = NULL;
	int index = 0;
	int verbose = 0;
	char server_type[128];
	bool show_bps = false;
	std::string username, password;
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	fprintf(stderr, "eb_server_QNG_PQ4000KU v" VERSION ", (C) 2009-2017 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "I:hSX:P:o:L:l:snv")) != -1)
	{
		switch(c)
		{
			case 'I':
				hosts.push_back(optarg);
				break;

			case 'S':
				show_bps = true;
				break;

			case 'X':
				get_auth_from_file(optarg, username, password);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'v':
				verbose++;
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

			case 'h':
				help();
				return 0;

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

	lock_mem(bytes, sizeof bytes);

	set_logging_parameters(log_console, log_logfile, log_syslog, log_level);

	QWQNG *q = new QWQNG();

	if (!q -> DeviceID())
		error_exit("Could not find a device? (2)");
	lock_mem(q, sizeof *q);

	snprintf(server_type, sizeof server_type, "eb_server_qwqng v" VERSION " %s", q -> DeviceID());
	dolog(LOG_INFO, server_type);

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

	init_showbps();
	set_showbps_start_ts();

	bool stats_error_reported = false;
	for(;!do_exit;)
	{
		int rc = q -> RandBytes(reinterpret_cast<char *>(bytes), 4096);
		if (rc != QNG_S_OK && rc != S_OK)
		{
			if (rc == QNG_E_STATS_EXCEPTION)
			{
				if (!stats_error_reported)
				{
					dolog(LOG_WARNING, "Device reports a statistics test exception");
					stats_error_reported = true;
				}

				usleep(10000); // do not hog cpu

				continue;
			}

			error_exit("Failed to retrieve random bytes from device %x", rc);
		}

		stats_error_reported = false;

		if (show_bps)
			update_showbps(4096);

		if (bytes_file)
			emit_buffer_to_file(bytes_file, bytes, index);

		if (p && p -> message_transmit_entropy_data(bytes, 4096, &do_exit) == -1)
		{
			dolog(LOG_INFO, "connection closed");
			p -> drop();
		}

		set_showbps_start_ts();

		index = 0;
	}

	delete p;

	memset(bytes, 0x00, sizeof bytes);

	unlink(pid_file);

	return 0;
}
