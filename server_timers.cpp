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

const char *server_type = "server_timers v" VERSION;
const char *pid_file = PID_DIR "/server_timers.pid";

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

#define SLEEP_CLOCK	CLOCK_MONOTONIC

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

int get_clock_res()
{
	struct timespec ts;

	if (clock_getres(SLEEP_CLOCK, &ts) == -1)
		error_exit("clock_getres failed");

	return ts.tv_nsec;
}

inline double gen_entropy_data(int sl)
{
	double start = get_ts_ns();

	const struct timespec ts = { 0, sl };
	clock_nanosleep(SLEEP_CLOCK, 0, &ts, NULL);

	return get_ts_ns() - start;
}


int main(int argc, char *argv[])
{
	unsigned char bytes[4096];
	int bits = 0, index = 0;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *bytes_file = NULL;
	bool show_bps = false;
	std::string username, password;
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	fprintf(stderr, "%s, (C) 2009-2017 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "I:hX:P:So:L:l:sn")) != -1)
	{
		switch(c)
		{
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

	if (!do_not_fork && !show_bps)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	protocol *p = NULL;
	if (!hosts.empty())
		p = new protocol(&hosts, username, password, true, server_type, DEFAULT_COMM_TO);

	int slp = get_clock_res();
	dolog(LOG_INFO, "resolution of clock is %dns", slp);

	init_showbps();
	set_showbps_start_ts();

	unsigned char cur_byte = 0;
	int equal_cnt = 0;
	for(;!do_exit;)
	{
		// gather random data
		double t1 = gen_entropy_data(slp), t2 = gen_entropy_data(slp);

		if (t1 == t2)
		{
			equal_cnt++;

			if (equal_cnt > 5 && slp < 1000)
			{
				dolog(LOG_DEBUG, "increasing sleep to %dns", slp);

				slp++;
			}

			continue;
		}
		equal_cnt = 0;

		cur_byte <<= 1;
		if (t1 >= t2)
			cur_byte |= 1;

		if (++bits == 8)
		{
			bytes[index++] = cur_byte;
			bits = 0;

			if (index == sizeof bytes)
			{
				if (show_bps)
					update_showbps(sizeof bytes);

				if (bytes_file)
					emit_buffer_to_file(bytes_file, bytes, index);

				if (p && p -> message_transmit_entropy_data(bytes, index, &do_exit) == -1)
				{
					dolog(LOG_INFO, "connection closed");

					p -> drop();
				}

				set_showbps_start_ts();

				index = 0; // skip header
			}
		}
	}

	memset(bytes, 0x00, sizeof bytes);
	unlink(pid_file);

	delete p;

	return 0;
}
