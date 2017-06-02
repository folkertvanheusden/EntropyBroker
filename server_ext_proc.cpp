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
#include <sys/wait.h>

#define SHELL "/bin/bash"

#define DEFAULT_SLEEP 0

const char *server_type = "server_ext_proc v" VERSION;
const char *pid_file = PID_DIR "/server_ext_proc.pid";

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
	printf("-c command   command to execute\n");
	printf("-Z shell  shell to use. default is " SHELL "\n");
	printf("-b x      how long to sleep between invocations (default: %ds)\n", DEFAULT_SLEEP);
	printf("-o file   file to write entropy data to\n");
        printf("-l file   log to file 'file'\n");
	printf("-L x      log level, 0=nothing, 255=all\n");
        printf("-s        log to syslog\n");
        printf("-S        show bps\n");
        printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int main(int argc, char *argv[])
{
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	const char *cmd = NULL, *shell = SHELL;
	std::string username, password;
	int slp = DEFAULT_SLEEP;
	char *bytes_file = NULL;
	bool show_bps = false;
	int idle = 0;
	int log_level = LOG_INFO;
	std::vector<std::string> hosts;

	fprintf(stderr, "%s, (C) 2009-2017 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "b:I:So:hc:Z:X:P:o:p:d:L:l:sn")) != -1)
	{
		switch(c)
		{
			case 'b':
				idle = atoi(optarg);
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

			case 'c':
				cmd = optarg;
				break;

			case 'S':
				show_bps = true;
				break;

			case 'Z':
				shell = optarg;
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

	if (!cmd)
		error_exit("no command to execute");

	(void)umask(0177);
	no_core();

	set_logging_parameters(log_console, log_logfile, log_syslog, log_level);

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
	signal(SIGCHLD, SIG_IGN);

	bool data = false;
	int got_bytes = -1;
	pid_t child_pid;
	int child_fd = -1;
	char buffer[32768];
	lock_mem(buffer, sizeof buffer);
	bool first = true;

	init_showbps();
	set_showbps_start_ts();
	for(;!do_exit;)
	{
		if (child_fd == -1)
		{
			if (first)
				first = false;
			else if (sleep > 0)
				sleep(slp);

			dolog(LOG_DEBUG, "Starting %s", cmd);

			start_process(shell, cmd, &child_fd, &child_pid);
		}

		// gather random data
		if (!data)
		{
			got_bytes = read(child_fd, buffer, sizeof buffer);
			if (got_bytes <= 0)
			{
				dolog(LOG_DEBUG, "Process stopped");

				close(child_fd);
				child_fd = -1;

				int status = 0;
				wait(&status);

				continue;
			}

			data = true;
		}

		if (data)
		{
			if (show_bps)
				update_showbps(got_bytes);

			if (bytes_file)
				emit_buffer_to_file(bytes_file, reinterpret_cast<unsigned char *>(buffer), got_bytes);

			if (p)
			{
				unsigned char *pnt = reinterpret_cast<unsigned char *>(buffer);
				while(got_bytes > 0)
				{
					int cur_count = std::min(got_bytes, 4096);

					if (p -> message_transmit_entropy_data(pnt, cur_count, &do_exit) == -1)
					{
						dolog(LOG_INFO, "connection closed");

						p -> drop();
					}

					pnt += cur_count;
					got_bytes -= cur_count;
				}
			}

			set_showbps_start_ts();

			data = false;
		}

		if (idle > 0)
			sleep(idle);
	}

	unlink(pid_file);

	memset(buffer, 0x00, sizeof buffer);

	delete p;

	return 0;
}
