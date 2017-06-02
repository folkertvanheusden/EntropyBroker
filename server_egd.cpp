#include <arpa/inet.h>
#include <string>
#include <map>
#include <vector>
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

const char *pid_file = PID_DIR "/server_egd.pid";

bool do_exit = false;

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	do_exit = true;
}

int open_tcp_socket(char *host, int port)
{
	return connect_to(host, port);
}

int open_unixdomain_socket(char *path)
{
        int len;
        struct sockaddr_un addr;
        int fd = -1;

        if (strlen(path) >= sizeof addr.sun_path)
		error_exit("Path %s too large (%d limit)", path, sizeof addr.sun_path);

        memset(&addr, 0x00, sizeof addr);
        addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);
        len = offsetof(struct sockaddr_un, sun_path) + strlen(path);

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
		error_exit("Failed to create socket");

	if (connect(fd, (struct sockaddr *)&addr, len) == 0)
		return fd;

	error_exit("Failed to connect to %s", path);

	return -1;
}

void help(void)
{
	printf("-I host   entropy_broker host to connect to\n");
	printf("          e.g. host\n");
	printf("               host:port\n");
	printf("               [ipv6 literal]:port\n");
	printf("          you can have multiple entries of this\n");
	printf("-d path   egd unix domain socket to read from\n");
	printf("-t host   egd tcp host to read from (mutually exclusive from width -d)\n");
	printf("-T port   egd tcp port to read from\n");
	printf("-o file   file to write entropy data to (mututally exclusive with -i)\n");
	printf("-a x      bytes per interval to read from egd\n");
	printf("-b x      interval for reading data\n");
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
	int read_fd = -1;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *device = NULL;
	char *bytes_file = NULL;
	double read_interval = 5.0;
	unsigned int read_bytes_per_interval = 16;
	int index = 0;
	int verbose = 0;
	char server_type[128];
	bool show_bps = false;
	std::string username, password;
	char *egd_host = NULL;
	int egd_port = -1;
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	fprintf(stderr, "eb_server_egd v" VERSION ", (C) 2009-2017 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "I:t:T:hSX:P:a:b:o:d:L:l:snv")) != -1)
	{
		switch(c)
		{
			case 'I':
				hosts.push_back(optarg);
				break;

			case 't':
				egd_host = optarg;
				break;

			case 'T':
				egd_port =  atoi(optarg);
				if (egd_port < 1)
					error_exit("-T requires a value >= 1");
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

			case 'a':
				read_bytes_per_interval = atoi(optarg);
				if (read_bytes_per_interval > sizeof bytes)
					error_exit("-a: parameter must be %d or less", sizeof bytes);
				break;

			case 'b':
				read_interval = atof(optarg);
				break;

			case 'o':
				bytes_file = optarg;
				break;

			case 'd':
				device = optarg;
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

	if (username.length() == 0 || password.length() == 0)
		error_exit("please select a file with authentication parameters (username + password) using the -X switch");

	if (hosts.empty() && !bytes_file)
		error_exit("no host to connect to given, also no file to write to given");

	if (!device && !egd_host)
		error_exit( "No egd source specified: use -d or -t (and -T)" );

	if (device != NULL && egd_host != NULL)
		error_exit("-d and -t are mutually exclusive");

	(void)umask(0177);
	no_core();
	lock_mem(bytes, sizeof bytes);

	set_logging_parameters(log_console, log_logfile, log_syslog, log_level);

	snprintf(server_type, sizeof server_type, "server_egd v" VERSION " %s", device);

	protocol *p = NULL;
	if (!hosts.empty())
		p = new protocol(&hosts, username, password, true, server_type, DEFAULT_COMM_TO);

	if (device)
	{
		read_fd = open_unixdomain_socket(device);
		if (read_fd == -1)
			error_exit("error opening %s", device);
	}
	else
	{
		read_fd = open_tcp_socket(egd_host, egd_port);
		if (read_fd == -1)
			error_exit("Failed to connect to %s:%d", egd_host, egd_port);
	}

	if (!do_not_fork)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	init_showbps();
	set_showbps_start_ts();
	for(;!do_exit;)
	{
		unsigned char request[2], reply[1];
		int bytes_to_read = std::min(255u, std::min((unsigned int)(sizeof bytes - index), read_bytes_per_interval));

		// gather random data from EGD
		request[0] = 1;
		request[1] = bytes_to_read;
		if (WRITE(read_fd, request, sizeof request, &do_exit) != 2)
			error_exit("Problem sending request to EGD");
		if (do_exit) break;
		if (READ(read_fd, reply, 1, &do_exit) != 1)
			error_exit("Problem receiving reply header from EGD");
		if (do_exit) break;
		bytes_to_read = reply[0];
		if (READ(read_fd, &bytes[index], bytes_to_read, &do_exit) != bytes_to_read)
			error_exit("Problem receiving reply-data from EGD");
		if (do_exit) break;
		index += bytes_to_read;
		dolog(LOG_DEBUG, "Got %d bytes from EGD", bytes_to_read);
		////////

		if (index == sizeof bytes)
		{
			if (show_bps)
				update_showbps(sizeof bytes);

			if (bytes_file)
				emit_buffer_to_file(bytes_file, bytes, index);

			if (p)
			{
				if (p -> message_transmit_entropy_data(bytes, index, &do_exit) == -1)
				{
					dolog(LOG_INFO, "connection closed");

					p -> drop();
				}

				if (read_interval > 0.0 && p -> sleep_interruptable(read_interval, &do_exit) != 0)
				{
					dolog(LOG_INFO, "connection closed");

					p -> drop();
				}
			}
			else if (read_interval > 0.0)
			{
				usleep(read_interval * 1000000.0);
			}

			set_showbps_start_ts();

			index = 0;
		}
	}

	memset(bytes, 0x00, sizeof bytes);
	unlink(pid_file);

	delete p;

	return 0;
}
