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

const char *server_type = "server_stream v" VERSION;
const char *pid_file = PID_DIR "/server_stream.pid";

#define BLOCK_SIZE 4096

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

void set_serial_parameters(int fd, char *pars_in)
{
        struct termios newtio;
	char **pars = NULL;
	int n_pars = 0;
	int bps = B9600;
	int bits = CS8;

	split_string(pars_in, ",", &pars, &n_pars);

	// bps,bits
	if (n_pars != 2)
		error_exit("set serial: missing parameter");

	switch(atoi(pars[0]))
	{
		case 50:
			bps = B50;
			break;

		case 75:
			bps = B75;
			break;

		case 110:
			bps = B110;
			break;

		case 134:
			bps = B134;
			break;

		case 150:
			bps = B150;
			break;

		case 200:
			bps = B200;
			break;

		case 300:
			bps = B300;
			break;

		case 600:
			bps = B600;
			break;

		case 1200:
			bps = B1200;
			break;

		case 1800:
			bps = B1800;
			break;

		case 2400:
			bps = B2400;
			break;

		case 4800:
			bps = B4800;
			break;

		case 9600:
			bps = B9600;
			break;

		case 19200:
			bps = B19200;
			break;

		case 38400:
			bps = B38400;
			break;

		case 57600:
			bps = B57600;
			break;

		case 115200:
			bps = B115200;
			break;

		case 230400:
			bps = B230400;
			break;

#ifdef linux
		case 460800:
			bps = B460800;
			break;

		case 500000:
			bps = B500000;
			break;

		case 576000:
			bps = B576000;
			break;

		case 921600:
			bps = B921600;
			break;

		case 1000000:
			bps = B1000000;
			break;

		case 1152000:
			bps = B1152000;
			break;

		case 1500000:
			bps = B1500000;
			break;

		case 2000000:
			bps = B2000000;
			break;
  /* not all of these constants are available on all architectures */
  #ifdef B2500000
		case 2500000:
			bps = B2500000;
			break;
  #endif

  #ifdef B3000000
		case 3000000:
			bps = B3000000;
			break;
  #endif

  #ifdef B3500000
		case 3500000:
			bps = B3500000;
			break;
  #endif

  #ifdef B4000000
		case 4000000:
			bps = B4000000;
			break;
  #endif
#endif
		default:
			error_exit("baudrate %s is not understood", pars[0]);
	}

	switch(atoi(pars[1]))
	{
		case 5:
			bits = CS5;
			break;

		case 6:
			bits = CS6;
			break;

		case 7:
			bits = CS7;
			break;

		case 8:
			bits = CS8;
			break;
	}

        if (tcgetattr(fd, &newtio) == -1)
                error_exit("tcgetattr failed");
        newtio.c_iflag = IGNBRK; // | ISTRIP;
        newtio.c_oflag = 0;
        newtio.c_cflag = bps | bits | CREAD | CLOCAL | CSTOPB;
        newtio.c_lflag = 0;
        newtio.c_cc[VMIN] = 1;
        newtio.c_cc[VTIME] = 0;
        tcflush(fd, TCIFLUSH);
        if (tcsetattr(fd, TCSANOW, &newtio) == -1)
                error_exit("tcsetattr failed");
}

void help(void)
{
        printf("-I host   entropy_broker host to connect to\n");
        printf("          e.g. host\n");
        printf("               host:port\n");
        printf("               [ipv6 literal]:port\n");
        printf("          you can have multiple entries of this\n");
	printf("-d dev    device to retrieve from\n");
	printf("-o file   file to write entropy data to (mututal exclusive with -d)\n");
	printf("-p pars   if the device is a serial device, then with -p\n");
	printf("          you can set its parameters: bps,bits\n");
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
	unsigned char bytes[BLOCK_SIZE];
	int read_fd = -1;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *device = NULL;
	char *serial = NULL;
	char *bytes_file = NULL;
	bool show_bps = false;
	std::string username, password;
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	fprintf(stderr, "%s, (C) 2009-2015 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "hSX:P:o:p:I:d:L:l:sn")) != -1)
	{
		switch(c)
		{
			case 'S':
				show_bps = true;
				break;

			case 'X':
				get_auth_from_file(optarg, username, password);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'o':
				bytes_file = optarg;
				break;

			case 'p':
				serial = optarg;
				break;

			case 'I':
				hosts.push_back(optarg);
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

	if (!hosts.empty() && (username.length() == 0 || password.length() == 0))
		error_exit("please select a file with authentication parameters (username + password) using the -X switch");

	if (hosts.empty() && !bytes_file)
		error_exit("no host to connect to or file to write to given");

	set_logging_parameters(log_console, log_logfile, log_syslog, log_level);

	if (device)
		read_fd = open(device, O_RDONLY);
	if (read_fd == -1)
		error_exit("error opening %s", device);

	if (serial)
		set_serial_parameters(read_fd, serial);

	(void)umask(0177);
	no_core();
	lock_mem(bytes, sizeof bytes);

	if (!do_not_fork)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	protocol *p = NULL;
	if (!hosts.empty())
		p = new protocol(&hosts, username, password, true, server_type, DEFAULT_COMM_TO);

	write_pid(pid_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	init_showbps();
	set_showbps_start_ts();
	for(;!do_exit;)
	{
		if (READ(read_fd, bytes, BLOCK_SIZE, &do_exit) != BLOCK_SIZE)
			error_exit("error reading from input");

		if (show_bps)
			update_showbps(BLOCK_SIZE);

		if (bytes_file)
			emit_buffer_to_file(bytes_file, bytes, BLOCK_SIZE);

		if (p && p -> message_transmit_entropy_data(bytes, BLOCK_SIZE, &do_exit) == -1)
		{
			dolog(LOG_INFO, "connection closed");
			p -> drop();
		}

		set_showbps_start_ts();
	}

	memset(bytes, 0x00, sizeof bytes);
	unlink(pid_file);

	delete p;

	return 0;
}
