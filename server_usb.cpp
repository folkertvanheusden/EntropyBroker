#include <arpa/inet.h>
#include <string>
#include <map>
#include <vector>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

extern "C" {
#include <libusb-1.0/libusb.h>
}

const char *server_type = "server_usb v" VERSION;
const char *pid_file = PID_DIR "/server_usb.pid";

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

void poke(libusb_device_handle *dev)
{
	unsigned char buffer[256];

	(void)libusb_get_descriptor(dev, 0, 0, buffer, sizeof buffer);
}

long int timed_poke(libusb_device_handle *dev)
{
	struct timespec t1, t2;

	clock_gettime(CLOCK_REALTIME, &t1);
	poke(dev);
	clock_gettime(CLOCK_REALTIME, &t2);

	long int dummy = t2.tv_sec - t1.tv_sec;

	return (dummy * 1000000000 + t2.tv_nsec) - t1.tv_nsec;
}

double gen_entropy_data(libusb_device_handle *dev)
{
	return double(timed_poke(dev));
}

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
	unsigned char bytes[4096];
	unsigned char cur_byte = 0;
	int bits = 0;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *bytes_file = NULL;
	bool show_bps = false;
	std::string username, password;
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	fprintf(stderr, "%s, (C) 2009-2017 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "hX:P:So:I:L:l:sn")) != -1)
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

	protocol *p = NULL;
	if (!hosts.empty())
		p = new protocol(&hosts, username, password, true, server_type, DEFAULT_COMM_TO);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	struct libusb_device **devs = NULL;
	libusb_device_handle **devhs;
	int index = 0, n = 0, use_n = 0;

	if (libusb_init(NULL) < 0)
		error_exit("cannot init libusb");

	if (libusb_get_device_list(NULL, &devs) < 0)
		error_exit("cannot retrieve usb devicelist");

	while(devs[n] != NULL) { n++; }

	dolog(LOG_INFO, "Found %d devices", n);

	devhs = (libusb_device_handle **)malloc(sizeof(libusb_device_handle *) * n);
	for(index=0; index<n; index++)
	{
		uint8_t bus_nr = libusb_get_bus_number(devs[index]);
		uint8_t dev_nr = libusb_get_device_address(devs[index]);
		struct libusb_device_descriptor desc;
		libusb_get_device_descriptor(devs[index], &desc);

		dolog(LOG_INFO, "Opening device %d: %d/%d %04x:%04x", index, bus_nr, dev_nr, desc.idVendor, desc.idProduct);

		if (desc.idVendor == 0x1d6b) // ignore
			continue;

		if (libusb_open(devs[index], &devhs[use_n++]) != 0)
			error_exit("error getting usb handle");
	}

	dolog(LOG_INFO, "Using %d devices", use_n);
	if (use_n == 0)
		error_exit("no devices found which can be used");

	init_showbps();
	set_showbps_start_ts();

	int dev_index = 0;
	for(;!do_exit;)
	{
		// gather random data
		double t1 = gen_entropy_data(devhs[dev_index]), t2 = gen_entropy_data(devhs[dev_index]);

		if (++dev_index >= use_n)
			dev_index = 0;

		if (t1 == t2)
			continue;

		cur_byte <<= 1;
		if (t1 > t2)
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

	for(index=0; index<n; index++)
		libusb_close(devhs[index]);

	libusb_free_device_list(devs, 1);

	libusb_exit(NULL);

	free(devhs);

	unlink(pid_file);

	return 0;
}
