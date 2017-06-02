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

const char *server_type = "server_cycle_count v" VERSION;
const char *pid_file = PID_DIR "/server_cycle_count.pid";

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

bool do_exit = false;

inline unsigned long long GetCC(void)
{
  unsigned a, d; 

  asm volatile("rdtsc" : "=a" (a), "=d" (d)); 

  return ((unsigned long long)a) | (((unsigned long long)d) << 32LL); 
}

typedef struct
{
	char *buffer;
	volatile int index;
	int cache_size, cache_line_size;
	volatile int a;
} fiddle_state_t;

void fiddle(fiddle_state_t *p)
{
	// trigger cache misses etc
	p -> a += (p -> buffer)[p -> index]++;

	p -> index += p -> cache_line_size;

	while(p -> index >= p -> cache_size * 3)
		p -> index -= p -> cache_size * 3;
}

int get_cache_size()
{
	const char *cache_size_file = "/sys/devices/system/cpu/cpu0/cache/index0/size";
	FILE *fh = fopen(cache_size_file, "r");
	if (!fh)
		return 1024*1024; // my laptop has 32KB data l1 cache

	unsigned int s = 0;
        if (fscanf(fh, "%d", &s) != 1)
		error_exit("Tried to obtain 1 field from %s, failed doing that", cache_size_file);

        fclose(fh);

	return s;
}

int get_cache_line_size()
{
	const char *cache_line_size_file = "/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size";
	FILE *fh = fopen(cache_line_size_file, "r");
	if (!fh)
		return 1;

	unsigned int s = 0;
        if (fscanf(fh, "%d", &s) != 1)
		error_exit("Tried to obtain 1 field from %s, failed doing that", cache_line_size_file);

        fclose(fh);

	return s;
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
	int sw;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *bytes_file = NULL;
	bool show_bps = false;
	std::string username, password;
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	fprintf(stderr, "%s, (C) 2009-2017 by folkert@vanheusden.com\n", server_type);

	while((sw = getopt(argc, argv, "I:hX:P:So:L:l:sn")) != -1)
	{
		switch(sw)
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

	set_logging_parameters(log_console, log_logfile, log_syslog, log_level);

	fiddle_state_t fs;

	fs.index = 0;
	fs.cache_size = get_cache_size();
	dolog(LOG_INFO, "cache size: %dKB", fs.cache_size);
	fs.buffer = reinterpret_cast<char *>(malloc(fs.cache_size * 3));
	fs.cache_line_size = get_cache_line_size();
	dolog(LOG_INFO, "cache-line size: %d bytes", fs.cache_line_size);

	if (!do_not_fork && !show_bps)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	protocol *p = NULL;
	if (!hosts.empty())
		p = new protocol(&hosts, username, password, true, server_type, DEFAULT_COMM_TO);

	unsigned char bytes[4096];
	lock_mem(bytes, sizeof bytes);

	unsigned char cur_byte = 0;
	int bits = 0;
	int index = 0;

	init_showbps();
	set_showbps_start_ts();
	for(;!do_exit;)
	{
		fiddle(&fs);
		unsigned long long int a = GetCC();
		fiddle(&fs);
		unsigned long long int b = GetCC();
		fiddle(&fs);
		unsigned long long int c = GetCC();
		fiddle(&fs);
		unsigned long long int d = GetCC();

		int A = int(b - a);
		int B = int(d - c);

		cur_byte <<= 1;

		if (A >= B)
			cur_byte |= 1;
			
		bits++;

		if (bits == 8)
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

				index = 0;

				set_showbps_start_ts();
			}
		}
	}

	memset(bytes, 0x00, sizeof bytes);
	unlink(pid_file);

	delete p;

	return 0;
}
