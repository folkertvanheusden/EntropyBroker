#include <arpa/inet.h>
#include <string>
#include <vector>
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
const char *pid_file = PID_DIR "/client_egd.pid";
const char *client_type = "client_egd " VERSION;

bool do_exit = false;

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	do_exit = true;
}

void egd_get__failure(int fd)
{
	unsigned char none = 0;

	if (WRITE(fd, &none, 1) != 1)
		dolog(LOG_INFO, "short write on egd client (# bytes)");
}

void egd_get(int fd, protocol *p, bool blocking)
{
	unsigned char n_bytes_to_get;

	if (READ(fd, &n_bytes_to_get, 1) != 1)
	{
		dolog(LOG_INFO, "short read on EGD client");
		return;
	}

	if (n_bytes_to_get == 0)
	{
		dolog(LOG_INFO, "client requesting 0 bytes");
		return;
	}

	int n_bits_to_get = n_bytes_to_get * 8;

	dolog(LOG_INFO, "will get %d bits (%sblocking)", n_bits_to_get, blocking?"":"non-");

	unsigned char *buffer = static_cast<unsigned char *>(malloc(n_bytes_to_get));
	if (!buffer)
		error_exit("Out of memory");
	lock_mem(buffer, n_bytes_to_get);

	int n_bytes = p -> request_bytes(buffer, n_bits_to_get, !blocking);
	if (n_bytes == 0)
		egd_get__failure(fd);
	else
	{
		unsigned char msg = std::min(255, n_bytes);
		if (!blocking && WRITE(fd, &msg, 1) != 1)
			dolog(LOG_INFO, "short write on egd client (# bytes)");
		else if (WRITE(fd, buffer, msg) != msg)
			dolog(LOG_INFO, "short write on egd client (data)");

		memset(buffer, 0x00, n_bytes);
	}

	unlock_mem(buffer, n_bytes);
	free(buffer);
}

void egd_entropy_count(int fd)
{
	unsigned int count = 9999;
	unsigned char reply[4];

	reply[0] = (count >> 24) & 255;
	reply[1] = (count >> 16) & 255;
	reply[2] = (count >> 8) & 255;
	reply[3] = count & 255;

	if (WRITE(fd, reply, 4) != 4)
		dolog(LOG_INFO, "short write on egd client");
}

void egd_put(int fd, protocol *p)
{
	unsigned char cmd[3];
	if (READ(fd, cmd, 3) != 3)
	{
		dolog(LOG_INFO, "EGD_put short read (1)");
		return;
	}

	int bit_cnt = (cmd[0] << 8) + cmd[1];
	dolog(LOG_INFO, "EGD client puts %d bits of entropy", bit_cnt);

	unsigned char byte_cnt = cmd[2];

	char buffer[256];
	lock_mem(buffer, sizeof buffer);
	if (byte_cnt > 0 && READ(fd, buffer, byte_cnt) != byte_cnt)
	{
		dolog(LOG_INFO, "EGD_put short read (2)");
		return;
	}

	(void)p -> message_transmit_entropy_data(reinterpret_cast<unsigned char *>(buffer), byte_cnt);

	memset(buffer, 0x00, sizeof buffer);
	unlock_mem(buffer, sizeof buffer);
}

void handle_client(int fd, protocol *p)
{
	for(;!do_exit;)
	{
		unsigned char egd_msg;

		if (READ(fd, &egd_msg, 1, &do_exit) != 1)
		{
			dolog(LOG_INFO, "EGD client disconnected");

			return;
		}

		if (egd_msg == 0)	// get entropy count
			egd_entropy_count(fd);
		else if (egd_msg == 1)	// get data, non blocking
			egd_get(fd, p, false);
		else if (egd_msg == 2)	// get data, blocking
			egd_get(fd, p, true);
		else if (egd_msg == 3)	// put data
			egd_put(fd, p);
	}
}

int open_unixdomain_socket(char *path, int nListen)
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
		error_exit("socket creation failed");

	if (bind(fd, (struct sockaddr *)&addr, len) == -1)
		error_exit("bind failed");

	if (listen(fd, nListen) == -1)
		error_exit("listen failed");

	return fd;
}

int open_tcp_socket(const char *adapter, int port, int nListen)
{
	return start_listen(adapter, port, nListen);
}

void help(void)
{
        printf("-I host   entropy_broker host to connect to\n");
        printf("          e.g. host\n");
        printf("               host:port\n");
        printf("               [ipv6 literal]:port\n");
        printf("          you can have multiple entries of this\n");
	printf("-d file   egd unix domain socket\n");
	printf("-t host   egd tcp host to listen on\n");
	printf("-T port   egd tcp port to listen on\n");
	printf("-l file   log to file 'file'\n");
	printf("-L x      log level, 0=nothing, 255=all\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

void start_child(int fd, bool do_not_fork, struct sockaddr *ca, std::vector<std::string> *hosts, std::string username, std::string password)
{
	if (fd != -1)
	{
		pid_t pid = 0;

		if (!do_not_fork)
			pid = fork();

		if (pid == 0)
		{
			protocol *p = new protocol(hosts, username, password, false, client_type, DEFAULT_COMM_TO);

			handle_client(fd, p);

			delete p;

			if (!do_not_fork)
				exit(0);
		}
		else if (pid == -1)
			error_exit("failed to fork");

		close(fd);
	}
}

int main(int argc, char *argv[])
{
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *uds = NULL;
	int u_listen_fd = -1, nListen = 5;
	std::string username, password;
	const char *egd_host = "0.0.0.0";
	int egd_port = -1;
	int t_listen_fd = -1;
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	printf("eb_client_egd v" VERSION ", (C) 2009-2017 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "t:T:hX:P:d:I:L:l:sn")) != -1)
	{
		switch(c)
		{
			case 't':
				egd_host = optarg;
				break;

			case 'T':
				egd_port =  atoi(optarg);
				if (egd_port < 1)
					error_exit("-T requires a value >= 1");
				break;

			case 'X':
				get_auth_from_file(optarg, username, password);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'd':
				uds = optarg;
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

	if (password.length() == 0 || username.length() == 0)
		error_exit("please set a non-empty username + password");

	if (hosts.empty())
		error_exit("no host to connect to selected");

	if (!uds && egd_port == -1)
		error_exit("no path for the unix domain socket selected, also no tcp listen port selected");

	(void)umask(0177);
	no_core();

	set_logging_parameters(log_console, log_logfile, log_syslog, log_level);

	if (uds != NULL)
		u_listen_fd = open_unixdomain_socket(uds, nListen);

	if (egd_port != -1)
		t_listen_fd = open_tcp_socket(egd_host, egd_port, nListen);

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

	for(; !do_exit;)
	{
		fd_set a_fds;
		FD_ZERO(&a_fds);

		if (u_listen_fd != -1)
			FD_SET(u_listen_fd, &a_fds);
		if (t_listen_fd != -1)
			FD_SET(t_listen_fd, &a_fds);

		if (select(std::max(u_listen_fd, t_listen_fd) + 1, &a_fds, NULL, NULL, NULL) == -1)
		{
			if (errno != EINTR)
				error_exit("select() failed");

			continue;
		}

		struct sockaddr addr;
		socklen_t addr_len = sizeof addr;

		if (u_listen_fd != -1 && FD_ISSET(u_listen_fd, &a_fds))
			start_child(accept(u_listen_fd, &addr, &addr_len), do_not_fork, &addr, &hosts, username, password);

		if (t_listen_fd != -1 && FD_ISSET(t_listen_fd, &a_fds))
			start_child(accept(t_listen_fd, &addr, &addr_len), do_not_fork, &addr, &hosts, username, password);
	}

	unlink(pid_file);
	dolog(LOG_INFO, "Finished");

	return 0;
}
