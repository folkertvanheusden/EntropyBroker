#include <string>
#include <pthread.h>
#include <vector>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>
#include <time.h>
#include <string>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef linux
#include <sys/syscall.h>
#endif

#include "defines.h"
#include "error.h"
#include "utils.h"
#include "log.h"
#include "kernel_prng_rw.h"
#include "my_pty.h"
#include "encrypt_stream.h"
#include "hasher.h"
#include "protocol.h"

#define MAX_LRAND48_GETS 250

pthread_mutexattr_t global_mutex_attr;

long double get_ts_ns()
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		error_exit("clock_gettime() failed");

	// start time is removed to allow more bits 'behind the dot'
	return (long double)(ts.tv_sec) + (long double)(ts.tv_nsec) / 1000000000.0;
}

double get_ts()
{
	struct timeval ts;

	if (gettimeofday(&ts, NULL) == -1)
		error_exit("gettimeofday failed");

	return double(ts.tv_sec) + double(ts.tv_usec) / 1000000.0;
}

int READ(int fd, char *whereto, size_t len, bool *do_exit)
{
	ssize_t cnt=0;

	while(len>0)
	{
		ssize_t rc;

		rc = read(fd, whereto, len);

		if (rc == -1)
		{
			if (do_exit && *do_exit)
				return -1;

			if (errno != EINTR && errno != EINPROGRESS && errno != EAGAIN)
				return -1;
		}
		else if (rc == 0)
		{
			break;
		}
		else
		{
			whereto += rc;
			len -= rc;
			cnt += rc;
		}
	}

	return cnt;
}

int READ(int fd, unsigned char *whereto, size_t len, bool *do_exit)
{
	return READ(fd, reinterpret_cast<char *>(whereto), len, do_exit);
}

int READ_TO(int fd, char *whereto, size_t len, double to, bool *do_exit)
{
	double end_ts = get_ts() + to;
	ssize_t cnt=0;

	while(len>0)
	{
		pollfd fds[1];
		double now_ts = get_ts();
		double time_left = end_ts - now_ts;
		ssize_t rc;

		if (time_left <= 0.0)
			return -1;

		fds[0].fd = fd;
		fds[0].events = POLLIN;

		int tv = time_left * 1000.0;
		rc = poll(fds, 1, tv);
		if (rc == -1)
		{
			if (do_exit && *do_exit)
				return -1;

			if (errno == EINTR || errno == EINPROGRESS || errno == EAGAIN)
				continue;

			return -1;
		}
		else if (rc == 0)
		{
			return 0;
		}

		if (fds[0].revents & (POLLERR|POLLHUP|POLLNVAL))
		{
			return -1;
		}

		if (fds[0].revents & POLLIN)
		{
			rc = read(fd, whereto, len);

			if (rc == -1)
			{
				if (errno == EINTR || errno == EINPROGRESS || errno == EAGAIN)
					continue;

				return -1;
			}
			else if (rc == 0)
			{
				return -1;
			}

			whereto += rc;
			len -= rc;
			cnt += rc;
		}
	}

	return cnt;
}

int READ_TO(int fd, unsigned char *whereto, size_t len, double to, bool *do_exit)
{
	return READ_TO(fd, reinterpret_cast<char *>(whereto), len, to, do_exit);
}

int WRITE(int fd, const char *whereto, size_t len, bool *do_exit)
{
	ssize_t cnt=0;

	while(len>0)
	{
		ssize_t rc;

		rc = write(fd, whereto, len);

		if (rc == -1)
		{
			if (do_exit && *do_exit)
				return -1;

			if (errno != EINTR && errno != EINPROGRESS && errno != EAGAIN)
				return -1;
		}
		else if (rc == 0)
		{
			return -1;
		}
		else
		{
			whereto += rc;
			len -= rc;
			cnt += rc;
		}
	}

	return cnt;
}

int WRITE(int fd, const unsigned char *whereto, size_t len, bool *do_exit)
{
	return WRITE(fd, reinterpret_cast<const char *>(whereto), len, do_exit);
}

int WRITE_TO(int fd, const char *whereto, size_t len, double to, bool *do_exit)
{
	double end_ts = get_ts() + to;
	ssize_t cnt=0;

	while(len>0)
	{
		pollfd fds[1];
		double now_ts = get_ts();
		double time_left = end_ts - now_ts;
		ssize_t rc;

		if (time_left <= 0.0)
			return -1;

		fds[0].fd = fd;
		fds[0].events = POLLOUT;

		int tv = time_left * 1000.0;
		rc = poll(fds, 1, tv);
		if (rc == -1)
		{
			if (do_exit && *do_exit)
				return -1;

			if (errno == EINTR || errno == EINPROGRESS || errno == EAGAIN)
				continue;

			return -1;
		}
		else if (rc == 0)
		{
			return -1;
		}

		if (fds[0].revents & POLLOUT) // should always evaluate to true at this point
		{
			rc = write(fd, whereto, len);

			if (rc == -1)
			{
				if (errno != EINTR && errno != EINPROGRESS && errno != EAGAIN)
					return -1;
			}
			else if (rc == 0)
			{
				return -1;
			}
			else
			{
				whereto += rc;
				len -= rc;
				cnt += rc;
			}
		}
	}

	return cnt;
}

int WRITE_TO(int fd, const unsigned char *whereto, size_t len, double to, bool *do_exit)
{
	return WRITE_TO(fd, reinterpret_cast<const char *>(whereto), len, to, do_exit);
}

int connect_to(const char *host, int portnr)
{
	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    // Allow IPv4 or IPv6
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;    // For wildcard IP address
	hints.ai_protocol = 0;          // Any protocol
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	char portnr_str[8];
	snprintf(portnr_str, sizeof portnr_str, "%d", portnr);

	struct addrinfo *result;
	int rc = getaddrinfo(host, portnr_str, &hints, &result);
	if (rc != 0)
		error_exit("Problem resolving %s: %s\n", host, gai_strerror(rc));

	for(struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next)
	{
		int fd = socket(rp -> ai_family, rp -> ai_socktype, rp -> ai_protocol);
		if (fd == -1)
			continue;

		if (connect(fd, rp -> ai_addr, rp -> ai_addrlen) == 0)
		{
			freeaddrinfo(result);

			return fd;
		}

		close(fd);
	}

	freeaddrinfo(result);

	return -1;
}

void disable_nagle(int fd)
{
	int disable = 1;

	// EBADF might happen if a connection was closed just before this call
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char *>(&disable), sizeof disable) == -1 && errno != EBADF)
		error_exit("setsockopt(IPPROTO_TCP, TCP_NODELAY) failed (fd: %d)", fd);
}

void enable_tcp_keepalive(int fd)
{
	int keep_alive = 1;

	// EBADF might happen if a connection was closed just before this call
	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<char *>(&keep_alive), sizeof keep_alive) == -1 && errno != EBADF)
		error_exit("problem setting KEEPALIVE (fd: %d)", fd);
}

void check_rand_state()
{
	static int n_random_retrieved = 0;

	if (--n_random_retrieved < 0)
	{
		unsigned short seed16v[3];

		kernel_rng_read_non_blocking(reinterpret_cast<unsigned char *>(seed16v), sizeof seed16v);
		seed48(seed16v);

		n_random_retrieved = MAX_LRAND48_GETS;
	}
}

double mydrand()
{
	check_rand_state();

	return drand48();
}

int myrand()
{
	check_rand_state();

	return lrand48();
}

int myrand(int max)
{
	check_rand_state();

	return int(drand48() * double(max));
}

void write_pid(const char *file)
{
	FILE *fh = fopen(file, "w");
	if (!fh)
		error_exit("Failed to write PID-file %s", file);

	fprintf(fh, "%d\n", getpid());

	fclose(fh);
}

void close_fds()
{
	for(int fd=3; fd<50; fd++)
		close(fd);
}

void start_process(const char *shell, const char *cmd, int *fd, pid_t *pid)
{
	int fd_slave;

	/* allocate pseudo-tty & fork*/
	*pid = get_pty_and_fork(fd, &fd_slave);
	if (*pid == -1)
		error_exit("Cannot fork and allocate pty");

	/* child? */
	if (*pid == 0)
	{
		setsid();

		/* reset signal handler for SIGTERM */
		signal(SIGTERM, SIG_DFL);

		/* connect slave-fd to stdin/out/err */
		close(0);
		close(1);
		close(2);
		dup(fd_slave);
		dup(fd_slave);
		dup(fd_slave);
		close_fds();

		/* start process */
		if (-1 == execlp(shell, shell, "-c", cmd, NULL))
			error_exit("cannot execlp(%s -c '%s')", shell, cmd);

		exit(1);
	}

	close(fd_slave);
}

void no_core()
{
#ifndef _DEBUG
	struct rlimit rlim = { 0, 0 };
	if (setrlimit(RLIMIT_CORE, &rlim) == -1)
		error_exit("setrlimit(RLIMIT_CORE) failed");
#endif
}

void lock_mem(void *p, int size)
{
	static bool notified_err = false;

	if (mlock(p, size) == -1)
	{
		if (!notified_err)
		{
			dolog(LOG_WARNING, "mlock failed");

			notified_err = true;
		}
	}
}

void unlock_mem(void *p, int size)
{
	static bool notified_err = false;

	if (munlock(p, size) == -1)
	{
		if (!notified_err)
		{
			dolog(LOG_CRIT, "mlock failed");

			notified_err = true;
		}
	}
}

void hexdump(unsigned char *in, int n)
{
	for(int index=0; index<n; index++)
		printf("%02x ", in[index]);

	printf("\n");
}

void split_resource_location(std::string in, std::string & host, int & port)
{
	char *copy = strdup(in.c_str());

	port = DEFAULT_BROKER_PORT;

	if (copy[0] == '[')	// ipv6 literal address
	{
		char *end = strchr(copy, ']');
		if (!end)
			error_exit("'%s' is not a valid ipv6 literal (expecting closing ']')", in.c_str());

		*end = 0x00;

		host.assign(&copy[1]);

		if (end[1] == ':') // port number following
			port = atoi(&end[1]);
	}
	else
	{
		char *colon = strchr(copy, ':');
		if (colon)
		{
			*colon = 0x00;
			port = atoi(colon + 1);
		}

		host.assign(copy);
	}

	free(copy);
}

void set_fd_nonblocking(int fd)
{
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1)
		error_exit("problem setting fd %d non-blocking");
}

int get_local_port(int fd)
{
	struct sockaddr_in6 addr;
	socklen_t addr_len = sizeof addr;

	if (getsockname(fd, (struct sockaddr *)&addr, &addr_len) == -1)
		return -1;

	return ntohs(addr.sin6_port);
}

std::string get_endpoint_name(int fd)
{
	char buffer[4096] = { "?" };
	struct sockaddr_in6 addr;
	socklen_t addr_len = sizeof addr;

	if (getpeername(fd, (struct sockaddr *)&addr, &addr_len) == -1)
		snprintf(buffer, sizeof buffer, "[FAILED TO FIND NAME OF %d: %s (1)]", fd, strerror(errno));
	else
	{
		char buffer2[4096];

		if (inet_ntop(AF_INET6, &addr.sin6_addr, buffer2, sizeof buffer2))
			snprintf(buffer, sizeof buffer, "[%s]:%d", buffer2, ntohs(addr.sin6_port));
		else
			snprintf(buffer, sizeof buffer, "[FAILED TO FIND NAME OF %d: %s (1)]", fd, strerror(errno));
	}

	return std::string(buffer);
}

void pthread_check(int rc, const char *name, int ok[])
{
	if (rc)
	{
		bool found = false;
		int index=0;
		while(ok[index])
		{
			if (ok[index] == rc)
			{
				found = true;
				break;
			}
		}

		if (!found)
		{
			errno = rc;
			error_exit("%s failed");
		}
	}
}

void pthread_check(int rc, const char *name)
{
	int ok[] = { 0 };

	pthread_check(rc, name, ok);
}

void my_mutex_lock(pthread_mutex_t *mutex)
{
	pthread_check(pthread_mutex_lock(mutex), "pthread_mutex_lock");
}

void my_mutex_unlock(pthread_mutex_t *mutex)
{
	pthread_check(pthread_mutex_unlock(mutex), "pthread_mutex_unlock");
}

void my_Assert(bool flag, int line, const char *file)
{
	if (flag == false)
		error_exit("assert failed in %s:%d", file, line);
}

void my_Assert2(bool flag, int line, const char *file, int debug_value)
{
	if (flag == false)
		error_exit("assert failed in %s:%d (%d)", file, line, debug_value);
}

// *BSD need a different implemenation for this
void set_thread_name(std::string name)
{
	//#ifdef linux
#if 0 // on ubuntu 10.04.4 this does not work (pthread_setname_np unknown)
	char *dummy = strdup(("eb:" + name).c_str());
	if (!dummy)
		error_exit("set_thread_name: out of memory");

	if (name.length() > 15)
	{
		dolog(LOG_DEBUG, "Truncating thread name '%s' to 16 characters", dummy);
		dummy[16] = 0x00;
	}

	// ignore pthread errors: at least under helgrind this would always fail
	int rc = pthread_setname_np(pthread_self(), dummy);
	if (rc)
		dolog(LOG_WARNING, "set_thread_name(%s) failed: %s (%d)", dummy, strerror(rc), rc);

	free(dummy);
#endif
}

// *BSD need a different implemenation for this
std::string get_thread_name(pthread_t *thread)
{
	//#ifdef linux
#if 0 // on ubuntu 10.04.4 this does not work (pthread_setname_np unknown)
	char buffer[4096];

	pthread_check(pthread_getname_np(*thread, buffer, sizeof buffer), "pthread_getname_np");

	return std::string(buffer);
#endif
	return std::string("?");
}

std::string get_current_thread_name()
{
	pthread_t tid = pthread_self();

	return get_thread_name(&tid);
}

void my_yield()
{
	// sched_yield

	pthread_check(pthread_yield(), "pthread_yield");
}

bool file_exist(const char *file)
{
	struct stat st;

	if (stat(file, &st) == -1)
	{
		if (errno == ENOENT)
			return false;

		error_exit("stat on %s failed", file);
	}

	return true;
}

void split_string(const char *in, const char *split, char ***out, int *n_out)
{
	int split_len = strlen(split);
	char *copy_in = strdup(in), *dummy = copy_in;

	for(;;)
	{
		char *next = NULL;

		(*n_out)++;
		*out = reinterpret_cast<char **>(realloc(*out, *n_out * sizeof(char *)));

		next = strstr(copy_in, split);
		if (!next)
		{
			(*out)[*n_out - 1] = strdup(copy_in);
			break;
		}

		*next = 0x00;

		(*out)[*n_out - 1] = strdup(copy_in);

		copy_in = next + split_len;
	}

	free(dummy);
}

std::vector<std::string> split_string(std::string in, std::string split)
{
	char **out = NULL;
	int n_out = 0;

	split_string(in.c_str(), split.c_str(), &out, &n_out);

	std::vector<std::string> list_out;

	for(int index=0; index<n_out; index++)
	{
		list_out.push_back(out[index]);
		free(out[index]);
	}

	free(out);

	return list_out;
}

unsigned int uchar_to_uint(unsigned char *in)
{
	return (in[0] << 24) + (in[1] << 16) + (in[2] << 8) + in[3];
}

bool recv_uint(int fd, unsigned int *value, double to)
{
	unsigned char buffer[4] = { 0 };

	if (READ_TO(fd, buffer, 4, to) != 4)
		return false;

	*value = uchar_to_uint(buffer);

	return true;
}

void uint_to_uchar(unsigned int value, unsigned char *out)
{
	out[0] = (value >> 24) & 255;
	out[1] = (value >> 16) & 255;
	out[2] = (value >>  8) & 255;
	out[3] = (value      ) & 255;
}

bool send_uint(int fd, unsigned int value, double to)
{
	unsigned char buffer[4];

	uint_to_uchar(value, buffer);

	if (WRITE_TO(fd, buffer, 4, to) != 4)
		return false;

	return true;
}

#ifdef linux
pid_t gettid()
{
	pid_t tid = (pid_t) syscall (SYS_gettid);

	return tid;
}
#else
#define gettid() 0
#endif

void *malloc_locked(size_t n)
{
	void *p = malloc(n);

	if (p)
		lock_mem(p, n);

	return p;
}

void free_locked(void *p, size_t n)
{
	if (p)
	{
		memset(p, 0x00, n);

		unlock_mem(p, n);
	}

	free(p);
}

std::string format(const char *fmt, ...)
{
	char *buffer = NULL;
	va_list ap;

	va_start(ap, fmt);
	(void)vasprintf(&buffer, fmt, ap);
	va_end(ap);

	std::string result = buffer;
	free(buffer);

	return result;
}

std::string time_to_str(time_t t)
{
	if (t == 0)
		return "n/a";

	struct tm *tm = localtime(&t);

	char time_buffer[128];
	strftime(time_buffer, sizeof time_buffer, "%a, %d %b %Y %T %z", tm);

	return std::string(time_buffer);
}

bool get_bool(FILE *fh, bool *value)
{
	int rc = fgetc(fh);

	if (rc < 0)
		return false;

	if (rc)
		*value = true;
	else
		*value = false;

	return true;
}

bool get_int(FILE *fh, int *value)
{
	unsigned char buffer[4];

	if (fread((char *)buffer, 4, 1, fh) != 1)
		return false;

	*value = (buffer[0] << 24) + (buffer[1] << 16) + (buffer[2] << 8) + buffer[3];

	return true;
}

// assuming 2x 32bit ints and 64bit long long int
bool get_long_long_int(FILE *fh, long long int *value)
{
	unsigned int i1, i2;

	if (!get_int(fh, (int *)&i1))
		return false;
	if (!get_int(fh, (int *)&i2))
		return false;

	*value = ((long long int)i1 << 32) + i2;

	return true;
}

void put_bool(FILE *fh, bool value)
{
	fputc(value ? 1 : 0, fh);
}

void put_int(FILE *fh, int value)
{
	unsigned char buffer[4];

	buffer[0] = (value >> 24) & 255;
	buffer[1] = (value >> 16) & 255;
	buffer[2] = (value >>  8) & 255;
	buffer[3] = (value      ) & 255;

	if (fwrite((char *)buffer, 4, 1, fh) != 1)
		error_exit("problem writing to data_store_int dump-file");
}

void put_long_long_int(FILE *fh, long long int value)
{
	put_int(fh, value >> 32);
	put_int(fh, value & 0xffffffff);
}

int start_listen(const char *adapter, int portnr, int listen_queue_size)
{
	int fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (fd == -1)
		error_exit("failed creating socket");

#ifdef TCP_TFO
	int qlen = listen_queue_size;
	if (setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen)) == -1)
		error_exit("Setting TCP_FASTOPEN on server socket failed");
#endif

	int reuse_addr = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&reuse_addr), sizeof reuse_addr) == -1)
		error_exit("setsockopt(SO_REUSEADDR) failed");

	struct sockaddr_in6 server_addr;

	int server_addr_len = sizeof server_addr;

	memset(reinterpret_cast<char *>(&server_addr), 0x00, server_addr_len);
	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_port = htons(portnr);

	if (!adapter || strcmp(adapter, "0.0.0.0") == 0)
		server_addr.sin6_addr = in6addr_any;
	else if (inet_pton(AF_INET6, adapter, &server_addr.sin6_addr) == 0)
	{
		fprintf(stderr, "\n");
		fprintf(stderr, " * inet_pton(%s) failed: %s\n", adapter, strerror(errno));
		fprintf(stderr, " * If you're trying to use an IPv4 address (e.g. 192.168.0.1 or so)\n");
		fprintf(stderr, " * then do not forget to place ::FFFF: in front of the address,\n");
		fprintf(stderr, " * e.g.: ::FFFF:192.168.0.1\n\n");
		error_exit("listen socket initialisation failure: did you configure a correct listen adapter? (run with -n for details)");
	}

	if (bind(fd, (struct sockaddr *)&server_addr, server_addr_len) == -1)
		error_exit("bind([%s]:%d) failed", adapter, portnr);

	if (listen(fd, listen_queue_size) == -1)
		error_exit("listen(%d) failed", listen_queue_size);

	return fd;
}
