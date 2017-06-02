#include <arpa/inet.h>
#include <string>
#include <map>
#include <vector>
#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "defines.h"
#include "error.h"
#include "random_source.h"
#include "log.h"
#include "encrypt_stream.h"
#include "hasher.h"
#include "protocol.h"
#include "server_utils.h"
#include "utils.h"
#include "statistics.h"
#include "statistics_global.h"
#include "statistics_user.h"
#include "users.h"
#include "auth.h"

const char *server_type = "server_v4l v" VERSION;
const char *pid_file = PID_DIR "/server_v4l.pid";

bool do_exit = false;

#define RES_LOW  0
#define RES_HIGH 127

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	do_exit = true;
}

void open_dev(char *dev_name, int *fd, unsigned char **io_buffer, int *io_buffer_len)
{
	*fd = open(dev_name, O_RDWR);
	if (*fd == -1)
		return;

	struct v4l2_capability cap;
	memset(&cap, 0x00, sizeof cap);
	if (ioctl(*fd, VIDIOC_QUERYCAP, &cap) == -1)
		error_exit("Cannot VIDIOC_QUERYCAP");
	else
	{
		dolog(LOG_DEBUG, "Device %s is:", dev_name);
		dolog(LOG_DEBUG, " %s %s %s", cap.driver, cap.card, cap.bus_info);
		dolog(LOG_DEBUG, " version: %d %d %d", (cap.version >> 16) & 255, (cap.version >> 8) & 255, cap.version & 255);
		if ((cap.capabilities & V4L2_CAP_VIDEO_CAPTURE) == 0)
			error_exit("Video4linux device cannot capture video");
	}

	struct v4l2_format fmt;
	memset(&fmt, 0x00, sizeof fmt);
	fmt.type                = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUV420;
	if (ioctl(*fd, VIDIOC_G_FMT, &fmt) == -1)
		error_exit("ioctl(VIDIOC_G_FMT) failed");
	char format[5];
	memcpy(format, &fmt.fmt.pix.pixelformat, 4);
	format[4]=0x00;
	dolog(LOG_DEBUG, " %dx%d: %d/%s\n", fmt.fmt.pix.width, fmt.fmt.pix.height, fmt.type, format);

	fmt.type                = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (ioctl(*fd, VIDIOC_S_FMT, &fmt) == -1)
		error_exit("ioctl(VIDIOC_S_FMT) failed");

	struct v4l2_requestbuffers req;
	memset(&req, 0x00, sizeof req);
	req.count  = 1;
	req.type   = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory = V4L2_MEMORY_MMAP;
	if (ioctl(*fd, VIDIOC_REQBUFS, &req) == -1)
		error_exit("ioctl(VIDIOC_REQBUFS) failed");

	struct v4l2_buffer buf;
	memset(&buf, 0x00, sizeof buf);
	buf.type        = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	buf.memory      = V4L2_MEMORY_MMAP;
	buf.index       = 0;
	if (ioctl(*fd, VIDIOC_QUERYBUF, &buf) == -1)
		error_exit("ioctl(VIDIOC_QUERYBUF) failed");

	if (ioctl(*fd, VIDIOC_QBUF, &buf) == -1)
		error_exit("ioctl(VIDIOC_QBUF) failed");

	enum v4l2_buf_type buf_type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (ioctl(*fd, VIDIOC_STREAMON, &buf_type) == -1)
		error_exit("ioctl(VIDIOC_STREAMON) failed");

	*io_buffer_len = buf.length;
	dolog(LOG_DEBUG, "%d bytes", *io_buffer_len);
	*io_buffer = static_cast<unsigned char *>(mmap(NULL, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, buf.m.offset));
	if (!*io_buffer)
		dolog(LOG_CRIT, "mmap() failed %s", strerror(errno));
}

void close_device(int fd, unsigned char *p, int p_len)
{
	munmap(p, p_len);

	close(fd);
}

void take_picture(int fd, struct v4l2_buffer *buf)
{
	if (ioctl(fd, VIDIOC_DQBUF, buf) == -1)
		dolog(LOG_CRIT, "VIDIOC_DQBUF failed %s", strerror(errno));
}

void untake_picture(int fd, struct v4l2_buffer *buf)
{
	if (ioctl(fd, VIDIOC_QBUF, buf) == -1)
		dolog(LOG_CRIT, "VIDIOC_QBUF failed %s", strerror(errno));
}

void help(void)
{
	printf("-I host   entropy_broker host to connect to\n");
        printf("          e.g. host\n");
        printf("               host:port\n");
        printf("               [ipv6 literal]:port\n");
        printf("          you can have multiple entries of this\n");
	printf("-d x   device to use\n");
	printf("-o file   file to write entropy data to (mututal exclusive with -d)\n");
	printf("-f x   skip x frames before processing images (in case the device\n");
	printf("       needs a few frames to settle)\n");
	printf("-l file   log to file 'file'\n");
	printf("-L x      log level, 0=nothing, 255=all\n");
	printf("-s        log to syslog\n");
	printf("-n     do not fork\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int main(int argc, char *argv[])
{
	int device_settle = 25;
	int c;
	unsigned char *img1, *img2, *unbiased;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *device = NULL;
	char *bytes_file = NULL;
	int loop;
	bool show_bps = false;
	std::string username, password;
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	fprintf(stderr, "%s, (C) 2009-2017 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "hSX:P:f:o:I:d:L:l:sn")) != -1)
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

			case 'f':
				device_settle = atoi(optarg);
				if (device_settle < 0)
					error_exit("-f requires a value >= 0");
				break;

			case 'o':
				bytes_file = optarg;
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

			default:
				help();
				return 1;
		}
	}

	if (!hosts.empty() && (username.length() == 0 || password.length() == 0))
		error_exit("please select a file with authentication parameters (username + password) using the -X switch");

	if (hosts.empty() && !bytes_file)
		error_exit("no host to connect to or file to write to given");

	if (!device)
		error_exit("Please select a video4linux video device (a webcam, tv-card, etc.)\ne.g.: -d /dev/vide0");

	(void)umask(0177);
	no_core();

	set_logging_parameters(log_console, log_logfile, log_syslog, log_level);

	signal(SIGHUP , SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);
	signal(SIGPIPE, SIG_IGN);

	if (!do_not_fork)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed - out of resources?");
	}

	write_pid(pid_file);

	protocol *p = NULL;
	if (!hosts.empty())
		p = new protocol(&hosts, username, password, true, server_type, DEFAULT_COMM_TO);

	/* open device */
	int fd = -1;
	unsigned char *io_buffer = NULL;
	int io_buffer_len = -1;
	open_dev(device, &fd, &io_buffer, &io_buffer_len);
	if (fd == -1)
		error_exit("failure opening %s", device);

	/* let device settle */
	dolog(LOG_DEBUG, "waiting for device to settle");
	for(loop=0; loop<device_settle; loop++)
	{
		struct v4l2_buffer buf;
		memset(&buf, 0x00, sizeof buf);
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;

		take_picture(fd, &buf);
		untake_picture(fd, &buf);
	}

	init_showbps();
	set_showbps_start_ts();

	unsigned char cur_byte = 0;
	for(;!do_exit;)
	{
		img1 = reinterpret_cast<unsigned char *>(malloc_locked(io_buffer_len));
		img2 = reinterpret_cast<unsigned char *>(malloc_locked(io_buffer_len));
		unbiased = reinterpret_cast<unsigned char *>(malloc_locked(io_buffer_len));
		if (!img1 || !img2 || !unbiased)
			error_exit("out of memory");
		struct v4l2_buffer buf;

		/* take pictures */
		dolog(LOG_DEBUG, "Smile!");
		memset(&buf, 0x00, sizeof buf);
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		take_picture(fd, &buf);
		memcpy(img1, io_buffer, io_buffer_len);
		untake_picture(fd, &buf);
		//
		memset(&buf, 0x00, sizeof buf);
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		take_picture(fd, &buf);
		memcpy(img2, io_buffer, io_buffer_len);
		untake_picture(fd, &buf);

		/* unbiase */
		dolog(LOG_DEBUG, "Filtering...");
		int nunbiased=0, nbits = 0;
		for(loop=0; loop<io_buffer_len; loop+=2)
		{
			/* calculate difference between the images */
			int diff1 = abs(img2[loop + 0] - img1[loop + 0]);
			int diff2 = abs(img2[loop + 1] - img1[loop + 1]);

			/* if the 2 difference are not correlated, add bit */
			if ((diff1 & 1) != (diff2 & 1))
			{
				cur_byte <<= 1;

				if (diff1 & 1)
					cur_byte |= 1;

				nbits++;

				if (nbits == 8)
				{
					unbiased[nunbiased++] = cur_byte;

					nbits = 0;
				}
			}
		}

		free_locked(img2, io_buffer_len);
		free_locked(img1, io_buffer_len);

		dolog(LOG_DEBUG, "got %d bytes of entropy", nunbiased);

		if (nunbiased > 0)
		{
			if (show_bps)
				update_showbps(nunbiased);

			if (bytes_file)
				emit_buffer_to_file(bytes_file, unbiased, nunbiased);

			if (p)
			{
				unsigned char *tempp = unbiased;
				int count = nunbiased;
				while(count > 0)
				{
					int n_to_do = std::min(count, 4096);

					if (p -> message_transmit_entropy_data(tempp, n_to_do, &do_exit) == -1)
					{
						dolog(LOG_INFO, "connection closed");
						p -> drop();
						break;
					}

					tempp += n_to_do;
					count -= n_to_do;
				}
			}

			set_showbps_start_ts();
		}

		free_locked(unbiased, io_buffer_len);
	}

	dolog(LOG_DEBUG, "Cleaning up");
	close_device(fd, io_buffer, io_buffer_len);

	delete p;

	unlink(pid_file);

	return 0;
}
