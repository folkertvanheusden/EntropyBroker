#include <arpa/inet.h>
#include <string>
#include <map>
#include <vector>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <errno.h>
#include <alsa/asoundlib.h>

const char *pid_file = PID_DIR "/eb_server_audio.pid";

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

#define DEFAULT_SAMPLE_RATE			11025
#define DEFAULT_CLICK_READ			(1 * DEFAULT_SAMPLE_RATE)

bool do_exit = false;

void sig_handler(int sig)
{
	signal(sig, SIG_IGN);

	fprintf(stderr, "Exit due to signal %d\n", sig);
	do_exit = true;
}

int setparams(snd_pcm_t *chandle, int sample_rate, snd_pcm_format_t *format, const char *cdevice)
{
	int err;
	snd_pcm_hw_params_t *ct_params;		/* templates with rate, format and channels */
	snd_pcm_hw_params_alloca(&ct_params);

	err = snd_pcm_hw_params_any(chandle, ct_params);
	if (err < 0)
		error_exit("Broken configuration for %s PCM: no configurations available: %s", cdevice, snd_strerror(err));

	/* Disable rate resampling */
	err = snd_pcm_hw_params_set_rate_resample(chandle, ct_params, 0);
	if (err < 0)
		error_exit("Could not disable rate resampling: %s", snd_strerror(err));

	/* Set access to SND_PCM_ACCESS_RW_INTERLEAVED */
	err = snd_pcm_hw_params_set_access(chandle, ct_params, SND_PCM_ACCESS_RW_INTERLEAVED);
	if (err < 0)
		error_exit("Could not set access to SND_PCM_ACCESS_RW_INTERLEAVED: %s", snd_strerror(err));

	/* Restrict a configuration space to have rate nearest to our target rate */
	err = snd_pcm_hw_params_set_rate_near(chandle, ct_params, (unsigned int *)&sample_rate, 0);
	if (err < 0)
		error_exit("Rate %iHz not available for %s: %s", sample_rate, cdevice, snd_strerror(err));

	/* Set sample format */
	*format = SND_PCM_FORMAT_S16_BE;
	err = snd_pcm_hw_params_set_format(chandle, ct_params, *format);
	if (err < 0)
	{
		*format = SND_PCM_FORMAT_S16_LE;
		err = snd_pcm_hw_params_set_format(chandle, ct_params, *format);
	}
	if (err < 0)
		error_exit("Sample format (SND_PCM_FORMAT_S16_BE and _LE) not available for %s: %s", cdevice, snd_strerror(err));

	/* Set stereo */
	err = snd_pcm_hw_params_set_channels(chandle, ct_params, 2);
	if (err < 0)
		error_exit("Channels count (%i) not available for %s: %s", 2, cdevice, snd_strerror(err));

	/* Apply settings to sound device */
	err = snd_pcm_hw_params(chandle, ct_params);
	if (err < 0)
		error_exit("Could not apply settings to sound device! %s", snd_strerror(err));

	return 0;
}

#define order(a, b)     (((a) == (b)) ? -1 : (((a) > (b)) ? 1 : 0))

void help(const char *cdevice)
{
	printf("-I host   entropy_broker host to connect to\n");
	printf("          e.g. host\n");
	printf("               host:port\n");
	printf("               [ipv6 literal]:port\n");
	printf("          you can have multiple entries of this\n");
	printf("-d dev    audio-device, default %s\n", cdevice);
	printf("-o file   file to write entropy data to\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
	printf("-l file   log to file 'file'\n");
	printf("-L x      log level, 0=nothing, 255=all\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

void recover_sound_dev(snd_pcm_t **chandle, bool is_open, const char *cdevice, snd_pcm_format_t *format)
{
	if (is_open)
		snd_pcm_close(*chandle);

	int err = -1;
	while ((err = snd_pcm_open(chandle, cdevice, SND_PCM_STREAM_CAPTURE, 0)) < 0 && !do_exit)
	{
		dolog(LOG_WARNING, "snd_pcm_open open error: %s (retrying)", snd_strerror(err));
		sleep(1);
	}

	if (!do_exit)
		setparams(*chandle, DEFAULT_SAMPLE_RATE, format, cdevice);
}

void main_loop(std::vector<std::string> * hosts, char *bytes_file, char show_bps, std::string username, std::string password, const char *cdevice)
{
	int n_to_do, bits_out=0, loop;
	char *dummy;
	static short psl=0, psr=0; /* previous samples */
	static char a=1; /* alternater */
	unsigned char byte_out=0;
	int input_buffer_size;
	char *input_buffer;
	snd_pcm_t *chandle;
	snd_pcm_format_t format;
	int err;
	unsigned char bytes[4096]; // 4096 * 8: 9992, must be less then 9999
	int bytes_out = 0;

	char server_type[128];
	snprintf(server_type, sizeof server_type, "eb_server_audio v" VERSION " %s", cdevice);

	protocol *p = NULL;
	if (!hosts -> empty())
		p = new protocol(hosts, username, password, true, server_type, DEFAULT_COMM_TO);

	lock_mem(bytes, sizeof bytes);

	recover_sound_dev(&chandle, false, cdevice, &format);

	init_showbps();
	set_showbps_start_ts();
	for(;!do_exit;)
	{
		char got_any = 0;

		input_buffer_size = snd_pcm_frames_to_bytes(chandle, DEFAULT_SAMPLE_RATE * 2);

		input_buffer = reinterpret_cast<char *>(malloc_locked(input_buffer_size));
		if (!input_buffer)
			error_exit("problem allocating %d bytes of memory", input_buffer_size);

		/* Discard the first data read */
		/* it often contains weird looking data - probably a click from */
		/* driver loading / card initialisation */
		snd_pcm_sframes_t garbage_frames_read = snd_pcm_readi(chandle, input_buffer, DEFAULT_SAMPLE_RATE);
		/* Make sure we aren't hitting a disconnect/suspend case */
		if (garbage_frames_read < 0)
		{
			dolog(LOG_INFO, "snd_pcm_readi: failed retrieving audio", snd_strerror(garbage_frames_read)); // FIXME

			if ((err = snd_pcm_recover(chandle, garbage_frames_read, 0)) < 0)
			{
				dolog(LOG_INFO, "snd_pcm_recover fail : %s", snd_strerror(err));

				dolog(LOG_INFO, "Failure retrieving sound from soundcard, re-opening device");

				recover_sound_dev(&chandle, true, cdevice, &format);
			}
		}

		/* Read a buffer of audio */
		n_to_do = DEFAULT_SAMPLE_RATE * 2;
		dummy = input_buffer;
		while (n_to_do > 0 && !do_exit)
		{
			snd_pcm_sframes_t frames_read = snd_pcm_readi(chandle, dummy, n_to_do);
			/* Make	sure we	aren't hitting a disconnect/suspend case */
			if (frames_read < 0)
				frames_read = snd_pcm_recover(chandle, frames_read, 0);
			/* Nope, something else is wrong. Bail.	*/
			if (frames_read == -1) 
			{
				if ((err = snd_pcm_recover(chandle, frames_read, 0)) < 0)
				{
					dolog(LOG_INFO, "snd_pcm_recover fail : %s", snd_strerror(err));

					dolog(LOG_INFO, "Failure retrieving sound from soundcard, re-opening device");

					recover_sound_dev(&chandle, true, cdevice, &format);
				}
			}
			else
			{
				n_to_do -= frames_read;
				dummy += frames_read;	
			}
		}

		/* de-biase the data */
		for(loop=0; loop<(DEFAULT_SAMPLE_RATE * 2/*16bits*/ * 2/*stereo*/ * 2) && !do_exit; loop+=8)
		{
			int w1, w2, w3, w4, o1, o2;

			if (format == SND_PCM_FORMAT_S16_BE)
			{
				w1 = (input_buffer[loop+0]<<8) + input_buffer[loop+1];
				w2 = (input_buffer[loop+2]<<8) + input_buffer[loop+3];
				w3 = (input_buffer[loop+4]<<8) + input_buffer[loop+5];
				w4 = (input_buffer[loop+6]<<8) + input_buffer[loop+7];
			}
			else
			{
				w1 = (input_buffer[loop+1]<<8) + input_buffer[loop+0];
				w2 = (input_buffer[loop+3]<<8) + input_buffer[loop+2];
				w3 = (input_buffer[loop+5]<<8) + input_buffer[loop+4];
				w4 = (input_buffer[loop+7]<<8) + input_buffer[loop+6];
			}

			/* Determine order of channels for each sample, subtract previous sample
			 * to compensate for unbalanced audio devices */
			o1 = order(w1-psl, w2-psr);
			o2 = order(w3-psl, w4-psr);
			if (a > 0)
			{
				psl = w3;
				psr = w4;
			}
			else
			{
				psl = w1;
				psr = w2;
			}

			/* If both samples have the same order, there is bias in the samples, so we
			 * discard them; if both channels are equal on either sample, we discard
			 * them too; additionally, alternate the sample we'll use next (even more
			 * bias removal) */
			if (o1 == o2 || o1 < 0 || o2 < 0)
			{
				a = -a;
			}
			else
			{
				/* We've got a random bit; the bit is either the order from the first or
				 * the second sample, determined by the alternator 'a' */
				char bit = (a > 0) ? o1 : o2;

				byte_out <<= 1;
				byte_out += bit;

				bits_out++;

				got_any = 1;

				if (bits_out>=8)
				{
					bytes[bytes_out++] = byte_out;

					if (bytes_out == sizeof bytes)
					{
						if (show_bps)
							update_showbps(sizeof bytes);

						if (bytes_file)
							emit_buffer_to_file(bytes_file, bytes, bytes_out);

						if (p && p -> message_transmit_entropy_data(bytes, bytes_out) == -1)
						{
							dolog(LOG_INFO, "connection closed");
							p -> drop();
						}

						set_showbps_start_ts();

						bytes_out = 0;
					}

					bits_out = 0;
				}
			}
		}

		if (!got_any)
			dolog(LOG_WARNING, "no bits in audio-stream, please make sure the recording channel is not muted");

		free_locked(input_buffer, input_buffer_size);
	}

	unlock_mem(bytes, sizeof bytes);

	if (!do_exit)
		snd_pcm_close(chandle);

	delete p;
}

int main(int argc, char *argv[])
{
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *bytes_file = NULL;
	bool show_bps = false;
	std::string username, password;
	const char *cdevice = "hw:1";				/* capture device */
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	fprintf(stderr, "eb_server_audio v" VERSION ", (C) 2009-2017 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "I:hX:P:So:d:L:l:sn")) != -1)
	{
		switch(c)
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

			case 'd':
				cdevice = optarg;
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
				help(cdevice);
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

	main_loop(&hosts, bytes_file, show_bps, username, password, cdevice);

	unlink(pid_file);

	fprintf(stderr, "program terminated\n");

	return 0;
}
