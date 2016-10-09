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
#include <winscard.h>

const char *server_type = "server_smartcard v" VERSION;
const char *pid_file = PID_DIR "/server_smartcard.pid";

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
	printf("-o file   file to write entropy data to\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
	printf("-l file   log to file 'file'\n");
	printf("-L x      log level, 0=nothing, 255=all\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

double gen_entropy_data(void)
{
	double start;

	start = get_ts();

	/* arbitrary value:
	 * not too small so that there's room for noise
	 * not too large so that we don't sleep unnecessary
	 */
	usleep(100);

	return get_ts() - start;
}

int main(int argc, char *argv[])
{
	unsigned char bytes[4096];
	int index = 0;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *bytes_file = NULL;
	bool show_bps = false;
	std::string username, password;
	std::vector<std::string> hosts;
	int log_level = LOG_INFO;

	fprintf(stderr, "%s, (C) 2009-2015 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "hX:P:So:I:L:l:sn")) != -1)
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

			case 'i':
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

	DWORD rv = -1;
        SCARDCONTEXT hContext;
        if (SCARD_S_SUCCESS != (rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext)))
        	error_exit("SCardEstablishContext: %s", pcsc_stringify_error(rv));

        LPTSTR mszReaders;
        DWORD dwReaders, dwActiveProtocol;
#ifdef SCARD_AUTOALLOCATE
        dwReaders = SCARD_AUTOALLOCATE;

        if (SCARD_S_SUCCESS != (rv = SCardListReaders(hContext, NULL, (LPTSTR)&mszReaders, &dwReaders)))
        	error_exit("SCardListReaders: %s", pcsc_stringify_error(rv));
#else
        if (SCARD_S_SUCCESS != (rv = SCardListReaders(hContext, NULL, NULL, &dwReaders)))
        	error_exit("SCardListReaders: %s", pcsc_stringify_error(rv));

        mszReaders = calloc(dwReaders, sizeof char);
        if (SCARD_S_SUCCESS != (rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders)))
        	error_exit("SCardListReaders %s", pcsc_stringify_error(rv));
#endif
        dolog(LOG_INFO, "reader name: %s", mszReaders);

        SCARDHANDLE hCard;
        if (SCARD_S_SUCCESS != (rv = SCardConnect(hContext, mszReaders, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol)))
        	error_exit("SCardConnect %s", pcsc_stringify_error(rv));

        SCARD_IO_REQUEST pioSendPci;
        switch(dwActiveProtocol)
        {
                case SCARD_PROTOCOL_T0:
                        pioSendPci = *SCARD_PCI_T0;
                        break;

                case SCARD_PROTOCOL_T1:
                        pioSendPci = *SCARD_PCI_T1;
                        break;
        }

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

	init_showbps();
	set_showbps_start_ts();
	for(; !do_exit;)
	{

		BYTE pbRecvBuffer[258];
		BYTE cmdGET_CHALLENGE[] = { 0x00, 0x84, 0x00, 0x00, 0x08 };

		DWORD dwRecvLength = sizeof pbRecvBuffer;
                if (SCARD_S_SUCCESS != (rv = SCardTransmit(hCard, &pioSendPci, cmdGET_CHALLENGE, sizeof cmdGET_CHALLENGE, NULL, pbRecvBuffer, &dwRecvLength)))
                	error_exit("SCardTransmit %s", pcsc_stringify_error(rv));

		if (dwRecvLength == 2)
		{
			short code = (pbRecvBuffer[0] << 8) + pbRecvBuffer[1];

			if (code == 0x9000) // all fine, just no data
			{
				dolog(LOG_WARNING, "No data from card?!");
				continue;
			}

			error_exit("ISO 7816 error code: %04x", code);
		}
		else if (dwRecvLength == 10)
		{
			int code = (pbRecvBuffer[8] << 8) + pbRecvBuffer[9];

			if (code != 0x9000) // got data but also an error?
				error_exit("Got data but also an ISO 7816 error code: %04x", code);
		}

		int n_to_add = std::min(sizeof bytes - index, (size_t)8);
		memcpy(&bytes[index], pbRecvBuffer, n_to_add);
		index += n_to_add;

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

	memset(bytes, 0x00, sizeof bytes);
	unlink(pid_file);

	delete p;

	return 0;
}
