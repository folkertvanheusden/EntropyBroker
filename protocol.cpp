#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <string>
#include <map>
#include <vector>

#include "defines.h"
#include "error.h"
#include "random_source.h"
#include "log.h"
#include "utils.h"
#include "math.h"
#include "encrypt_stream.h"
#include "hasher.h"
#include "hasher_type.h"
#include "stirrer.h"
#include "stirrer_type.h"
#include "fips140.h"
#include "scc.h"
#include "kernel_prng_io.h"
#include "server_utils.h"
#include "protocol.h"
#include "pool_crypto.h"
#include "pool.h"
#include "pools.h"
#include "statistics.h"
#include "statistics_global.h"
#include "statistics_user.h"
#include "users.h"
#include "auth.h"

int recv_length_data(int fd, char **data, unsigned int *len, double to)
{
	if (!recv_uint(fd, len, to))
		return -1;

	if (*len == 0)
		*data = NULL;
	else if (*len > 100 * 1024 * 1024) // TODO there now is a limit on the data transmitted
		return -1;
	else
	{
		*data = reinterpret_cast<char *>(malloc(*len + 1));
		if (!*data)
		{
			dolog(LOG_WARNING, "Cannot allocate %d bytes of memory (amount of data to be transmitted by fd: %d)", *len + 1, fd);
			return -1;
		}

		if (READ_TO(fd, *data, int(*len), to) != int(*len))
		{
			free(*data);
			*data = NULL;

			return -1;
		}

		(*data)[*len] = 0x00;
	}

	return 0;
}

int send_length_data(int fd, const char *data, unsigned int len, double to)
{
	if (!send_uint(fd, len, to))
		return -1;

	if (len > 0 && WRITE_TO(fd, data, int(len), to) != int(len))
		return -1;

	return 0;
}

void make_msg(unsigned char *where_to, unsigned int code, unsigned int value)
{
	if (code > 9999)
		error_exit("invalid code: %d", code);

	snprintf(reinterpret_cast<char *>(where_to), 5, "%04d", code);

	uint_to_uchar(value, &where_to[4]);
}

void calc_ivec(const char *password, long long unsigned int rnd, long long unsigned int counter, size_t ivec_size, unsigned char *dest)
{
	unsigned char *prnd = reinterpret_cast<unsigned char *>(&rnd);
	unsigned char *pcnt = reinterpret_cast<unsigned char *>(&counter);

	memset(dest, 0x00, ivec_size);
	memcpy(dest, password, std::min(strlen(password), ivec_size));

	unsigned int index_dest = 0, index_rnd = 0, rnd_len = sizeof rnd;
	while(index_dest < ivec_size)
	{
		dest[index_dest] ^= prnd[index_rnd];
		dest[index_dest] ^= pcnt[index_rnd];
		index_dest++;
		index_rnd++;

		if (index_rnd == rnd_len)
			index_rnd = 0;
	}
}

protocol::protocol(std::vector<std::string> *hosts_in, std::string username_in, std::string password_in, bool is_server_in, std::string type_in, double comm_time_out_in) : hosts(hosts_in), username(username_in), password(password_in), is_server(is_server_in), type(type_in), comm_time_out(comm_time_out_in)
{
	host_index = 0;

	stream_cipher = NULL;
	mac_hasher = NULL;

        socket_fd = -1;
        sleep_9003 = 300;

	pingnr = 0;

        ivec_counter = 0;
	challenge = 13;

	max_get_put_size = 1249;
}

protocol::~protocol()
{
	if (socket_fd != -1)
	{
		unsigned char logout_msg[8] = { 0 };

		make_msg(logout_msg, 9999, 0); // 9999 = logout
		(void)WRITE_TO(socket_fd, logout_msg, 8, comm_time_out);

		close(socket_fd);
	}

	delete stream_cipher;
	delete mac_hasher;
}

void protocol::error_sleep(int count)
{
	long int sleep_micro_seconds = myrand(count * 1000000) + 1;

	dolog(LOG_WARNING, "Failed connecting (%s), sleeping for %f seconds", strerror(errno), double(sleep_micro_seconds) / 1000000.0);

	usleep((long)sleep_micro_seconds);
}

reconnect_status_t protocol::reconnect_server_socket(bool *do_exit)
{
	reconnect_status_t rc = RSS_FAIL;

	char connect_msg = 0;

	// connect to server
	if (socket_fd == -1)
	{
		rc = RSS_NEW_CONNECTION;

		connect_msg = 1;

		delete stream_cipher;
		stream_cipher = NULL;

		delete mac_hasher;
		mac_hasher = NULL;

		unsigned int host_try_count = 0;
		int count = 1;
		std::string cipher_data, mac_hash;
		for(;;)
		{
			std::string host;
			int port = DEFAULT_BROKER_PORT;
			split_resource_location(hosts -> at(host_index), host, port);

			dolog(LOG_INFO, "Connecting to %s:%d", host.c_str(), port);

			socket_fd = connect_to(host.c_str(), port);
			if (socket_fd != -1)
			{
				if (auth_client_server(socket_fd, 10, username, password, &challenge, is_server, type, cipher_data, mac_hash, &max_get_put_size) == 0)
					break;

				close(socket_fd);
				socket_fd = -1;
			}

			if (do_exit && *do_exit)
				return RSS_FAIL;

			host_index++;
			if (host_index == hosts -> size())
			{
				host_index = 0;

				error_sleep(count);
			}
			else
			{
				dolog(LOG_WARNING, "Failed to connect to %s:%d (%s), continuing with next host", host.c_str(), port, strerror(errno));
			}

			host_try_count++;
			if (host_try_count == hosts -> size())
				dolog(LOG_WARNING, "All hosts are not reachable, still trying");

			if (count < 16)
				count++;
		}

		stream_cipher = encrypt_stream::select_cipher(cipher_data);

		unsigned char ivec[stream_cipher -> get_ivec_size()] = { 0 };
		calc_ivec(password.c_str(), challenge, 0, stream_cipher -> get_ivec_size(), ivec);
#ifdef CRYPTO_DEBUG
		printf("IVEC: "); hexdump(ivec, 8);
#endif

		unsigned char *pw_char = reinterpret_cast<unsigned char *>(const_cast<char *>(password.c_str()));
		stream_cipher -> init(pw_char, password.length(), ivec);

		mac_hasher = hasher::select_hasher(mac_hash);
	}
	else
	{
		rc = RSS_STILL_CONNECTED;
	}

	if (connect_msg)
		dolog(LOG_INFO, "Connected");

	return rc;
}

int protocol::sleep_interruptable(double how_long, bool *do_exit)
{
	if (socket_fd == -1)
		return -1;

	int rc = -1;
	fd_set rfds;

	for(;;)
	{
		FD_ZERO(&rfds);
		FD_SET(socket_fd, &rfds);

		struct timeval tv;
		tv.tv_sec = how_long;
		tv.tv_usec = (how_long - double(tv.tv_sec)) * 1000000.0;

		rc = select(socket_fd + 1, &rfds, NULL, NULL, &tv);
		if (do_exit && *do_exit)
			return -1;
		if (rc != -1 || errno != EINTR)
			break;
	}

	if (rc > 0 && FD_ISSET(socket_fd, &rfds))
	{
		char buffer[8];

		if (READ_TO(socket_fd, buffer, 8, comm_time_out, do_exit) != 8)
		{
			dolog(LOG_INFO, "error receiving unsollicited message");
			return -1;
		}
		buffer[4] = 0x00; // don't care about the value

		if (memcmp(buffer, "0010", 4) == 0)
			dolog(LOG_INFO, "Broker requests for data");
		if (memcmp(buffer, "0009", 4) == 0)
			dolog(LOG_INFO, "Broker informs about data being available");
		else if (memcmp(buffer, "9004", 4) != 0)
			dolog(LOG_WARNING, "Unexpected message '%s' received from broker! (1)", buffer);
		else
			dolog(LOG_WARNING, "Unexpected message '%s' received from broker! (2)", buffer);
	}

	return 0;
}

int protocol::message_transmit_entropy_data(unsigned char *bytes_in, unsigned int n_bytes, bool *do_exit)
{
	int error_count = 0;
	while(n_bytes > 0)
	{
		unsigned n_done = -1;

		for(;;)
		{
			unsigned char reply[8] = { 0 };
			unsigned char header[8] = { 0 };

			if (do_exit && *do_exit)
				return -1;

			error_count++;
			if (error_count > MAX_ERROR_SLEEP)
				error_count = MAX_ERROR_SLEEP;

			reconnect_status_t rss = reconnect_server_socket(do_exit);
			if (rss == RSS_FAIL)
				continue;

			disable_nagle(socket_fd);
			enable_tcp_keepalive(socket_fd);

			dolog(LOG_DEBUG, "request to send %d bytes", n_bytes);

			make_msg(header, 2, std::min(max_get_put_size, n_bytes * 8)); // 0002 xmit data request

			// header
			if (WRITE_TO(socket_fd, header, 8, comm_time_out, do_exit) != 8)
			{
				if (do_exit && *do_exit)
					return -1;

				dolog(LOG_INFO, "error transmitting header");

				close(socket_fd);
				socket_fd = -1;

				error_sleep(error_count);
				continue;
			}

			// ack from server?
		ignore_unsollicited_msg: // we jump to this label when unsollicited msgs are
			// received during data-transmission handshake
			if (READ_TO(socket_fd, reply, 8, comm_time_out, do_exit) != 8)
			{
				if (do_exit && *do_exit)
					return -1;

				dolog(LOG_INFO, "error receiving ack/nack");

				close(socket_fd);
				socket_fd = -1;

				error_sleep(error_count);
				continue;
			}

			unsigned int value = uchar_to_uint(&reply[4]);

			if (memcmp(reply, "0001", 4) == 0 || memcmp(reply, "9003", 4) == 0)                 // ACK
			{
				unsigned int cur_n_bytes = (value + 7) / 8;

				if (cur_n_bytes > n_bytes)
					error_exit("ERROR: server requesting more data than available");

				dolog(LOG_DEBUG, "Transmitting %d bytes", cur_n_bytes);

				// encrypt data
				int hash_len = mac_hasher -> get_hash_size();
				int with_hash_n = cur_n_bytes + hash_len;

				unsigned char *bytes_out = reinterpret_cast<unsigned char *>(malloc(with_hash_n));
				if (!bytes_out)
					error_exit("out of memory");
				unsigned char *temp_buffer = reinterpret_cast<unsigned char *>(malloc_locked(with_hash_n));
				if (!temp_buffer)
					error_exit("out of memory");

				mac_hasher -> do_hash(bytes_in, cur_n_bytes, temp_buffer);
				memcpy(&temp_buffer[hash_len], bytes_in, cur_n_bytes);

				stream_cipher -> encrypt(temp_buffer, with_hash_n, bytes_out);

				free_locked(temp_buffer, with_hash_n);

				if (WRITE_TO(socket_fd, bytes_out, with_hash_n, comm_time_out, do_exit) != with_hash_n)
				{
					if (do_exit && *do_exit)
						return -1;

					dolog(LOG_INFO, "error transmitting data");
					free(bytes_out);

					close(socket_fd);
					socket_fd = -1;

					error_sleep(error_count);
					continue;
				}

				free(bytes_out);

				if (memcmp(reply, "9003", 4) == 0)            // ACK but full
				{
					// only usefull for eb_proxy
					dolog(LOG_DEBUG, "pool full, sleeping %d seconds (with ACK)", sleep_9003);
					// same comments as for 9001 apply
					sleep_interruptable(sleep_9003);
				}

				n_done = cur_n_bytes;

				break;
			}
			else if (memcmp(reply, "9001", 4) == 0)            // NACK
			{
				dolog(LOG_DEBUG, "pool full, sleeping %d seconds", value);

				sleep_9003 = (sleep_9003 + value * 2) / 2;

				// now we should sleep and wait for either the time
				// to pass or a 0010 to come in. in reality we just
				// sleep until the first message comes in and then
				// continue; it'll only be 0010 anyway
				sleep_interruptable(value);
			}
			else if (memcmp(reply, "0010", 4) == 0)            // there's a need for data
			{
				// this message can be received during transmission hand-
				// shake as it might have been queued earlier
				goto ignore_unsollicited_msg;
			}
			else if (memcmp(reply, "9004", 4) == 0)            // all pools full, only for provies
				goto ignore_unsollicited_msg;
			else if (memcmp(reply, "0009", 4) == 0)            // got data
				goto ignore_unsollicited_msg;
			else
			{
				dolog(LOG_CRIT, "garbage received: %s", reply);

				error_sleep(error_count);
				continue;
			}

			error_count = 1;
		}

		n_bytes -= n_done;
		bytes_in += n_done;
	}

	return 0;
}

int protocol::request_bytes(unsigned char *where_to, unsigned int n_bits, bool fail_on_no_bits, bool *do_exit)
{
	bool request_sent = false;

	if (n_bits < 8)
		error_exit("Internal error: must request at list 8 bits");

	double sleep_trigger = -1;
	int error_count = 0;
	for(;;)
	{
		if (do_exit && *do_exit)
			return -1;

		error_count++;
		if (error_count > MAX_ERROR_SLEEP)
			error_count = MAX_ERROR_SLEEP;

		reconnect_status_t rss = reconnect_server_socket(do_exit);
		if (rss == RSS_FAIL)
                        error_exit("Failed to connect");
		else if (rss == RSS_NEW_CONNECTION)
			request_sent = false;

		unsigned char request[8];
		make_msg(request, 1, std::min(max_get_put_size, n_bits)); // 0001

		if (!request_sent || (sleep_trigger > 0.0 && get_ts() >= sleep_trigger))
		{
			sleep_trigger = -1.0;

			dolog(LOG_DEBUG, "Send request (%s)", request);
			if (WRITE(socket_fd, request, 8) != 8)
			{
				if (do_exit && *do_exit)
					return -1;

				close(socket_fd);
				socket_fd = -1;

				error_sleep(error_count);

				continue;
			}

			request_sent = true;
		}

		unsigned char reply[8];
		int rc = READ_TO(socket_fd, reply, 8, comm_time_out, do_exit);
		if (do_exit && *do_exit)
			return -1;
		if (rc == 0)
			continue;
		if (rc != 8)
		{
			dolog(LOG_INFO, "Read error, got %d of 8 bytes", rc);

			close(socket_fd);
			socket_fd = -1;

			error_sleep(error_count);

			continue;
		}

                dolog(LOG_DEBUG, "received reply: %s", reply);

                if (memcmp(reply, "9000", 4) == 0 || memcmp(reply, "9002", 4) == 0) // no data/quota
                {
			error_count = 0;
			unsigned int sleep_time = uchar_to_uint(&reply[4]);
			dolog(LOG_DEBUG, "data denied: %s, sleep for %d seconds", reply[3] == '0' ? "no data" : "quota", sleep_time);

			sleep_trigger = get_ts() + sleep_time;

			if (fail_on_no_bits)
				return 0;
		}
                else if (memcmp(reply, "0004", 4) == 0)       /* ping request */
                {
			error_count = 0;

                        dolog(LOG_DEBUG, "PING");

                        unsigned char xmit_buffer[8];
			make_msg(xmit_buffer, 5, pingnr++); // 0005

                        if (WRITE_TO(socket_fd, xmit_buffer, 8, comm_time_out, do_exit) != 8)
                        {
				if (do_exit && *do_exit)
					return -1;

                                close(socket_fd);
                                socket_fd = -1;
                        }
                }
                else if (memcmp(reply, "0009", 4) == 0)
                {
			error_count = 0;
                        dolog(LOG_INFO, "Broker informs about data");
			if (sleep_trigger > 0.0)
				sleep_trigger = 2.0;
                }
                else if (memcmp(reply, "0010", 4) == 0)
                {
			error_count = 0;
                        dolog(LOG_INFO, "Broker requests data");
                }
                else if (memcmp(reply, "9004", 4) == 0)
                {
			error_count = 0;
                        dolog(LOG_INFO, "Broker is full");
                }
		else if (memcmp(reply, "0002", 4) == 0)	// there's data!
		{
			error_count = 0;
			int will_get_n_bits = uchar_to_uint(&reply[4]);
			int will_get_n_bytes = (will_get_n_bits + 7) / 8;

			dolog(LOG_INFO, "server is offering %d bits (%d bytes)", will_get_n_bits, will_get_n_bytes);

			if (will_get_n_bytes == 0)
			{
				dolog(LOG_CRIT, "Broker is offering 0 bits?! Please report this to folkert@vanheusden.com");
				request_sent = false;
				continue;
			}

			int hash_len = mac_hasher -> get_hash_size();
			int xmit_bytes = will_get_n_bytes + hash_len;
#ifdef CRYPTO_DEBUG
			printf("bytes: %d\n", xmit_bytes);
#endif
			unsigned char *buffer_in = reinterpret_cast<unsigned char *>(malloc(xmit_bytes));
			if (!buffer_in)
				error_exit("out of memory allocating %d bytes", will_get_n_bytes);

			if (READ_TO(socket_fd, buffer_in, xmit_bytes, comm_time_out, do_exit) != xmit_bytes)
			{
				if (do_exit && *do_exit)
					return -1;

				dolog(LOG_INFO, "Network read error (data)");

				free(buffer_in);

				close(socket_fd);
				socket_fd = -1;

				request_sent = false;

				continue;
			}

			// decrypt
			unsigned char *temp_buffer = reinterpret_cast<unsigned char *>(malloc_locked(xmit_bytes));

			stream_cipher -> decrypt(buffer_in, xmit_bytes, temp_buffer);

			// verify data is correct
			unsigned char *hash = reinterpret_cast<unsigned char *>(malloc(hash_len));
			mac_hasher -> do_hash(&temp_buffer[hash_len], will_get_n_bytes, hash);

#ifdef CRYPTO_DEBUG
			printf("in  : "); hexdump(temp_buffer, hash_len);
			printf("calc: "); hexdump(hash, hash_len);
			printf("data: "); hexdump(temp_buffer + hash_len, 8);
#endif

			if (memcmp(hash, temp_buffer, hash_len) != 0)
				error_exit("Data corrupt!");
#ifdef CRYPTO_DEBUG
			else
				printf("data is OK\n");
#endif

			memcpy(where_to, &temp_buffer[hash_len], will_get_n_bytes);

			free_locked(temp_buffer, xmit_bytes);

			free(buffer_in);

			free(hash);

			dolog(LOG_DEBUG, "got %d bits", will_get_n_bytes * 8);

			return will_get_n_bytes;
		}
		else
		{
			dolog(LOG_WARNING, "Unknown message %s received (disconnecting)", reply);

			close(socket_fd);
			socket_fd = -1;

			error_sleep(error_count);
		}
	}

	return 0;
}

void protocol::drop()
{
	close(socket_fd);

	socket_fd = -1;
}
