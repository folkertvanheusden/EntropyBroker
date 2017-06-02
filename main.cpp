#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <vector>
#include <string>
#include <map>

#include "error.h"
#include "random_source.h"
#include "math.h"
#include "hasher_type.h"
#include "hasher.h"
#include "hasher_md5.h"
#include "hasher_ripemd160.h"
#include "hasher_sha512.h"
#include "hasher_whirlpool.h"
#include "encrypt_stream.h"
#include "encrypt_stream_3des.h"
#include "encrypt_stream_aes.h"
#include "encrypt_stream_blowfish.h"
#include "encrypt_stream_camellia.h"
#include "stirrer_type.h"
#include "stirrer.h"
#include "stirrer_3des.h"
#include "stirrer_aes.h"
#include "stirrer_blowfish.h"
#include "stirrer_camellia.h"
#include "pool_crypto.h"
#include "pool.h"
#include "fips140.h"
#include "scc.h"
#include "config.h"
#include "pools.h"
#include "statistics.h"
#include "statistics_global.h"
#include "statistics_user.h"
#include "users.h"
#include "handle_client.h"
#include "data_store_int.h"
#include "data_logger.h"
#include "utils.h"
#include "log.h"
#include "signals.h"
#include "auth.h"
#include "http_request_t.h"
#include "http_bundle.h"
#include "http_file.h"
#include "web_server.h"

const char *pid_file = PID_DIR "/entropy_broker.pid";
const char *version = "entropy_broker v " VERSION ", (C) 2009-2017 by folkert@vanheusden.com";

void seed(pools *ppools, pool_crypto *pc)
{
	int n = 0, dummy;

	n += ppools -> add_event(get_ts_ns(), NULL, 0, 0.005, pc); 

	dummy = getpid();
	n += ppools -> add_event(get_ts_ns(), (unsigned char *)&dummy, sizeof dummy, 0.005, pc);

	dolog(LOG_DEBUG, "added %d bits of startup-event-entropy to pool", n);
}

void help(void)
{
	printf("-c file   config-file to read (default: " CONFIG "\n");
	printf("-l file   log to file 'file'\n");
	printf("-L x      log level, 0=nothing, 255=all\n");
	printf("-s        log to syslog\n");
	printf("-S        statistics-file to log to\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
}

int main(int argc, char *argv[])
{
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *stats_file = NULL;
	fips140 *eb_output_fips140 = new fips140();
	scc *eb_output_scc = new scc();
	const char *config_file = CONFIG;
	config_t config;
	int log_level = LOG_INFO;

	printf("%s\n", version);

	eb_output_fips140 -> set_user("output");
	eb_output_scc     -> set_user("output");

	while((c = getopt(argc, argv, "hP:c:S:L:l:sn")) != -1)
	{
		switch(c)
		{
			case 'P':
				pid_file = optarg;
				break;

			case 'c':
				config_file = optarg;
				break;

			case 'S':
				stats_file = optarg;
				break;

			case 's':
				log_syslog = true;
				break;

			case 'l':
				log_logfile = optarg;
				break;

			case 'L':
				log_level = atoi(optarg);
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

	(void)umask(0177);
	no_core();

	fips140::init();

	pthread_check(pthread_mutexattr_init(&global_mutex_attr), "pthread_mutexattr_init");
	pthread_check(pthread_mutexattr_settype(&global_mutex_attr, PTHREAD_MUTEX_ERRORCHECK), "pthread_mutexattr_settype");

	set_logging_parameters(log_console, log_logfile, log_syslog, log_level);

	load_config(config_file, &config);
	if (stats_file)
		config.stats_file = stats_file;

	dolog(LOG_INFO, "%s", version);

	dolog(LOG_DEBUG, "Main thread id: %ld", gettid());

	eb_output_scc -> set_threshold(config.scc_threshold);

	bit_count_estimator *bce = new bit_count_estimator(config.bitcount_estimator);

	// random
	pool_crypto pc(config.st, config.ht, config.rs);

	unsigned int rand_seed = 11;
	pc.get_random_source() -> get(reinterpret_cast<unsigned char *>(&rand_seed), sizeof rand_seed);
	srand(rand_seed);

	pools *ppools = new pools(std::string(CACHE_DIR), config.max_number_of_mem_pools, config.max_number_of_disk_pools, config.min_store_on_disk_n, bce, config.pool_size_bytes);

	seed(ppools, &pc);

	if (!do_not_fork)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	set_signal_handlers();

	std::vector<client_t *> clients;
	pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

	statistics_global stats;

	data_logger *dl = new data_logger(&stats, ppools, &clients, &clients_mutex);

	users *user_map = new users(*config.user_map, config.default_max_get_bps);
	if (!user_map)
		error_exit("failed allocating users-object");

	if (config.webserver_port >= 1)
		start_web_server(&config, &clients, &clients_mutex, ppools, &stats, eb_output_fips140, eb_output_scc, dl, user_map);

	struct rlimit rlim = {config.max_open_files , config.max_open_files };
	if (setrlimit(RLIMIT_NOFILE, &rlim) == -1)
		error_exit("setrlimit(RLIMIT_NOFILE) failed");

	main_loop(&clients, &clients_mutex, ppools, &config, eb_output_fips140, eb_output_scc, &pc, &stats, user_map);

	dolog(LOG_INFO, "Dumping pool contents to cache-file");

	delete dl;

	delete user_map;

	delete ppools;

	delete bce;
	delete eb_output_fips140;
	delete eb_output_scc;

	delete config.user_map;

	free((void *)config.listen_adapter);
	free((void *)config.graph_font);

	unlink(pid_file);

	dolog(LOG_INFO, "--- terminating ---\n");

	return 0;
}
