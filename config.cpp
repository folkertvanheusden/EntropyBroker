#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <libgen.h>
#include <string>
#include <map>
#include <vector>

#include "defines.h"
#include "error.h"
#include "random_source.h"
#include "math.h"
#include "hasher_type.h"
#include "stirrer_type.h"
#include "encrypt_stream.h"
#include "hasher.h"
#include "protocol.h"
#include "config.h"
#include "log.h"
#include "stirrer.h"
#include "fips140.h"
#include "scc.h"
#include "pool_crypto.h"
#include "pool.h"
#include "pools.h"
#include "statistics.h"
#include "statistics_global.h"
#include "statistics_user.h"
#include "users.h"
#include "auth.h"

bool config_yes_no(char *what)
{
        if (what[0] == '1' || strcasecmp(what, "yes") == 0 || strcasecmp(what, "on") == 0)
                return true;

        return false;
}

void load_config(const char *config, config_t *pconfig)
{
	char *dummy = strdup(config);

	char *cur_dir_dummy = dirname(dummy);
	char *cur_dir = realpath(cur_dir_dummy, NULL);

        int linenr = 0;
        FILE *fh = fopen(config, "r");
        if (!fh)
                error_exit("error opening configuration file '%s'", config);

	/* set defaults */
	pconfig -> max_number_of_mem_pools = 14;
	pconfig -> max_number_of_disk_pools = 128;
	pconfig -> min_store_on_disk_n = 5;

	pconfig -> bitcount_estimator = BCE_SHANNON;

	pconfig -> listen_adapter    = "0.0.0.0";
	pconfig -> listen_port       = DEFAULT_BROKER_PORT;
	pconfig -> listen_queue_size = 64;
	pconfig -> disable_nagle     = false;
	pconfig -> enable_keepalive  = true;

	pconfig -> reset_counters_interval    = 60;
	pconfig -> statistics_interval        = 300;
	pconfig -> ping_interval              = 601;
	pconfig -> kernelpool_filled_interval = 3600;

	pconfig -> stats_file = NULL;

	pconfig -> communication_timeout              = 15.0;
	pconfig -> communication_session_timeout      = 3600.0; /* 0 for no timeout */
	pconfig -> default_sleep_time_when_pools_full = 10;
	pconfig -> default_sleep_when_pools_empty     = 16;
	pconfig -> default_max_sleep_when_pools_empty = 60;
	pconfig -> when_pools_full_allow_submit_interval = 15;
	pconfig -> max_open_files = 1024;

	pconfig -> default_max_bits_per_interval = 16000000;

	pconfig -> ignore_rngtest_fips140 = false;
	pconfig -> ignore_rngtest_scc = false;
	pconfig -> scc_threshold = 0.2;

	pconfig -> allow_event_entropy_addition = true;
	pconfig -> add_entropy_even_if_all_full = false;
	pconfig -> allow_prng = false;

	pconfig -> user_map = new std::string("usermap.txt");

	pconfig -> pool_size_bytes = DEFAULT_POOL_SIZE_BITS / 8;

	pconfig -> prng_seed_file = NULL;

	pconfig -> max_get_put_size = 1249;

	pconfig -> ht = H_SHA512;
	pconfig -> st = S_BLOWFISH;

	pconfig -> rs = RS_CRYPTOPP;

	pconfig -> stream_cipher = "blowfish";
	pconfig -> mac_hasher = "md5";
	pconfig -> hash_hasher = "sha512";

	pconfig -> webserver_interface = "0.0.0.0";
	pconfig -> webserver_port = -1;

	pconfig -> graph_font = strdup(FONT);

	pconfig -> default_max_get_bps = 4096;

        for(;;)
        {
		double parvald;
		int parval;
                char read_buffer[4096], *lf, *par;
                char *cmd = fgets(read_buffer, sizeof read_buffer, fh), *is;
                if (!cmd)
                        break;
                linenr++;

                if (read_buffer[0] == '#' || read_buffer[0] == ';')
                        continue;

		while(*cmd == ' ') cmd++;

                lf = strchr(read_buffer, '\n');
                if (lf) *lf = 0x00;

		if (strlen(cmd) == 0)
			continue;

                is = strchr(read_buffer, '=');
                if (!is)
                        error_exit("invalid line at line %d: '=' missing", linenr);

                *is = 0x00;
                par = is + 1;
		while(*par == ' ') par++;
		parval = atoi(par);
		parvald = atof(par);

		is--;
		while(*is == ' ') { *is = 0x00 ; is--; }

		if (strcmp(cmd, "max_number_of_mem_pools") == 0)
			pconfig -> max_number_of_mem_pools = parval;
		else if (strcmp(cmd, "max_number_of_disk_pools") == 0)
			pconfig -> max_number_of_disk_pools = parval;
		else if (strcmp(cmd, "min_store_on_disk_n") == 0)
			pconfig -> min_store_on_disk_n = parval;
		else if (strcmp(cmd, "listen_adapter") == 0)
			pconfig -> listen_adapter = strdup(par);
		else if (strcmp(cmd, "graph_font") == 0)
			pconfig -> graph_font = strdup(par);
		else if (strcmp(cmd, "users") == 0)
		{
			char *p_file = static_cast<char *>(malloc(strlen(cur_dir) + strlen(par) + 1 + 1));
			if (par[0] == '/')
				strcpy(p_file, par);
			else
				sprintf(p_file, "%s/%s", cur_dir, par);
			dolog(LOG_INFO, "Load users from %s", p_file);
			delete pconfig -> user_map;
			pconfig -> user_map = new std::string(p_file);
			free(p_file);
		}
		else if (strcmp(cmd, "bitcount_estimator") == 0)
		{
			if (strcmp(par, "shannon") == 0)
				pconfig -> bitcount_estimator = BCE_SHANNON;
			else if (strcmp(par, "compression") == 0)
				pconfig -> bitcount_estimator = BCE_COMPRESSION;
			else
				error_exit("bitcount_estimator of type '%s' is not known", par);
		}
		else if (strcmp(cmd, "random_source") == 0)
		{
			if (strcmp(par, "crypto++") == 0)
				pconfig -> rs = RS_CRYPTOPP;
			else if (strcmp(par, "dev_random") == 0)
				pconfig -> rs = RS_DEV_RANDOM;
			else if (strcmp(par, "dev_urandom") == 0)
				pconfig -> rs = RS_DEV_URANDOM;
			else
				error_exit("random_source of type '%s' is not known", par);
		}
		else if (strcmp(cmd, "listen_port") == 0)
			pconfig -> listen_port = parval;
		else if (strcmp(cmd, "listen_queue_size") == 0)
			pconfig -> listen_queue_size = parval;
		else if (strcmp(cmd, "default_max_get_bps") == 0)
			pconfig -> default_max_get_bps = parval;
		else if (strcmp(cmd, "max_open_files") == 0)
			pconfig -> max_open_files = parval;
		else if (strcmp(cmd, "webserver_interface") == 0)
			pconfig -> webserver_interface = par;
		else if (strcmp(cmd, "webserver_port") == 0)
			pconfig -> webserver_port = parval;
		else if (strcmp(cmd, "disable_nagle") == 0)
			pconfig -> disable_nagle = config_yes_no(par);
		else if (strcmp(cmd, "enable_keepalive") == 0)
			pconfig -> enable_keepalive = config_yes_no(par);
		else if (strcmp(cmd, "reset_counters_interval") == 0)
			pconfig -> reset_counters_interval = parval;
		else if (strcmp(cmd, "statistics_interval") == 0)
			pconfig -> statistics_interval = parval;
		else if (strcmp(cmd, "ping_interval") == 0)
			pconfig -> ping_interval = parval;
		else if (strcmp(cmd, "pool_size_in_bytes") == 0)
			pconfig -> pool_size_bytes = parval;
		else if (strcmp(cmd, "max_get_put_size") == 0)
			pconfig -> max_get_put_size = parval;
		else if (strcmp(cmd, "kernelpool_filled_interval") == 0)
			pconfig -> kernelpool_filled_interval = parval;
		else if (strcmp(cmd, "stats_file") == 0)
			pconfig -> stats_file = strdup(par);
		else if (strcmp(cmd, "stream_cipher") == 0)
			pconfig -> stream_cipher = par;
		else if (strcmp(cmd, "mac_hasher") == 0)
			pconfig -> mac_hasher = par;
		else if (strcmp(cmd, "hash_hasher") == 0)
			pconfig -> hash_hasher = par;
		else if (strcmp(cmd, "prng_seed_file") == 0)
		{
			char *p_file = static_cast<char *>(malloc(strlen(VAR_DIR) + strlen(par) + 1 + 1));
			if (par[0] == '/')
				strcpy(p_file, par);
			else
				sprintf(p_file, VAR_DIR "/%s", par);
			dolog(LOG_INFO, "Will load PRNG seed from %s", p_file);
			pconfig -> prng_seed_file = p_file;
		}
		else if (strcmp(cmd, "communication_timeout") == 0)
			pconfig -> communication_timeout = parvald;
		else if (strcmp(cmd, "communication_session_timeout") == 0)
			pconfig -> communication_session_timeout = parvald;
		else if (strcmp(cmd, "default_sleep_time_when_pools_full") == 0)
			pconfig -> default_sleep_time_when_pools_full = parval;
		else if (strcmp(cmd, "default_sleep_when_pools_empty") == 0)
			pconfig -> default_sleep_when_pools_empty = parval;
		else if (strcmp(cmd, "default_max_sleep_when_pools_empty") == 0)
			pconfig -> default_max_sleep_when_pools_empty = parval;
		else if (strcmp(cmd, "default_max_bits_per_interval") == 0)
			pconfig -> default_max_bits_per_interval = parval;
		else if (strcmp(cmd, "ignore_rngtest_fips140") == 0)
			pconfig -> ignore_rngtest_fips140 = config_yes_no(par);
		else if (strcmp(cmd, "ignore_rngtest_scc") == 0)
			pconfig -> ignore_rngtest_scc = config_yes_no(par);
		else if (strcmp(cmd, "allow_event_entropy_addition") == 0)
			pconfig -> allow_event_entropy_addition = config_yes_no(par);
		else if (strcmp(cmd, "add_entropy_even_if_all_full") == 0)
			pconfig -> add_entropy_even_if_all_full = config_yes_no(par);
		else if (strcmp(cmd, "allow_prng") == 0)
			pconfig -> allow_prng = config_yes_no(par);
		else if (strcmp(cmd, "scc_threshold") == 0)
			pconfig -> scc_threshold = parvald;
		else if (strcmp(cmd, "when_pools_full_allow_submit_interval") == 0)
			pconfig -> when_pools_full_allow_submit_interval = parval;
		else if (strcmp(cmd, "hash_type") == 0)
		{
			if (strcmp(par, "sha512") == 0)
				pconfig -> ht = H_SHA512;
			else if (strcmp(par, "md5") == 0)
				pconfig -> ht = H_MD5;
			else if (strcmp(par, "ripemd160") == 0)
				pconfig -> ht = H_RIPEMD160;
			else if (strcmp(par, "whirlpool") == 0)
				pconfig -> ht = H_WHIRLPOOL;
			else
				error_exit("Hash type '%s' not understood", par);
		}
		else if (strcmp(cmd, "stirrer_type") == 0)
		{
			if (strcmp(par, "blowfish") == 0)
				pconfig -> st = S_BLOWFISH;
			else if (strcmp(par, "aes") == 0)
				pconfig -> st = S_AES;
			else if (strcmp(par, "3des") == 0)
				pconfig -> st = S_3DES;
			else if (strcmp(par, "camellia") == 0)
				pconfig -> st = S_CAMELLIA;
			else
				error_exit("Stirrer type '%s' not understood", par);
		}
		else
			error_exit("%s=%s not understood", cmd, par);
	}

	dolog(LOG_DEBUG, "read %d configuration file lines", linenr);

	fclose(fh);

	free(dummy);
	free(cur_dir);
}
