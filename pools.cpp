#include <math.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <vector>
#include <string>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/file.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "error.h"
#include "random_source.h"
#include "log.h"
#include "math.h"
#include "hasher_type.h"
#include "hasher.h"
#include "stirrer_type.h"
#include "stirrer.h"
#include "pool_crypto.h"
#include "pool.h"
#include "utils.h"
#include "fips140.h"
#include "scc.h"
#include "pools.h"

pools::pools(std::string cache_dir_in, unsigned int max_n_mem_pools_in, unsigned int max_n_disk_pools_in, unsigned int min_store_on_disk_n_in, bit_count_estimator *bce_in, int new_pool_size_in_bytes) : cache_dir(cache_dir_in), max_n_mem_pools(max_n_mem_pools_in), max_n_disk_pools(max_n_disk_pools_in), min_store_on_disk_n(min_store_on_disk_n_in), disk_limit_reached_notified(false), bce(bce_in)
{
	pthread_check(pthread_rwlock_init(&list_lck, NULL), "pthread_rwlock_init");
	is_w_locked = false;

	pthread_check(pthread_mutex_init(&lat_lck, NULL), "pthread_mutex_init");
	last_added_to = 0;

	new_pool_size = new_pool_size_in_bytes;

	if (min_store_on_disk_n >= max_n_mem_pools)
		error_exit("min_store_on_disk_n must be less than max_number_of_mem_pools");
	if (min_store_on_disk_n < 0)
		error_exit("min_store_on_disk_n must be at least 0");

	if (max_n_mem_pools < 3)
		error_exit("maximum number of memory pools must be at least 3");

	if (max_n_disk_pools < 0)
		error_exit("maximum number of disk pools must be at least 0");

	load_cachefiles_list();
}

pools::~pools()
{
	store_caches(0);

	pthread_check(pthread_mutex_destroy(&lat_lck), "pthread_mutex_destroy");
	pthread_check(pthread_rwlock_destroy(&list_lck), "pthread_rwlock_destroy");
}

double calc_time_left(double start_ts, double max_time)
{
	return std::max(MIN_SLEEP, max_time - (get_ts() - start_ts));
}

double calc_time_left(double start_ts, unsigned int cur, unsigned int n, double max_duration)
{
	double now_ts = get_ts();
	double time_left = ((max_duration * 0.9) - (now_ts - start_ts)) / double(n - cur);

	if (time_left < MIN_SLEEP)
		return MIN_SLEEP;

	return time_left;
}

void pools::list_wlock()
{
	pthread_check(pthread_rwlock_wrlock(&list_lck), "pthread_rwlock_wrlock");

	my_assert(is_w_locked == false);
	is_w_locked = true;
}

void pools::list_wunlock()
{
	my_assert(is_w_locked);
	is_w_locked = false;

	pthread_check(pthread_rwlock_unlock(&list_lck), "pthread_rwlock_unlock");
}

void pools::list_runlock()
{
	pthread_check(pthread_rwlock_unlock(&list_lck), "pthread_rwlock_unlock");
}

void pools::list_rlock()
{
	pthread_check(pthread_rwlock_rdlock(&list_lck), "pthread_rwlock_rdlock");
}

// keep_n == 0: means dump all
void pools::store_caches(unsigned int keep_n)
{
	if(max_n_disk_pools == 0) {
		dolog(LOG_DEBUG, "Disabled disk pools: not creating any");
		return;
	}

	if (cache_list.size() >= max_n_disk_pools && keep_n != 0)
	{
		if (!disk_limit_reached_notified)
		{
			dolog(LOG_DEBUG, "Maximum number of disk pools reached: not creating a new one");
			disk_limit_reached_notified = true;
		}
	}
	else
	{
		disk_limit_reached_notified = false;
		dolog(LOG_DEBUG, "Storing %d pools on disk (new number of files: %d)", pool_vector.size() - keep_n, cache_list.size() + 1);

		long double now = get_ts_ns();
		char buffer[128];
		snprintf(buffer, sizeof buffer, "%Lf", now);

		std::string new_cache_file = cache_dir + "/" + std::string(buffer) + ".pool";
		FILE *fh = fopen(new_cache_file.c_str(), "wb");
		if (!fh)
			error_exit("Failed to create file %s", new_cache_file.c_str());

		if (flock(fileno(fh), LOCK_EX) == -1)
			error_exit("flock(LOCK_EX) for %s failed", new_cache_file.c_str());

		int bit_sum = 0;
		while(pool_vector.size() > keep_n)
		{
			if (pool_vector.at(0) -> timed_lock_object(1.0) == NULL) // will always succeed due to writelock on list
			{
				int n_bits = pool_vector.at(0) -> get_n_bits_in_pool();
				if (n_bits > 0)
				{
					bit_sum += n_bits;
					pool_vector.at(0) -> dump(fh);
				}

				pool_vector.at(0) -> unlock_object();

				delete pool_vector.at(0);
				pool_vector.erase(pool_vector.begin() + 0);
			}
		}

		cache_list.push_back(std::pair<std::string, int>(new_cache_file, bit_sum));

		fflush(fh);

		if (flock(fileno(fh), LOCK_UN) == -1)
			error_exit("flock(LOCK_UN) for %s failed", new_cache_file.c_str());

		fclose(fh);
	}
}

bool pools::load_caches(unsigned int load_n_bits, pool_crypto *pc)
{
	dolog(LOG_DEBUG, "Loading %d bits from pools", load_n_bits);

	unsigned int bits_loaded = 0;

	unsigned int files_loaded = 0;
	while(!cache_list.empty() && bits_loaded < load_n_bits)
	{
		dolog(LOG_DEBUG, "Load bits from %s", cache_list.at(0).first.c_str());
		FILE *fh = fopen(cache_list.at(0).first.c_str(), "r");
		if (!fh)
			error_exit("Failed to open cache-file %s", cache_list.at(0).first.c_str());

		if (flock(fileno(fh), LOCK_EX) == -1)
			error_exit("flock(LOCK_EX) for %s failed", cache_list.at(0).first.c_str());

		while(!feof(fh))
		{
			/// FIXME ugly hack, should throw an exception in pool-constructor
			if (fgetc(fh) == -1)
				break;
			if (fseek(fh, -1, SEEK_CUR) == -1)
				error_exit("Problem seeking in %s", cache_list.at(0).first.c_str());
			///// FIXME /////

			pool *new_pool = new pool(++files_loaded, fh, bce, pc);

			bits_loaded += new_pool -> get_n_bits_in_pool();

			pool_vector.push_back(new_pool);
		}

		if (unlink(cache_list.at(0).first.c_str()) == -1)
			error_exit("Failed to delete cache-file %s", cache_list.at(0).first.c_str());

		fflush(fh);

		if (flock(fileno(fh), LOCK_UN) == -1)
			error_exit("flock(LOCK_UN) for %s failed", cache_list.at(0).first.c_str());

		fclose(fh);

		cache_list.erase(cache_list.begin());
	}

	if (bits_loaded > 0 || files_loaded > 0)
	{
		dolog(LOG_DEBUG, "%d bits loaded from %d files", bits_loaded, files_loaded);
		return true;
	}

	return false;
}

void pools::flush_empty_pools()
{
	unsigned int deleted = 0;
	for(int index=pool_vector.size() - 1; index >= 0; index--)
	{
		if (pool_vector.at(index) -> timed_lock_object(1.0) == NULL) // will always succeed due to writelock on list
		{
			if (pool_vector.at(index) -> get_n_bits_in_pool() == 0)
			{
				pool *obj = pool_vector.at(index);

				pool_vector.erase(pool_vector.begin() + index);

				obj -> unlock_object();
				delete obj;

				deleted++;
			}
			else
			{
				pool_vector.at(index) -> unlock_object();
			}
		}
	}

	if (deleted)
		dolog(LOG_DEBUG, "Deleted %d empty pool(s), new count: %d", deleted, pool_vector.size());
}

typedef struct
{
	int index;
	int n_bits;
}
merge_t;

int merge_compare_bits(const void *a, const void *b)
{
	merge_t *ma = (merge_t *)a;
	merge_t *mb = (merge_t *)b;

	return ma -> n_bits - mb -> n_bits;
}

void pools::merge_pools(pool_crypto *pc)
{
	if (pool_vector.empty())
		return;

	int n_merged = 0;
	int n_in = pool_vector.size();

	int process_n = 0;
	merge_t *list = reinterpret_cast<merge_t *>(malloc(n_in * sizeof(merge_t)));
	for(int index=0; index<n_in; index++)
	{
		if (pool_vector.at(index) -> timed_lock_object(0.01))
			continue;

		list[process_n].index = index;
		list[process_n].n_bits = pool_vector.at(index) -> get_n_bits_in_pool();

		if (list[process_n].n_bits > 0)
			process_n++;
		else
			pool_vector.at(index) -> unlock_object();
	}

	if (process_n > 0)
	{
		qsort(list, process_n, sizeof(merge_t), merge_compare_bits);

		int stir_size = pc -> get_stirrer() -> get_stir_size();

		int add_index = -1, max_n_bits = -1;;
		for(int index=0; index<process_n; index++)
		{
			if (add_index == -1)
			{
				add_index = index++;
				max_n_bits = pool_vector.at(list[add_index].index) -> get_pool_size();

				if (index == process_n)
					break;
			}

			if (list[add_index].n_bits + list[index].n_bits > max_n_bits + stir_size)
			{
				add_index = -1;
				index--;
			}
			else
			{
				int i1 = list[add_index].index;
				int i2 = list[index].index;

				int data_size = pool_vector.at(i2) -> get_pool_size_bytes();
				unsigned char *data = pool_vector.at(i2) -> expose_contents();

				pool_vector.at(i1) -> add_entropy_data(data, data_size, pc, list[index].n_bits);

				n_merged++;
			}
		}
	}

	for(int index=0; index<process_n; index++)
		pool_vector.at(list[index].index) -> unlock_object();

	free(list);

	if (n_merged)
		dolog(LOG_INFO, "%d pool(s) merged, new count: %d", n_merged, pool_vector.size());
}

void pools::load_cachefiles_list()
{
	DIR *dirp = opendir(cache_dir.c_str());
	if (!dirp)
		error_exit("Failed to open directory %s", cache_dir.c_str());

	struct dirent *de = NULL;
	while((de = readdir(dirp)) != NULL)
	{
		std::string file_name = cache_dir + "/" + std::string(de -> d_name);

		struct stat ss;
		if (stat(file_name.c_str(), &ss) == -1)
		{
			if (errno == EEXIST)
				dolog(LOG_WARNING, "File %s suddenly disappeared?!", file_name.c_str());

			error_exit("Error doing stat on %s", file_name.c_str());
		}

		if (ss.st_mode & S_IFDIR)
			continue;

		if (file_name.substr(file_name.size() - 5, 5) == ".pool")
		{
			dolog(LOG_DEBUG, "Added %s to cache list", file_name.c_str());
			cache_list.push_back(std::pair<std::string, int>(file_name, pool::get_file_bit_count(file_name)));
		}
	}

	closedir(dirp);
}

bool pools::verify_quality(unsigned char *data, int n, bool ignore_rngtest_fips140, fips140 *pfips, bool ignore_rngtest_scc, scc *pscc)
{
	if (!ignore_rngtest_fips140 || !ignore_rngtest_scc)
	{
		for(int rngtest_loop=0; rngtest_loop<n; rngtest_loop++)
		{
			pfips -> add(data[rngtest_loop]);
			pscc -> add(data[rngtest_loop]);
		}
	}

	bool rc_fips140 = true, rc_scc = true;

	if (!ignore_rngtest_fips140)
		rc_fips140 = pfips -> is_ok();

	if (!ignore_rngtest_scc)
		rc_scc = pfips -> is_ok();

	return rc_fips140 == true && rc_scc == true;
}

// returns a locked pool
int pools::find_non_full_pool(bool timed, double max_duration)
{
	// be carefull that start_ts is not used when timed == false!!!
	double start_ts = timed ? get_ts() : 0;

	int n = pool_vector.size();

	// please note: it is not required that this offset is cryptographically
	// random, it is only used to "spread the load" over all the pools
	int index_offset = rand();
	if (index_offset >= INT_MAX - (n + 1))
		index_offset /= 2;

	for(int loop_index=0; loop_index<n; loop_index++)
	{
		int index = abs(loop_index + index_offset) % n;

		pthread_cond_t *cond = NULL;
		if (timed)
		{
			double cur_max_duration = calc_time_left(start_ts, loop_index, n, max_duration);

			cond = pool_vector.at(index) -> timed_lock_object(cur_max_duration);
		}
		else
			cond = pool_vector.at(index) -> lock_object();

		if (!cond)
		{
			if (!pool_vector.at(index) -> is_almost_full())
				return index;

			pool_vector.at(index) -> unlock_object();
		}
	}

	return -1;
}

// returns a locked pool
int pools::select_pool_to_add_to(bool timed, double max_time, pool_crypto *pc)
{
	double start_ts = timed ? get_ts() : 0.0;

	list_rlock();
	double left = timed ? calc_time_left(start_ts, max_time) : -1.0;

	int index = find_non_full_pool(timed, left);

	if (index == -1)
	{
		list_runlock();
		list_wlock();
		// at this point (due to context switching between the unlock and the
		// wlock), there may already be a non-empty pool: that is not a problem

		if (pool_vector.size() >= max_n_mem_pools)
			store_caches(std::max(0, int(pool_vector.size()) - int(min_store_on_disk_n)));

		// see if the number of in-memory pools is reduced after the call to store_caches
		// it might have not stored any on disk if the limit on the number of files has been reached
		if (pool_vector.size() < max_n_mem_pools)
		{
			dolog(LOG_DEBUG, "Adding empty pool to queue (new number of pools: %d)", pool_vector.size() + 1);

			pool_vector.push_back(new pool(new_pool_size, bce, pc));
		}

		list_wunlock();
		list_rlock();

		left = timed ? calc_time_left(start_ts, max_time) :  -1.0;

		index = find_non_full_pool(timed, left);
		if (index == -1)
		{
			// this can happen if
			// 1. the number of in-memory-pools limit has been reached and
			// 2. the number of on-disk-pools limit has been reached
			my_mutex_lock(&lat_lck);
			last_added_to++;
			last_added_to %= pool_vector.size();
			index = last_added_to;
			my_mutex_unlock(&lat_lck);

			left = calc_time_left(start_ts, max_time);

			if (pool_vector.at(index) -> timed_lock_object(left))
				index = -1;
		}
	}

	if (index != -1)
	{
		my_mutex_lock(&lat_lck);
		last_added_to = index;
		my_mutex_unlock(&lat_lck);
	}

	return index;
}

int pools::get_bit_sum_unlocked(double max_duration)
{
	double start_ts = get_ts();

	int bit_count = 0;
	unsigned int n = pool_vector.size();
	for(unsigned int index=0; index<n; index++)
	{
		double time_left = calc_time_left(start_ts, index, n, max_duration);

		if (!pool_vector.at(index) -> timed_lock_object(time_left))
		{
			bit_count += pool_vector.at(index) -> get_n_bits_in_pool();

			pool_vector.at(index) -> unlock_object();
		}
	}

	return bit_count;
}

int pools::get_bits_from_pools(int n_bits_requested, unsigned char **buffer, bool allow_prng, bool ignore_rngtest_fips140, fips140 *pfips, bool ignore_rngtest_scc, scc *pscc, double max_duration, pool_crypto *pc)
{
	my_assert(n_bits_requested > 0);

	pthread_testcancel();
	pthread_check(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL), "pthread_setcancelstate");

	double start_ts = get_ts();

	int n_to_do_bytes = (n_bits_requested + 7) / 8;
	int n_to_do_bits = n_to_do_bytes * 8;
	int n_bits_retrieved = 0;

	unsigned char *cur_p = *buffer = reinterpret_cast<unsigned char *>(malloc_locked(n_to_do_bytes + 1));
	if (!cur_p)
		error_exit("transmit_bits_to_client memory allocation failure");

	// load bits from disk if needed
	bool have_bits = true;
	for(;;)
	{
		list_rlock();
		if (!have_bits)
			break;

		int bits_needed_to_load = n_bits_requested - get_bit_sum_unlocked(max_duration);

		// no unlock in the break: need to have the list locked later on
		if (bits_needed_to_load <= 0)
			break;

		// a 'list_relock' would be nice
		list_runlock();
		pthread_testcancel();
		list_wlock();

		merge_pools(pc);
		flush_empty_pools();

		// due to the un- and relock this might have changed
		// also merging pools might change this value
		have_bits = load_caches(bits_needed_to_load, pc);

		list_wunlock();
		pthread_testcancel();
	}
	// at this point the list is read locked

	unsigned int n = pool_vector.size();

	int pool_block_size = -1, get_per_pool_n = -1;
	if (n == 0)
	{
		pool_block_size = pc -> get_hasher() -> get_hash_size() / 2;
		get_per_pool_n = std::max(pool_block_size, n_bits_requested);
	}
	else
	{
		pool_block_size = pool_vector.at(0) -> get_get_size();
		get_per_pool_n = std::max(pool_block_size, n_bits_requested / int(n));
	}
	get_per_pool_n = std::min(get_per_pool_n, new_pool_size);

	int index_offset = rand();
	if (index_offset >= INT_MAX - int(n + 1))
		index_offset /= 2;

	int round = 0;

	for(;n_to_do_bits > 0 && round < 2;)
	{
		// please note: it is not required that this offset is cryptographically
		// random, it is only used to "spread the load" over all the pools
		for(unsigned int loop_index=0; loop_index<n && n_to_do_bits > 0; loop_index++)
		{
			int index = abs((int)(loop_index + index_offset)) % n;

			double time_left = calc_time_left(start_ts, loop_index, n, max_duration);

			pthread_cond_t *cond = NULL;
			if (round > 0)
				cond = pool_vector.at(index) -> timed_lock_object(time_left);
			else
				cond = pool_vector.at(index) -> lock_object();

			if (!cond)
			{
				int cur_n_to_get_bits = (round > 0 && allow_prng) ? get_per_pool_n : n_to_do_bits;
				int cur_n_to_get_bytes = (cur_n_to_get_bits + 7) / 8;

				unsigned int got_n_bytes = pool_vector.at(index) -> get_entropy_data(cur_p, cur_n_to_get_bytes, round > 0 ? allow_prng : false, pc);
				unsigned int got_n_bits = got_n_bytes * 8;

				if (got_n_bits > 0 && verify_quality(cur_p, got_n_bytes, ignore_rngtest_fips140, pfips, ignore_rngtest_scc, pscc))
				{
					cur_p += got_n_bytes;
					n_to_do_bits -= got_n_bits;
					n_bits_retrieved += got_n_bits;

					dolog(LOG_DEBUG, "Retrieved %d bits from pool %d", got_n_bits, index);
				}

				pool_vector.at(index) -> unlock_object();
			}
		}

		round++;
	}

	list_runlock();

	pthread_check(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL), "pthread_setcancelstate");
	pthread_testcancel();

	return n_bits_retrieved;
}

int pools::add_bits_to_pools(unsigned char *data, int n_bytes, bool ignore_rngtest_fips140, fips140 *pfips, bool ignore_rngtest_scc, scc *pscc, double max_duration, pool_crypto *pc)
{
	my_assert(n_bytes > 0);

	pthread_testcancel();
	pthread_check(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL), "pthread_setcancelstate");

	double start_ts = get_ts();

	int n_bits_added = 0;
	int start_n = n_bytes;

	int round = 0, n_was_locked = 0;
	bool first = true;
	while(n_bytes > 0)
	{
		if (first)
		{
			list_rlock();
			first = false;
		}

		int n = pool_vector.size();

		list_runlock();
		pthread_testcancel();

		double time_left = calc_time_left(start_ts, start_n - n_bytes, start_n, max_duration);

		int index = select_pool_to_add_to(round > 0, time_left, pc); // returns a locked object
		// the list is now read-locked

		if (index == -1)
		{
			if (++n_was_locked >= n)
			{
				n_was_locked = 0;
				round++;
			}
		}
		else
		{
			int space_available = pool_vector.at(index) -> get_pool_size() - pool_vector.at(index) -> get_n_bits_in_pool();
			// in that case we're already mixing in so we can change all data anyway
			// this only happens when all pools are full
			if (space_available <= pool_vector.at(index) -> get_get_size_in_bits())
				space_available = pool_vector.at(index) -> get_pool_size();

			unsigned int n_bytes_to_add = std::min(n_bytes, (space_available + 7) / 8);
			dolog(LOG_DEBUG, "Adding %d bits to pool %d", n_bytes_to_add * 8, index);

			if (verify_quality(data, n_bytes_to_add, ignore_rngtest_fips140, pfips, ignore_rngtest_scc, pscc))
				n_bits_added += pool_vector.at(index) -> add_entropy_data(data, n_bytes_to_add, pc);

			n_bytes -= n_bytes_to_add;
			data += n_bytes_to_add;

			pool_vector.at(index) -> unlock_object();
		}
	}

	list_runlock();

	pthread_check(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL), "pthread_setcancelstate");
	pthread_testcancel();

	return n_bits_added;
}

int pools::get_bit_sum(double max_duration)
{
	pthread_testcancel();
	pthread_check(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL), "pthread_setcancelstate");

	list_rlock();
	int bit_count = get_bit_sum_unlocked(max_duration);
	list_runlock();

	pthread_check(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL), "pthread_setcancelstate");
	pthread_testcancel();

	return bit_count;
}

int pools::add_event(long double event, unsigned char *event_data, int n_event_data, double max_time, pool_crypto *pc)
{
	pthread_testcancel();
	pthread_check(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL), "pthread_setcancelstate");

	int index = select_pool_to_add_to(true, max_time, pc); // returns a locked object
	// the list is now read-locked and the object as well

	int rc = 0;
	if (index != -1)
	{
		rc = pool_vector.at(index) -> add_event(event, event_data, n_event_data, pc);

		pool_vector.at(index) -> unlock_object();
	}

	list_runlock();

	pthread_check(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL), "pthread_setcancelstate");
	pthread_testcancel();

	return rc;
}

bool pools::all_pools_full(double max_duration)
{
	pthread_testcancel();
	pthread_check(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL), "pthread_setcancelstate");

	double start_ts = get_ts();

	bool rc = true;

	list_rlock();

	unsigned int n = pool_vector.size();

	if (n < max_n_mem_pools)
		rc = false;
	else
	{
		for(unsigned int loop=0; loop<n; loop++)
		{
			double time_left = calc_time_left(start_ts, loop, n, max_duration);

			if (!pool_vector.at(loop) -> timed_lock_object(time_left))
			{
				if (!pool_vector.at(loop) -> is_almost_full())
				{
					pool_vector.at(loop) -> unlock_object();

					rc = false;
					break;
				}

				pool_vector.at(loop) -> unlock_object();
			}
		}
	}

	list_runlock();

	pthread_check(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL), "pthread_setcancelstate");
	pthread_testcancel();

	return rc;
}

int pools::get_memory_pool_count()
{
	list_rlock();
	int n = pool_vector.size();
	list_runlock();

	return n;
}

int pools::get_disk_pool_count()
{
	list_rlock();
	int n = cache_list.size();
	list_runlock();

	return n;
}

int pools::get_disk_pool_bit_count()
{
	int bit_sum = 0;

	list_rlock();
	for(unsigned int index=0; index<cache_list.size(); index++)
		bit_sum += cache_list.at(index).second;
	list_runlock();

	return bit_sum;
}
