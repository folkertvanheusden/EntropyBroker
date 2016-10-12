#include <stdlib.h>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <pthread.h>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "statistics.h"
#include "statistics_user.h"
#include "users.h"

users::users(std::string filename_in, int default_max_get_bps_in) : filename(filename_in), default_max_get_bps(default_max_get_bps_in)
{
	pthread_check(pthread_rwlock_init(&rwlck, NULL), "pthread_rwlock_init");

	user_map = NULL;
	load_usermap();
}

users::~users()
{
	delete user_map;

	pthread_check(pthread_rwlock_destroy(&rwlck), "pthread_rwlock_destroy");
}

void users::list_wlock()
{
	pthread_check(pthread_rwlock_wrlock(&rwlck), "pthread_rwlock_wrlock");
}

void users::list_wunlock()
{
	pthread_check(pthread_rwlock_unlock(&rwlck), "pthread_rwlock_unlock");
}

void users::list_runlock()
{
	pthread_check(pthread_rwlock_unlock(&rwlck), "pthread_rwlock_unlock");
}

void users::list_rlock()
{
	pthread_check(pthread_rwlock_rdlock(&rwlck), "pthread_rwlock_rdlock");
}

void users::reload()
{
	dolog(LOG_INFO, "Reload user database");

	list_wlock();

	std::map<std::string, user_t>::iterator it;
	for(it = user_map -> begin(); it != user_map -> end(); it++)
		pthread_check(pthread_mutex_destroy(&it -> second.lck), "pthread_mutex_destroy");

	delete user_map;

	load_usermap();

	list_wunlock();
}

void users::load_usermap()
{
	user_map = new std::map<std::string, user_t>();

	std::ifstream fh(filename.c_str());
	if (!fh.is_open())
		error_exit("Cannot open %s", filename.c_str());

	std::string line;
	int line_nr = 0;
	while(!fh.eof())
	{
		std::getline(fh, line);
		if (line.length() == 0)
			break;

		line_nr++;

		std::vector<std::string> pars = split_string(line, "|");
		if (pars.size() == 1)
			error_exit("%s: separator missing at line %d (%s)", filename.c_str(), line_nr, line.c_str());

		user_t u;
		u.password = pars[1];
		if (pars.size() >= 3)
			u.allowance = u.max_get_bps = atoi(pars[2].c_str());
		else
			u.allowance = u.max_get_bps = default_max_get_bps;
		u.last_get_message = 0.0;

		if (pars.size() >= 4)
			u.allow_rw = pars[3].compare("yes") == 0;
		else
			u.allow_rw = true;

		pthread_check(pthread_mutex_init(&u.lck, &global_mutex_attr), "pthread_mutex_init");

		std::string username = pars[0];
		u.username = username;

		if (username.length() == 0 || u.password.length() == 0)
			error_exit("%s: username/password cannot be empty at line %d (%s)", filename.c_str(), line_nr, line.c_str());

		(*user_map)[username] = u;
	}

	fh.close();
}

user_t *users::find_user(std::string username)
{
	std::map<std::string, user_t>::iterator it = user_map -> find(username);
	if (it == user_map -> end())
	{
		dolog(LOG_WARNING, "User %s not known", username.c_str());
		return NULL;
	}

	return &it -> second;
}

bool users::get_password(std::string username, std::string & password)
{
	password.assign("DEFINITELY WRONG  PASSWORd");

	list_rlock();

	user_t *u = find_user(username);
	if (u)
		password.assign(u -> password);

	list_runlock();

	return u ? true : false;
}

// http://stackoverflow.com/questions/667508/whats-a-good-rate-limiting-algorithm
int users::calc_max_allowance(std::string username, double now, int n_requested)
{
	list_rlock();

	int n = -1;

	user_t *u = find_user(username);

	if (u)
	{
		my_mutex_lock(&u -> lck);

		double rate = u -> max_get_bps;	// unit: messages
		double per = 1.0;	// unit: seconds
		double allowance = u -> allowance; // unit: messages

		double last_check = u -> last_get_message; // floating-point, e.g. usec accuracy. Unit: seconds

		double time_passed = now - last_check;
		allowance += time_passed * (rate / per);

		if (allowance > rate)
			allowance = rate; // throttle

		if (allowance < 8.0) // 8 bits in a byte
			n = 0;
		else
			n = std::min(n_requested, int(allowance));

		u -> allowance = allowance;
	}

	return n;
}

bool users::use_allowance(std::string username, int n)
{
	user_t *u = find_user(username);

	if (u)
	{
		u -> allowance -= n;

		u -> last_get_message = get_ts();

		my_mutex_unlock(&u -> lck);
	}

	list_runlock();

	return u ? true : false;
}

bool users::cancel_allowance(std::string username)
{
	user_t *u = find_user(username);

	if (u)
		my_mutex_unlock(&u -> lck);

	list_runlock();

	return u ? true : false;
}

std::vector<std::string> users::get_users()
{
	std::vector<std::string> list;

	std::map<std::string, user_t>::iterator it = user_map -> begin();

	list_rlock();
	for(;it != user_map -> end(); it++)
		list.push_back(it -> first);
	list_runlock();

	return list;
}

double users::get_last_login(std::string username)
{
	double rc = 0.0;

	list_rlock();

	user_t *u = find_user(username);
	if (u)
		rc = u -> last_logon;

	list_runlock();

	return rc;
}

void users::set_last_login(std::string username, double when_ts)
{
	list_rlock();

	user_t *u = find_user(username);
	if (u)
		u -> last_logon = when_ts;

	list_runlock();
}

user_t *users::find_and_lock_user(std::string username)
{
	list_rlock();

	user_t *u = find_user(username);
	if (!u)
		u = &dummy_user;

	my_mutex_lock(&u -> lck);

	return u;
}

void users::unlock_user(user_t *u)
{
	my_mutex_unlock(&u -> lck);

	list_runlock();
}

// ***** user statistics *****
void users::inc_disconnects(std::string username)
{
        user_t *u = find_and_lock_user(username);

        if (u)
        {
		u -> stats_user() -> inc_disconnects();

		unlock_user(u);
	}
}

void users::inc_timeouts(std::string username)
{
        user_t *u = find_and_lock_user(username);

        if (u)
        {
		u -> stats_user() -> inc_timeouts();

		unlock_user(u);
	}
}

void users::inc_n_times_empty(std::string username)
{
        user_t *u = find_and_lock_user(username);

        if (u)
        {
		u -> stats_user() -> inc_n_times_empty();

		unlock_user(u);
	}
}

void users::inc_n_times_quota(std::string username)
{
        user_t *u = find_and_lock_user(username);

        if (u)
        {
		u -> stats_user() -> inc_n_times_quota();

		unlock_user(u);
	}
}

void users::inc_n_times_full(std::string username)
{
        user_t *u = find_and_lock_user(username);

        if (u)
        {
		u -> stats_user() -> inc_n_times_full();

		unlock_user(u);
	}
}

void users::inc_msg_cnt(std::string username)
{
        user_t *u = find_and_lock_user(username);

        if (u)
        {
		u -> stats_user() -> inc_msg_cnt();

		unlock_user(u);
	}
}

void users::inc_submit_while_full(std::string username)
{
        user_t *u = find_and_lock_user(username);

        if (u)
        {
		u -> stats_user() -> inc_submit_while_full();

		unlock_user(u);
	}
}

void users::inc_network_error(std::string username)
{
        user_t *u = find_and_lock_user(username);

        if (u)
        {
		u -> stats_user() -> inc_network_error();

		unlock_user(u);
	}
}

void users::inc_protocol_error(std::string username)
{
        user_t *u = find_and_lock_user(username);

        if (u)
        {
		u -> stats_user() -> inc_protocol_error();

		unlock_user(u);
	}
}

void users::inc_misc_errors(std::string username)
{
        user_t *u = find_and_lock_user(username);

        if (u)
        {
		u -> stats_user() -> inc_misc_errors();

		unlock_user(u);
	}
}

void users::track_sents(std::string username, int cur_n_bits)
{
        user_t *u = find_and_lock_user(username);

        if (u)
        {
		u -> stats_user() -> track_sents(cur_n_bits);

		unlock_user(u);
	}
}

void users::track_recvs(std::string username, int n_bits_added, int n_bits_added_in)
{
        user_t *u = find_and_lock_user(username);

        if (u)
        {
		u -> stats_user() -> track_recvs(n_bits_added, n_bits_added_in);

		unlock_user(u);
	}
}

void users::register_msg(std::string username, bool is_put)
{
	user_t *u = find_and_lock_user(username);

	if (u)
	{
		u -> stats_user() -> register_msg(is_put);

		unlock_user(u);
	}
}

int users::get_reset_bps_cur(std::string username)
{
	int rc = -1;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                rc = u -> stats_user() -> get_reset_bps_cur();

                unlock_user(u);
        }

	return rc;
}

int users::get_msg_cnt(std::string username)
{       
	int rc = -1;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                rc = u -> stats_user() -> get_msg_cnt();
        
                unlock_user(u);
        }

	return rc;
}

int users::get_disconnects(std::string username)
{       
	int rc = -1;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                rc = u -> stats_user() -> get_disconnects();
        
                unlock_user(u);
        }

	return rc;
}

int users::get_times_empty(std::string username)
{       
	int rc = -1;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                rc = u -> stats_user() -> get_times_empty();
        
                unlock_user(u);
        }

	return rc;
}

int users::get_times_full(std::string username)
{       
	int rc = -1;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                rc = u -> stats_user() -> get_times_full();
        
                unlock_user(u);
        }

	return rc;
}

int users::get_times_quota(std::string username)
{       
	int rc = -1;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                rc = u -> stats_user() -> get_times_quota();
        
                unlock_user(u);
        }

	return rc;
}

int users::get_submit_while_full(std::string username)
{       
	int rc = -1;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                rc = u -> stats_user() -> get_submit_while_full();
        
                unlock_user(u);
        }

	return rc;
}

int users::get_network_error(std::string username)
{       
	int rc = -1;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                rc = u -> stats_user() -> get_network_error();
        
                unlock_user(u);
        }

	return rc;
}

int users::get_protocol_error(std::string username)
{       
	int rc = -1;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                rc = u -> stats_user() -> get_protocol_error();
        
                unlock_user(u);
        }

	return rc;
}

int users::get_misc_errors(std::string username)
{       
	int rc = -1;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                rc = u -> stats_user() -> get_misc_errors();
        
                unlock_user(u);
        }

	return rc;
}

void users::get_recvs(std::string username, long long int *total_bits, int *n_reqs, long long int *total_bits_in)
{       
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                u -> stats_user() -> get_recvs(total_bits, n_reqs, total_bits_in);
        
                unlock_user(u);
        }
}

void users::get_sents(std::string username, long long int *total_bits, int *n_sents)
{       
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                u -> stats_user() -> get_sents(total_bits, n_sents);
        
                unlock_user(u);
        }
}

double users::get_last_msg_ts(std::string username)
{       
	double rc = -1.0;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                rc = u -> stats_user() -> get_last_msg_ts();
        
                unlock_user(u);
        }

	return rc;
}

double users::get_last_put_msg_ts(std::string username)
{       
	double rc = -1.0;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                rc = u -> stats_user() -> get_last_put_msg_ts();
        
                unlock_user(u);
        }

	return rc;
}

double users::get_last_get_msg_ts(std::string username)
{       
	double rc = -1.0;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                rc = u -> stats_user() -> get_last_get_msg_ts();
        
                unlock_user(u);
        }

	return rc;
}

void users::get_sent_avg_sd(std::string username, double *avg, double *sd)
{       
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                u -> stats_user() -> get_sent_avg_sd(avg, sd);
        
                unlock_user(u);
        }
}

void users::get_recv_avg_sd(std::string username, double *avg, double *sd)
{       
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                u -> stats_user() -> get_recv_avg_sd(avg, sd);
        
                unlock_user(u);
        }
}

void users::get_recv_in_avg_sd(std::string username, double *avg, double *sd)
{       
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
                u -> stats_user() -> get_recv_in_avg_sd(avg, sd);
        
                unlock_user(u);
        }
}

bool users::get_is_rw(const std::string & username)
{
	bool allow = false;
        user_t *u = find_and_lock_user(username); 
        
        if (u) 
        {
		allow = u -> allow_rw;

		unlock_user(u);
	}

	return allow;
}
