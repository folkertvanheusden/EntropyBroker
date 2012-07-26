#define min(x, y)       ((x)<(y)?(x):(y))
#define max(x, y)       ((x)>(y)?(x):(y))

double get_ts(void);
long double get_ts_ns(void);
int READ(int fd, char *whereto, size_t len);
int READ_TO(int fd, char *whereto, size_t len, int to);
int WRITE(int fd, char *whereto, size_t len);
int WRITE_TO(int fd, char *whereto, size_t len, int to);
int start_listen(char *adapter, int portnr, int listen_queue_size);
int connect_to(char *host, int portnr);
void disable_nagle(int fd);
void enable_tcp_keepalive(int fd);
double mydrand();
int myrand();
int myrand(int max);
void write_pid(const char *file);