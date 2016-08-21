
#ifndef FREEBSD
# define _POSIX_C_SOURCE 200112L
# define _XOPEN_SOURCE  1
#endif 


#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <wordexp.h>

#include <arpa/inet.h>

#ifdef OPENSSL
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#else
#include <netdb.h>
#endif /* OPENSSL */

#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <net/if.h>
// XXX find freebsd equivalent.
# include <linux/if.h>
# include <linux/if_tun.h>

#include "helper_objects.h"
#include "config.h"
#include "protocol.h"

#define TARGET_CERT_FILE "target_cert.pem"
#define CONTROLLER_CERT_FILE "controller_cert.pem"
#define CONTROLLER_KEY_FILE "controller_key.pem"

/* Encryption definitions. */
#define PLAINTEXT 0
#define ADH 1
#define EDH 2

#define DEFAULT_PROXY_ADDR "127.0.0.1"
#define DEV_NET_TUN	"/dev/net/tun"

/* Connection states for proxy connections. */
#define CON_SOCKS_NO_HANDSHAKE	0
#define CON_SOCKS_V5_AUTH	1
#define CON_READY 2
#define CON_EINPROGRESS 3
#define CON_ACTIVE 4
#define CON_DORMANT 5

/* The max number of messages we will queue for delivery before requesting the remote client to throttle the connection. */
#define MESSAGE_DEPTH_MAX	64


/* We will set this up ourselves for portability. */
char *program_invocation_short_name;

/* These variables are global because they won't change (once initialized) */
/* and any given part of the code may need to reference them. */
int pagesize;
int verbose;

/*
	 This struct represents the overall state of the I/O. It was being passed around as a function argument, but it was getting passed everywhere... 
	 Once we cleaned up error reporting and it was obvious all code needed access to this struct in order to do the right thing upon error, and I decided to
	 just make it a global. It's being used globally, no need to pretend it's something other than what it is.
 */
struct io_helper *io;

char **string_to_vector(char *command_string);
void free_vector(char **vector);

int init_io_controller(struct config_helper *config);
int init_io_target(struct config_helper *config);

int remote_read_plaintext(void *buf, size_t count);
int remote_write_plaintext(void *buf, size_t count);

#ifdef OPENSSL
int remote_read_encrypted(void *buf, size_t count);
int remote_write_encrypted(void *buf, size_t count);

int dummy_verify_callback(int preverify_ok, X509_STORE_CTX* ctx);
#endif /* OPENSSL */

int message_pull();
int message_push();
struct message_helper *message_helper_create(char *data, unsigned short data_len, unsigned short message_data_size);
void message_helper_destroy(struct message_helper *mh);

int remote_printf(char *fmt, ...);
int negotiate_protocol();

void report_error(char *fmt, ...);
int report_log(char *fmt, ...);
int report_log_string(char *error_string);

int do_control(struct config_helper *config);
int do_target(struct config_helper *config);

int broker(struct config_helper *config);
void signal_handler(int signal);

void catch_alarm(int signal);

#ifndef FREEBSD
int posix_openpt(int flags);
#endif /* FREEBSD */

struct proxy_node *proxy_node_new(char *proxy_string, int proxy_type);
int proxy_listen(struct proxy_node *cur_proxy_node);
int proxy_connect(char *rhost_rport);

struct connection_node *connection_node_create();
int connection_node_delete(struct connection_node *);
struct connection_node *connection_node_find(unsigned short origin, unsigned short id);
void connection_node_queue(struct connection_node *cur_connection_node);
struct connection_node *handle_tun_tap_init(int ifr_flag);

int parse_socks_request(struct connection_node *cur_connection_node);
char *addr_to_string(int atype, char *addr, char *port, int len);
int proxy_response(int sock, char ver, char cmd, char *buffer, int buffer_size);

int handle_signal_sigwinch();
int handle_local_write();
int handle_local_read();
int handle_message_dt_tty();
int handle_message_dt_winresize();
int handle_message_dt_proxy_ht_destroy();
int handle_message_dt_proxy_ht_create();
int handle_message_dt_proxy_ht_response();
int handle_con_activate(struct connection_node *cur_connection_node);
int handle_message_dt_connection();
int handle_proxy_read(struct proxy_node *cur_proxy_node);
int handle_connection_write(struct connection_node *cur_connection_node);
int handle_connection_read(struct connection_node *cur_connection_node);
int handle_send_nop();
