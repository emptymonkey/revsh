
#ifndef FREEBSD
# define _POSIX_C_SOURCE 200112L
# define _XOPEN_SOURCE  1
#endif /* FREEBSD */


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


#include "helper_objects.h"

#include "config.h"

#define TARGET_CERT_FILE "target_cert.pem"
#define CONTROLLER_CERT_FILE "controller_cert.pem"
#define CONTROLLER_KEY_FILE "controller_key.pem"

/* Encryption definitions. */
#define PLAINTEXT 0
#define ADH 1
#define EDH 2

#define LOCAL_BUFF_SIZE	128

/* Proxy types */
#define PROXY_LOCAL 0
#define PROXY_DYNAMIC 1

#define DEFAULT_PROXY_ADDR "127.0.0.1"

/* Connection states for proxy connections. */
#define CON_SOCKS_NO_HANDSHAKE	0
#define CON_SOCKS_V5_AUTH	1
#define CON_READY 2
#define CON_ACTIVE 3
#define CON_DORMANT 4

/* The max number of messages we will queue for delivery before requesting the remote client to throttle the connection. */
#define MESSAGE_DEPTH_MAX	64

/* We will set this up ourselves for portability. */
char *program_invocation_short_name;

/* These variables are global because they won't change (once initialized) */
/* and any given part of the code may need to reference them. */
int pagesize;
int verbose;

char **string_to_vector(char *command_string);
void free_vector(char **vector);

int init_io_controller(struct io_helper *io, struct config_helper *config);
int init_io_target(struct io_helper *io, struct config_helper *config);

int remote_read_plaintext(struct io_helper *io, void *buf, size_t count);
int remote_write_plaintext(struct io_helper *io, void *buf, size_t count);

#ifdef OPENSSL
int remote_read_encrypted(struct io_helper *io, void *buf, size_t count);
int remote_write_encrypted(struct io_helper *io, void *buf, size_t count);

int dummy_verify_callback(int preverify_ok, X509_STORE_CTX* ctx);
#endif /* OPENSSL */

int message_pull(struct io_helper *io);
int message_push(struct io_helper *io);
struct message_helper *message_helper_create(char *data, unsigned short data_len, unsigned short message_data_size);
void message_helper_destroy(struct message_helper *mh);

int remote_printf(struct io_helper *io, char *fmt, ...);
int print_error(struct io_helper *io, char *fmt, ...);
int negotiate_protocol(struct io_helper *io);

int do_control(struct io_helper *io, struct config_helper *config);
int do_target(struct io_helper *io, struct config_helper *config);

int broker(struct io_helper *io, struct config_helper *config);
void signal_handler(int signal);

void catch_alarm(int signal);

#ifndef FREEBSD
int posix_openpt(int flags);
#endif /* FREEBSD */

struct proxy_node *proxy_node_new(char *proxy_string, int proxy_type);
int proxy_listen(struct proxy_node *cur_proxy_node);
int proxy_connect(char *rhost_rport);

struct connection_node *connection_node_create(struct io_helper *io);
int connection_node_delete(struct io_helper *io, unsigned short origin, unsigned short id);
struct connection_node *connection_node_find(struct io_helper *io, unsigned short origin, unsigned short id);
void connection_node_queue(struct io_helper *io, struct connection_node *cur_connection_node);

int parse_socks_request(struct connection_node *cur_connection_node);
char *addr_to_string(int atype, char *addr, char *port, int len);
int proxy_response(int sock, char ver, char cmd, char *buffer, int buffer_size);

int handle_signal_sigwinch(struct io_helper *io);
int handle_local_write(struct io_helper *io);
int handle_local_read(struct io_helper *io);
int handle_message_dt_tty(struct io_helper *io);
int handle_message_dt_winresize(struct io_helper *io);
int handle_message_dt_proxy_ht_destroy(struct io_helper *io);
int handle_message_dt_proxy_ht_create(struct io_helper *io);
int handle_message_dt_proxy_ht_response(struct io_helper *io);
int handle_message_dt_connection(struct io_helper *io);
int handle_proxy_read(struct io_helper *io, struct proxy_node *cur_proxy_node);
int handle_connection_write(struct io_helper *io, struct connection_node *cur_connection_node);
int handle_connection_read(struct io_helper *io, struct connection_node *cur_connection_node);



/**********************************************************************************************************************
 *
 * Message Bus Protocol Specification:
 *
 *	Header:
 *		- header_len		: unsigned short (network order)
 *			-- This is the size of the remaining header data.
 *		- data_type			:	unsigned char
 *		- data_len			:	unsigned short (network order)
 *		- Other data_type specific headers, as needed.
 *
 *	Other headers used with DT_PROXY and DT_CONNECTION:
 *		- header_type		: unsigned short (network order)
 *		- header_id			: unsigned long (network order)
 *
 *	Body:
 *		- data					:	void *
 *
 *
 *	The naming convetion below is DT for "Data Type" and HT for "Header Type".
 *	E.g. DT_PROXY_HT_CREATE denotes a message where the data type is that of a proxy, but the header will have
 *  additional information relating to the type of request, in this case "create" the proxy.
 *
 **********************************************************************************************************************/

/* This is the smallest message size we will respect when asked by the remote connection. */
#define MINIMUM_MESSAGE_SIZE	1024

/* Data Types */
/* DT_INIT: Initialization sequence data. */
#define DT_INIT				1

/* DT_TTY: TTY interaction data. */
#define DT_TTY				2

/* DT_WINRESIZE: Window re-size event data. */
#define DT_WINRESIZE	3

/* DT_PROXY: Proxy meta-data. (e.g. setup, teardown, etc.) */
#define DT_PROXY			4
/*
	In a DT_PROXY_HT_CREATE request, the first char will be ver, the second char will be cmd.
	Null terminated rhost_rport string follows.
*/
#define DT_PROXY_HT_CREATE	1
#define DT_PROXY_HT_DESTROY	2
#define DT_PROXY_HT_RESPONSE 3

/* DT_CONNECTION: Proxy data for established connections. */
#define DT_CONNECTION	5
/*
	DT_CONNECTION_HT_DORMANT: used when a local fd would block for writting, and our message queue is getting deep.
		Tells the other side to stop reading from the associated remote fd until otherwise notified. Reset to normal
		withDT_CONNECTION_HT_ACTIVE. 
*/
#define DT_CONNECTION_HT_DATA	0
#define DT_CONNECTION_HT_DORMANT	1
#define DT_CONNECTION_HT_ACTIVE	2

/* DT_NOP: No Operation dummy message used for keep-alive. */
// XXX implement this!
#define DT_NOP	6

/* DT_DEBUG: Used to send error reporting to be served up via an alternative delivery mechanism. (e.g. fifo, socket, log_file, etc.) */
// XXX implement this!
#define DT_DEBUG	7

