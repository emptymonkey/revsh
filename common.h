
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

/*
	The maximum size buffer needed to handle any single side of a socks 
	protocol conversation is the Username / Password negotiation.
		+----+------+----------+------+----------+
		|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		+----+------+----------+------+----------+
		| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		+----+------+----------+------+----------+

	1 + 1 + 255 + 1 + 255 
	= 513

	All other requests / responses are smaller than this. (Some exceptions,
	such as UDP are being overlooked here as we have no plans to implement
	the UDP portion of the protocol.)
*/
#define MAX_SOCKS_BUFFER_SIZE	513

#define SOCKS_NO_HANDSHAKE	0
#define SOCKS_V4_COMPLETE 1
#define SOCKS_V4A_COMPLETE 2
#define SOCKS_V5_AUTH	3
#define SOCKS_V5_COMPLETE	4


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
struct connection_node *connection_node_create(struct connection_node **head);
int connection_node_delete(unsigned short origin, unsigned short id, struct connection_node **head);
struct connection_node *connection_node_find(unsigned short origin, unsigned short id, struct connection_node **head);
int parse_socks_request(struct connection_node *cur_connection_node);
char *addr_to_string(int atype, char *addr, char *port, int len);
int proxy_response(int sock, char ver, char cmd, char *buffer, int buffer_size);



/**********************************************************************************************************************
 *
 * Protocol Specification:
 *
 *	Header:
 *		- header_len		: unsigned short (network order)
 *				This is the size of the remaining header data.
 *		- data_type			:	unsigned char
 *		- data_len			:	unsigned short (network order)
 *		- Other data_type specific headers, as needed.
 *
 *	Other headers for DT_PROXY and DT_CONNECTION:
 *		- header_type		: unsigned short (network order)
 *		- header_id			: unsigned long (network order)
 *
 *	Body:
 *		- data					:	void *
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

/* DT_NOP: No Operation dummy message used for keep-alive. */
// XXX implement this!
#define DT_NOP	6
