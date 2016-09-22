

#ifndef FREEBSD
# define _POSIX_C_SOURCE 200112L
# define _XOPEN_SOURCE  1
#endif 

// GENERIC_BUILD will set the binary to build with opptions geared toward a non-custom build. 
// This option exists to ease building a community binary for inclusion in a generic toolkit / distribution.
//#define GENERIC_BUILD

/******************************************************************************
 * system headers
 ******************************************************************************/

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
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

/******************************************************************************
 * OS specific headers
 ******************************************************************************/

#ifdef FREEBSD

# include <netinet/in.h>

#else // Linux

# include <linux/if.h>
# include <linux/if_tun.h>

#endif


/******************************************************************************
 * linenoise library header
 ******************************************************************************/

#ifdef LINENOISE
# include "linenoise.h"
#endif


/******************************************************************************
 * revsh headers
 ******************************************************************************/

#include "helper_objects.h"
#include "config.h"
#include "protocol.h"


/******************************************************************************
 * constant definitions
 ******************************************************************************/

#define TARGET_CERT_FILE "target_cert.pem"
#define CONTROLLER_CERT_FILE "control_cert.pem"
#define CONTROLLER_KEY_FILE "control_key.pem"

/* Encryption definitions. */
#define PLAINTEXT 0
#define ADH 1
#define EDH 2

#define DEFAULT_PROXY_ADDR "127.0.0.1"
#define DEV_NET_TUN	"/dev/net/tun"

/* Connection states for proxy connections. */
#define CON_SOCKS_INIT 0
#define CON_SOCKS_V5_AUTH 1
#define CON_EINPROGRESS 2
#define CON_ACTIVE 3
#define CON_DORMANT 4

/* Reply strings for socks requests are static in the modern era. */
#define SOCKS_V4_REPLY "\x00\x5a\x00\x00\x00\x00\x00\x00"
#define SOCKS_V4_REPLY_LEN 8
#define SOCKS_V5_AUTH_REPLY "\x05\x00"
#define SOCKS_V5_AUTH_REPLY_LEN 2
#define SOCKS_V5_REPLY "\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
#define SOCKS_V5_REPLY_LEN 10

/* Maximum possible size of a socks request. */
/*
	 Max size cases:
	 Socks 4: 9 byte header. (Our implementation ignores USERID.)  =  9
	 Socks 4a: 9 byte header + domain name (255 max) + null byte  =  265
	 Socks 5: 2 bytes for auth header + 255 max auth types + 6 byte header + domain name size byte + domain name (255 max)  =  519

   In socks 5, the domain name is not null-terminated. Adding one to ensure we will always have a null terminating byte.
 */
#define SOCKS_REQ_MAX	520

/* The max number of messages we will queue for delivery before requesting the remote client to throttle the connection. */
#define MESSAGE_DEPTH_MAX	64

/* States possible in the escape sequence processing state machine. */
#define ESCAPE_NONE 0
#define ESCAPE_CR 1
#define ESCAPE_TILDE 2

/* The max length of the escape sequence command input strings. Arbitrary, but probably more than long enough. */
// MAX_INPUT and MAX_CANON both seem unusually small given that we can take two file names as arguments,
// and each file name can be upwards of 255 characters.
#define ESC_COMMAND_MAX 1024

#define REVSH_PROMPT "revsh>"


/******************************************************************************
 * global variables
 ******************************************************************************/

/* We will set this up ourselves for portability. */
char *program_invocation_short_name;

/* These variables are global because they won't change (once initialized) */
/* and any given part of the code may need to reference them. */
int pagesize;
int verbose;
struct message_helper *message;

/*
	 This struct represents the overall state of the I/O. It was being passed around as a function argument, but it was getting passed everywhere... 
	 Once I cleaned up error reporting it was obvious that all code needed access to this struct in order to do the right thing.
	 I decided to just make it a global. It's being used globally, no need to pretend it's something other than what it is.
 */
struct io_helper *io;
/*
	Same with config. However, this one is a more reasonable global. Once you leave main, it is intended to be read-only.
 */
struct config_helper *config;

/******************************************************************************
 * function definitions
 *  -  See Documentation/CODEMAP for insight into how it all fits together.
 ******************************************************************************/

/* broker.c */
int broker();
void signal_handler(int signal);

/* control.c */
int do_control();

/* escape.c */
int escape_check();
int send_consumed();
int send_message(int count);
void message_shift(int count);
int is_valid_escape(char c);
int process_escape(char c);
void list_all();
void list_listeners();
void list_connections();
void print_valid_escapes();

/* esc_shell.c */
int esc_shell_start();
int esc_shell_stop();
#ifdef LINENOISE
int esc_shell_loop();
void esc_shell_help(char **command_vec);
const struct esc_shell_command *find_in_menu(char **command_vec);
void expand_tab(const char *buf, linenoiseCompletions *lc);
int command_validate(char **command_vec);
char **suggest_files(char *string);
#endif

/* handler.c */
int handle_signal_sigwinch();
int handle_local_write();
int handle_local_read();
int handle_command_shell_read();
int handle_message_dt_tty();
int handle_message_dt_winresize();
int handle_message_dt_proxy_ht_destroy();
int handle_message_dt_proxy_ht_create();
int handle_message_dt_proxy_ht_report();
int handle_message_dt_connection_ht_destroy();
int handle_message_dt_connection_ht_create();
int handle_message_dt_connection_ht_create_tun_tap();
int handle_message_dt_connection_ht_response();
int handle_connection_activate(struct connection_node *cur_connection_node);
int handle_message_dt_connection_ht_active_dormant();
int handle_message_dt_connection_ht_data();
int handle_proxy_read(struct proxy_node *cur_proxy_node);
int handle_connection_write(struct connection_node *cur_connection_node);
int handle_connection_read(struct connection_node *cur_connection_node);
int handle_connection_socks_init(struct connection_node *cur_connection_node);
int handle_send_dt_proxy_ht_destroy(unsigned short origin, unsigned short id, unsigned short header_errno);
int handle_send_dt_proxy_ht_create(char *proxy_string, int proxy_type);
int handle_send_dt_proxy_ht_report(struct proxy_node *cur_proxy_node);
int handle_send_dt_connection_ht_destroy(unsigned short origin, unsigned short id, unsigned short header_errno);
int handle_send_dt_connection_ht_create(struct connection_node *cur_connection_node);
int handle_send_dt_nop();
struct connection_node *handle_tun_tap_init(int ifr_flag);

/* io.c */
int negotiate_protocol();
void seppuku(int signal);

/* io_nossl.c */
int remote_read_plaintext(void *buf, size_t count);
int remote_write_plaintext(void *buf, size_t count);

/* io_ssl.c */
#ifdef OPENSSL
int remote_read_encrypted(void *buf, size_t count);
int remote_write_encrypted(void *buf, size_t count);

int dummy_verify_callback(int preverify_ok, X509_STORE_CTX* ctx);
#endif /* OPENSSL */

/* io_nossl.c & io_ssl.c */
int init_io_control();
int init_io_target();

/* message.c */
int message_pull();
int message_push();
struct message_helper *message_helper_create(char *data, unsigned short data_len, unsigned short message_data_size);
void message_helper_destroy(struct message_helper *mh);

/* proxy.c */
struct proxy_node *proxy_node_new(char *proxy_string, int proxy_type);
int proxy_listen(struct proxy_node *cur_proxy_node);
int proxy_connect(char *rhost_rport);
struct proxy_node *proxy_node_create();
void proxy_node_delete(struct proxy_node *);
struct proxy_node *proxy_node_find(unsigned short origin, unsigned short id);
struct connection_node *connection_node_create();
void connection_node_delete(struct connection_node *);
struct connection_node *connection_node_find(unsigned short origin, unsigned short id);
void connection_node_queue(struct connection_node *cur_connection_node);
int parse_socks_request(struct connection_node *cur_connection_node);
char *addr_to_string(int atype, char *addr, char *port, int len);

/* report.c */
void report_error(char *fmt, ...);
int report_log(char *fmt, ...);
int report_log_string(char *error_string);

/* revsh.c */
void clean_io();
#ifndef FREEBSD
int posix_openpt(int flags);
#endif 

/* string_to_vector.c */
char **string_to_vector(char *command_string);
void free_vector(char **vector);
char **cli_to_vector(char *command);
char *pack_vector(char **command_vec);
char **unpack_vector(char *packed_command);
char **vector_push(char **vector, char *string);

/* target.c */
int do_target();
int remote_printf(char *fmt, ...);

