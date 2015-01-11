
#define DEBUG


#ifndef FREEBSD
# define _POSIX_C_SOURCE 199309L
# define _BSD_SOURCE
# define _XOPEN_SOURCE 500
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


#include "helper_objects.h"

#include "config.h"

#define TARGET_CERT_FILE "target_cert.pem"
#define CONTROLLER_CERT_FILE "controller_cert.pem"
#define CONTROLLER_KEY_FILE "controller_key.pem"

/*
	 This should only need to be 16 chars long.
	 4 control chars + 1 space + (2 * string length of winsize members).
	 winsize members are unsigned shorts on my dev platform.
	 There are four members total in a winsize object, but the second two are ignored.
 */
#define WINSIZE_BUFF_LEN  16

/* State definitions. */
#define NO_EVENT        0
#define APC_HIGH_FOUND  1
#define DATA_FOUND      2
#define ST_HIGH_FOUND   3

/* Encryption definitions. */
#define PLAINTEXT 0
#define ADH 1
#define EDH 2

#define MINIMUM_MESSAGE_SIZE	1024
#define LOCAL_BUFF_SIZE	128


/* We will set this up ourselves for portability. */
char *program_invocation_short_name;

int pagesize;

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


/**********************************************************************************************************************
 *
 * Protocol Specification:
 *
 *	Header:
 *		- header_len		: unsigned short (network order)
 *				This is the size of the *remaining* header data.
 *		- data_type			:	unsigned char
 *		- data_len			:	unsigned short (network order)
 *		- Other data_type specific headers, as needed.
 *
 *	Body:
 *		- data					:	void *
 *
 **********************************************************************************************************************/

/* Data Types */

/* DT_INIT: Initialization sequence data. */
#define DT_INIT				1

/* DT_TTY: TTY interaction data. */
#define DT_TTY				2

/* DT_WINRESIZE: Window re-size event data. */
#define DT_WINRESIZE	3

/* DT_PROXY: SOCKS proxy networking data. */
/*#define DT_PROXY			4*/

