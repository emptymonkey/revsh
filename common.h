
//#define DEBUG

#define _GNU_SOURCE
#define _XOPEN_SOURCE

#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/limits.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "remote_io_helper.h"


#define DEFAULT_SHELL	"/bin/bash"
#define DEFAULT_ENV	"TERM LANG"


#define UTF8_HIGH 0xc2
#define APC 0x9f
#define ST  0x9c

#define WINSIZE_BUFF_LEN  16

#define REVSH_DIR ".revsh"
#define RC_FILE "rc"


// state definitions
#define NO_EVENT        0
#define APC_HIGH_FOUND  1
#define DATA_FOUND      2
#define ST_HIGH_FOUND   3


#define PLAINTEXT 0
#define ADH 1

#define ADH_CIPHER "ADH-AES256-SHA"

#define BUFFER_SIZE 1024


char **string_to_vector(char *command_string);

int remote_read_plaintext(struct remote_io_helper *io, void *buf, size_t count);
int remote_write_plaintext(struct remote_io_helper *io, void *buf, size_t count);
int remote_read_encrypted(struct remote_io_helper *io, void *buf, size_t count);
int remote_write_encrypted(struct remote_io_helper *io, void *buf, size_t count);

int remote_printf(struct remote_io_helper *io, char *fmt, ...);
int print_error(struct remote_io_helper *io, char *fmt, ...);


int broker(struct remote_io_helper *io);
void signal_handler(int signal);
