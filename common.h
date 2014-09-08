
//#define DEBUG

#define _GNU_SOURCE
#define _XOPEN_SOURCE

#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <wordexp.h>

#include <arpa/inet.h>


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

#include "config.h"

#define TARGET_CERT_FILE "target_cert.pem"
#define CONTROLLER_CERT_FILE "controller_cert.pem"
#define CONTROLLER_KEY_FILE "controller_key.pem"

// No good reason for 1024. Pick your favorite power of two.
#define BUFFER_SIZE 1024

// These define the actual values to be used for controlling the in-band signalling.
#define UTF8_HIGH 0xc2
#define APC 0x9f
#define ST  0x9c

// This should only need to be 16 chars long.
// 4 control chars + 1 space + (2 * string length of winsize members).
// winsize members are unsigned shorts on my dev platform.
// There are four members total in a winsize object, but the second two are ignored.
#define WINSIZE_BUFF_LEN  16

// State definitions.
#define NO_EVENT        0
#define APC_HIGH_FOUND  1
#define DATA_FOUND      2
#define ST_HIGH_FOUND   3

// Encryption definitions.
#define PLAINTEXT 0
#define ADH 1
#define EDH 2


char **string_to_vector(char *command_string);

int remote_read_plaintext(struct remote_io_helper *io, void *buf, size_t count);
int remote_write_plaintext(struct remote_io_helper *io, void *buf, size_t count);
int remote_read_encrypted(struct remote_io_helper *io, void *buf, size_t count);
int remote_write_encrypted(struct remote_io_helper *io, void *buf, size_t count);

int remote_printf(struct remote_io_helper *io, char *fmt, ...);
int print_error(struct remote_io_helper *io, char *fmt, ...);


int broker(struct remote_io_helper *io);
void signal_handler(int signal);
