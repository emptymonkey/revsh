
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

#define ADDRESS "127.0.0.1:9999"

// No good reason for 1024. Pick your favorite power of two.
#define BUFFER_SIZE 1024

// I had this as "/bin/sh". Hacker's don't care for that backward compatability shit.
// They just want it to work with as little fuss as possible.
#define DEFAULT_SHELL	"/bin/bash"

// These two environement variables are important enough in allowing the tool to provide a sane
// feeling terminal that we bake them into the binary. They will be passed automatically. Feel
// free to bake more in here by adding them to the DEFAULT_ENV string (space delimited). Otherwise,
// just set the environment on the fly using your rc file.
#define DEFAULT_ENV	"TERM LANG"

// These define the actual values to be used for controlling the in-band signalling.
#define UTF8_HIGH 0xc2
#define APC 0x9f
#define ST  0x9c

// This should only need to be 16 chars long.
// 4 control chars + 1 space + (2 * string length of winsize members).
// winsize members are unsigned shorts on my dev platform.
// There are four members total in a winsize object, but the second two are ignored.
#define WINSIZE_BUFF_LEN  16

#define REVSH_DIR ".revsh"
#define RC_FILE "rc"
#define KEYS_DIR "keys"
#define CONNECTOR_CERT_FILE "target_cert.pem"
#define LISTENER_CERT_FILE "controller_cert.pem"
#define LISTENER_KEY_FILE "controller_key.pem"

// State definitions.
#define NO_EVENT        0
#define APC_HIGH_FOUND  1
#define DATA_FOUND      2
#define ST_HIGH_FOUND   3

// Encryption definitions.
#define PLAINTEXT 0
#define ADH 1
#define EDH 2

// Cipher definitions.
#define ADH_CIPHER "ADH-AES256-SHA"
#define EDH_CIPHER "DHE-RSA-AES256-SHA"
#define SERVER_CIPHER "!ADH:" EDH_CIPHER
#define CLIENT_CIPHER "DHE-RSA-AES256-SHA:ADH-AES256-SHA"


char **string_to_vector(char *command_string);

int remote_read_plaintext(struct remote_io_helper *io, void *buf, size_t count);
int remote_write_plaintext(struct remote_io_helper *io, void *buf, size_t count);
int remote_read_encrypted(struct remote_io_helper *io, void *buf, size_t count);
int remote_write_encrypted(struct remote_io_helper *io, void *buf, size_t count);

int remote_printf(struct remote_io_helper *io, char *fmt, ...);
int print_error(struct remote_io_helper *io, char *fmt, ...);


int broker(struct remote_io_helper *io);
void signal_handler(int signal);
