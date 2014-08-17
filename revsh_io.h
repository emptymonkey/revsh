

#define _GNU_SOURCE
#define _XOPEN_SOURCE

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

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

#define BUFFER_SIZE 1024

int remote_printf(struct remote_io_helper *io, char *fmt, ...);
int print_error(struct remote_io_helper *io, char *fmt, ...);
