
#include "common.h"


int do_control(struct io_helper *io, struct config_helper *config){

	int i;
	int retval;
	int err_flag;

	struct termios saved_termios_attrs, new_termios_attrs;
	char **exec_envp;
	struct winsize *tty_winsize;

  int rc_fd;
  wordexp_t rc_file_exp;
	
	struct message_helper *message;
	char *tmp_ptr;
	int io_bytes;


	/* We will be using the internal message struct inside of io quite a bit, so this will be a nice shorthand. */
	message = &io->message;

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

	if(init_io_controller(io, config) == -1){
		fprintf(stderr, "%s: %d: init_io_listen(%lx, %lx): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) config, \
				strerror(errno));
		return(-1);
	}

	if(negotiate_protocol(io) == -1){
		fprintf(stderr, "%s: %d: negotiate_protocol(%lx): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, \
				strerror(errno));
		return(-1);
	}

	if(config->verbose){
		printf("Initializing...");
	}


	/*  - Agree on interactive / non-interactive mode. */
	message->data_type = DT_INIT;
	message->data_len = sizeof(config->interactive);
	memcpy(message->data, &config->interactive, sizeof(config->interactive));

	if(message_push(io) == -1){
		fprintf(stderr, "%s: %d: message->push(%lx): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, \
				strerror(errno));
		return(-1);
	}

	if(message_pull(io) == -1){
		fprintf(stderr, "%s: %d: message_pull(%lx): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, \
				strerror(errno));
		return(-1);
	}

	if(message->data_type != DT_INIT){
		fprintf(stderr, "%s: %d: DT_INIT interactive: Protocol violation!\r\n", \
				program_invocation_short_name, io->controller); 
		return(-1);
	}

	/* Both sides must agree on interaction. If either one opts out, fall back to non-interactive data transfer. */	
	if(!message->data[0]){
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
	/* We will indicated this by sending an empty string for the shell. */
	message->data_type = DT_INIT;
	message->data_len = 0;
	if(config->shell){
		message->data_len = strlen(config->shell);
		memcpy(message->data, config->shell, message->data_len);
	}

	if(message_push(io) == -1){
		print_error(io, "%s: %d: message_push(%lx): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, \
				strerror(errno));
		return(-1);
	}

	/*  - Send initial environment data. */
	if((exec_envp = string_to_vector(DEFAULT_ENV)) == NULL){
		print_error(io, "%s: %d: string_to_vector(%s): %s\n", \
				program_invocation_short_name, io->controller, \
				DEFAULT_ENV, \
				strerror(errno));
		return(-1);
	}

	message->data_type = DT_INIT;
	message->data_len = 0;
	
	/* First, calculate size. */
	io_bytes = 0;
	for(i = 0; exec_envp[i]; i++){

		/* This will be the length of the env variable name, plus one char for '=' and one char for ' ' or '\0'. */
		io_bytes += strlen(exec_envp[i]) + 2;

		/* Also, the length of any value assigned to that variable. */
		if((tmp_ptr = getenv(exec_envp[i])) != NULL){
			io_bytes += strlen(tmp_ptr);
		}
	}

	if(io_bytes > message->data_size){
		print_error(io, "%s: %d: Environment string too long!\n", \
				program_invocation_short_name, io->controller);
		return(-1);
	}

	for(i = 0; exec_envp[i]; i++){

		if(message->data_len){
			*(message->data + message->data_len++) = ' ';
		}

		io_bytes = strlen(exec_envp[i]);
		memcpy((message->data + message->data_len), exec_envp[i], io_bytes);
		message->data_len += io_bytes;

		*(message->data + message->data_len++) = '=';

		if((tmp_ptr = getenv(exec_envp[i])) == NULL){
			fprintf(stderr, "%s: No such environment variable \"%s\". Ignoring.\n", \
					program_invocation_short_name, exec_envp[i]);
		}else{
			io_bytes = strlen(tmp_ptr);
			memcpy((message->data + message->data_len), tmp_ptr, io_bytes);
			message->data_len += io_bytes;
		}
	}

	free_vector(exec_envp);

	if(message_push(io) == -1){
		print_error(io, "%s: %d: message_push(%lx): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, \
				strerror(errno));
		return(-1);
	}

	/*  - Send initial termios data. */
	if(ioctl(STDIN_FILENO, TIOCGWINSZ, tty_winsize) == -1){
		print_error(io, "%s: %d: ioctl(STDIN_FILENO, TIOCGWINSZ, %lx): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) tty_winsize, strerror(errno));
		return(-1);
	}

	message->data_type = DT_INIT;
	*((unsigned short *) message->data) = htons(tty_winsize->ws_row);
	message->data_len = sizeof(tty_winsize->ws_row);
	*((unsigned short *) (message->data + message->data_len)) = htons(tty_winsize->ws_col);
	message->data_len += sizeof(tty_winsize->ws_col);

	if(message_push(io) == -1){
		print_error(io, "%s: %d: message_push(%lx): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, \
				strerror(errno));
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

		message->data_type = DT_TTY;

		while((io_bytes = read(rc_fd, message->data, message->data_size))){
			if(io_bytes == -1){
				print_error(io, "%s: %d: read(%d, %lx, %d): %s\r\n", \
						program_invocation_short_name, io->controller, \
						rc_fd, (unsigned long) message->data, message->data_size, \
						strerror(errno));
				return(-1);
			}

			message->data_len = io_bytes;

			if(message_push(io) == -1){
				print_error(io, "%s: %d: message_push(%lx): %s\r\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, \
						strerror(errno));
				return(-1);
			}
		}

		close(rc_fd);
	}


	err_flag = 0;

	/*  - Enter broker() for tty brokering. */
	retval = broker(io, config);

	if(retval == -1 && !io->eof){
		
		if(errno == ECONNRESET){
			err_flag = errno;
		}else{
			print_error(io, "%s: %d: broker(%lx, %lx): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) config, \
					strerror(errno));
		}
	}

	/*  - Reset local term. */
	tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios_attrs);

	/*  - Exit. */
	if(!err_flag){
		printf("Good-bye!\n");
	}else{
		while(message_pull(io) > 0){
			if(message->data_type == DT_TTY){
				write(STDERR_FILENO, message->data, message->data_len);
			}
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

	return(0);
}
