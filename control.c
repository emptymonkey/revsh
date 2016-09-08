
#include "common.h"

/***********************************************************************************************************************
 *
 * do_control()
 *
 * Input: Our io and config helper objects.
 *
 * Output: 0 for success, -1 on error.
 *
 * Purpose: This is the defining function for a control node.
 *
 **********************************************************************************************************************/
int do_control(struct config_helper *config){

	int i;
	int retval;
	int err_flag;

	struct termios saved_termios_attrs, new_termios_attrs;
	char **exec_envp;
	struct winsize tty_winsize;

	int rc_fd;
	wordexp_t rc_file_exp;

	char *tmp_ptr;
	int io_bytes;


	/* Set up the network connection. */
	if(init_io_controller(config) == -1){
		report_error("do_control(): init_io_controller(%lx): %s", (unsigned long) config, strerror(errno));
		return(-1);
	}

	/* Prepare the message buffer. */
	if(negotiate_protocol() == -1){
		report_error("do_control(): negotiate_protocol(): %s", strerror(errno));
		return(-1);
	}

	/* Start conversing with the remote partner to agree on the shape of this session. */
	report_log("Controller: Initializing.");

	/*  - Agree on interactive / non-interactive mode. */
	message->data_type = DT_INIT;
	message->data_len = sizeof(config->interactive);
	memcpy(message->data, &config->interactive, sizeof(config->interactive));

	if(message_push() == -1){
		report_error("do_control(): message->push(): %s", strerror(errno));
		return(-1);
	}

	if(message_pull() == -1){
		report_error("do_control(): message_pull(): %s", strerror(errno));
		return(-1);
	}

	if(message->data_type != DT_INIT){
		report_error("do_control(): DT_INIT interactive: Protocol violation!");
		return(-1);
	}

	/* Both sides must agree on interaction. If either one opts out, fall back to non-interactive data transfer. */	
	io->interactive = 1;
	if(!(config->interactive && message->data[0])){
		io->interactive = 0;
	}
	
	if(!io->interactive){
		retval = broker(config);

		return(retval);
	}

	/* Initialize the structures we will leverage. */
	if(wordexp(config->rc_file, &rc_file_exp, 0)){
		report_error("do_control(): wordexp(%s, %lx, 0): %s", config->rc_file, (unsigned long)  &rc_file_exp, strerror(errno));
		return(-1);
	}

	if(rc_file_exp.we_wordc != 1){
		report_error("do_control(): Invalid path: %s", config->rc_file);
		return(-1);
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

	if(message_push() == -1){
		report_error("do_control(): message_push(): %s", strerror(errno));
		return(-1);
	}

	/*  - Send initial environment data. */
	if((exec_envp = string_to_vector(DEFAULT_ENV)) == NULL){
		report_error("do_control(): string_to_vector(%s): %s", DEFAULT_ENV, strerror(errno));
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

	if(io_bytes > io->message_data_size){
		report_error("do_control(): Environment string too long!");
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
			report_error("do_control(): No such environment variable \"%s\". Ignoring.", exec_envp[i]);
		}else{
			io_bytes = strlen(tmp_ptr);
			memcpy((message->data + message->data_len), tmp_ptr, io_bytes);
			message->data_len += io_bytes;
		}
	}

	free_vector(exec_envp);

	if(message_push() == -1){
		report_error("do_control(): message_push(): %s", strerror(errno));
		return(-1);
	}

	/*  - Send initial termios data. */
	if(ioctl(STDIN_FILENO, TIOCGWINSZ, &tty_winsize) == -1){
		report_error("do_control(): ioctl(STDIN_FILENO, TIOCGWINSZ, %lx): %s", (unsigned long) &tty_winsize, strerror(errno));
		return(-1);
	}

	message->data_type = DT_INIT;
	*((unsigned short *) message->data) = htons(tty_winsize.ws_row);
	message->data_len = sizeof(tty_winsize.ws_row);
	*((unsigned short *) (message->data + message->data_len)) = htons(tty_winsize.ws_col);
	message->data_len += sizeof(tty_winsize.ws_col);

	if(message_push() == -1){
		report_error("do_control(): message_push(): %s", strerror(errno));
		return(-1);
	}

	// The initialization protocol is now finished. Rest of initialization is local.
	io->init_complete = 1;

	/*  - Set local terminal to raw.  */
	if(tcgetattr(STDIN_FILENO, &saved_termios_attrs) == -1){
		report_error("do_control(): tcgetattr(STDIN_FILENO, %lx): %s", (unsigned long) &saved_termios_attrs, strerror(errno));
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
		report_error("do_control(): tcsetattr(STDIN_FILENO, TCSANOW, %lx): %s", (unsigned long) &new_termios_attrs, strerror(errno));
		return(-1);
	}	

	report_log("Controller: Initializtion complete.");

	/*  - Send the commands in the rc file. */
	if((rc_fd = open(rc_file_exp.we_wordv[0], O_RDONLY)) != -1){

		message->data_type = DT_TTY;

		while((io_bytes = read(rc_fd, message->data, io->message_data_size))){
			if(io_bytes == -1){
				report_error("do_control(): read(%d, %lx, %d): %s", rc_fd, (unsigned long) message->data, io->message_data_size, strerror(errno));
				return(-1);
			}

			message->data_len = io_bytes;

			if(message_push() == -1){
				report_error("do_control(): message_push(): %s", strerror(errno));
				return(-1);
			}
		}

		close(rc_fd);
	}

	err_flag = 0;

	/*  - Enter broker() for tty brokering. */
	retval = broker(config);

	if(retval == -1 && !io->eof){

		if(errno == ECONNRESET){
			err_flag = errno;
		}else{
			report_error("do_control(): broker(%lx): %s", (unsigned long) config, strerror(errno));
		}
	}

	/*  - Reset local term. */
	if(tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios_attrs) == -1){
		report_error("do_control(): tcsetattr(STDIN_FILENO, TCSANOW, %lx): %s", (unsigned long) &saved_termios_attrs, strerror(errno));
	}

	/*  - Exit. */
	if(!err_flag){
		if(verbose){
			printf("Good-bye!\n");
		}
		report_log("Controller: Good-bye!");
	}else{
		while(message_pull() > 0){
			if(message->data_type == DT_TTY){
				write(STDERR_FILENO, message->data, message->data_len);
			}
		}
	}

	return(0);
}
