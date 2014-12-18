
#include "common.h"


int do_target(struct io_helper *io, struct configuration_helper *config){

	int retval;

	char *pty_name;
	int pty_master, pty_slave;

	char **exec_argv;
	char **exec_envp;
	char **tmp_vector;

	int buff_len, tmp_len;
	char *buff_head = NULL, *buff_tail;

	int io_bytes;

	struct winsize *tty_winsize;

	char tmp_char;

	struct passwd *passwd_entry;

	struct sockaddr addr;
	socklen_t addrlen = (socklen_t) sizeof(addr);


	buff_len = getpagesize();
	if((buff_head = (char *) calloc(buff_len, sizeof(char))) == NULL){
		if(config->verbose){
			fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					buff_len, (int) sizeof(char), \
					strerror(errno));
		}
		return(-1);
	}

	if((tty_winsize = (struct winsize *) calloc(1, sizeof(struct winsize))) == NULL){
		if(config->verbose){
			fprintf(stderr, "%s: %d: calloc(1, %d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(int) sizeof(struct winsize), strerror(errno));
		}
		return(-1);
	}


	if(init_io_target(io, config) == -1){
		fprintf(stderr, "%s: %d: init_io_connect(%lx, %lx): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) config, \
				strerror(errno));
		return(-1);
	}


	/*  - Agree on interactive / non-interactive mode. */
	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;
	*(buff_tail++) = (char) APC;
	*(buff_tail++) = (char) config->interactive;
	*(buff_tail) = (char) ST;

	if((io_bytes = io->remote_write(io, buff_head, HANDSHAKE_LEN)) == -1){
		if(config->verbose){
			fprintf(stderr, "%s: %d: io->remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) buff_head, HANDSHAKE_LEN, strerror(errno));
		}
		return(-1);
	}

	if(io_bytes != HANDSHAKE_LEN){
		if(config->verbose){
			fprintf(stderr, "%s: %d: io->remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) buff_head, HANDSHAKE_LEN);
		}
		return(-1);
	}

	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;
	if((io_bytes = io->remote_read(io, buff_tail, HANDSHAKE_LEN)) == -1){
		if(config->verbose){
			fprintf(stderr, "%s: %d: io->remote_read(%lx, %lx, %d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) buff_tail, HANDSHAKE_LEN, strerror(errno));
		}
		return(-1);
	}

	if(io_bytes != HANDSHAKE_LEN){
		if(config->verbose){
			fprintf(stderr, "%s: %d: io->remote_read(%lx, %lx, %d): Unable to write entire string.\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) buff_tail, HANDSHAKE_LEN);
		}
		return(-1);
	}

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


	if(!config->verbose){
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
	if(io->remote_read(io, &tmp_char, 1) == -1){
		print_error(io, "%s: %d: io->remote_read(%lx, %lx, %d): %s\r\n", \
				program_invocation_short_name, io->controller, (unsigned long) io, (unsigned long) &tmp_char, 1, strerror(errno));
		return(-1);
	}

	if(tmp_char != (char) APC){
		print_error(io, "%s: %d: invalid initialization: shell\r\n", program_invocation_short_name, io->controller);
		return(-1);
	}

	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;

	if(io->remote_read(io, &tmp_char, 1) == -1){
		print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
		return(-1);
	}

	while(tmp_char != (char) ST){
		*(buff_tail++) = tmp_char;

		if((buff_tail - buff_head) >= buff_len){
			print_error(io, "%s: %d: Shell string too long.\r\n", \
					program_invocation_short_name, io->controller);
			return(-1);
		}

		if(io->remote_read(io, &tmp_char, 1) == -1){
			print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
			return(-1);
		}
	}

	tmp_len = strlen(buff_head);

	if(!tmp_len){
		if(config->shell){
			tmp_len = strlen(config->shell);
			memcpy(buff_head, config->shell, tmp_len);
		}else{
			tmp_len = strlen(DEFAULT_SHELL);
			memcpy(buff_head, DEFAULT_SHELL, tmp_len);
		}
	}

	if((config->shell = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
		print_error(io, "%s: %d: calloc(%d, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				tmp_len + 1, (int) sizeof(char), strerror(errno));
		return(-1);
	}
	memcpy(config->shell, buff_head, tmp_len);


	/*  - Receive and set the initial environment. */
	if(io->remote_read(io, &tmp_char, 1) == -1){
		print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
		return(-1);
	}

	if(tmp_char != (char) APC){
		print_error(io, "%s: %d: invalid initialization: environment\r\n", \
				program_invocation_short_name, io->controller);
		return(-1);
	}

	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;

	if(io->remote_read(io, &tmp_char, 1) == -1){
		print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
		return(-1);
	}

	while(tmp_char != (char) ST){
		*(buff_tail++) = tmp_char;

		if((buff_tail - buff_head) >= buff_len){
			print_error(io, "%s: %d: Environment string too long.\r\n", \
					program_invocation_short_name, io->controller);
			return(-1);
		}

		if(io->remote_read(io, &tmp_char, 1) == -1){
			print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
			return(-1);
		}
	}

	if((exec_envp = string_to_vector(buff_head)) == NULL){
		print_error(io, "%s: %d: string_to_vector(%s): %s\r\n", \
				program_invocation_short_name, io->controller, \
				buff_head, strerror(errno));
		return(-1);
	}

	/*  - Receive and set the initial termios. */
	if(io->remote_read(io, &tmp_char, 1) == -1){
		print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
		return(-1);
	}

	if(tmp_char != (char) APC){
		print_error(io, "%s: %d: invalid initialization: termios\r\n", \
				program_invocation_short_name, io->controller);
		return(-1);
	}

	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;

	if(io->remote_read(io, &tmp_char, 1) == -1){
		print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
		return(-1);
	}

	while(tmp_char != (char) ST){
		*(buff_tail++) = tmp_char;

		if((buff_tail - buff_head) >= buff_len){
			print_error(io, "%s: %d: termios string too long.\r\n", \
					program_invocation_short_name, io->controller);
			return(-1);
		}

		if(io->remote_read(io, &tmp_char, 1) == -1){
			print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
			return(-1);
		}
	}

	if((tmp_vector = string_to_vector(buff_head)) == NULL){
		print_error(io, "%s: %d: string_to_vector(%s): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		return(-1);
	}

	if(tmp_vector[0] == NULL){
		print_error(io, "%s: %d: invalid initialization: tty_winsize->ws_row\r\n", \
				program_invocation_short_name, io->controller);
		return(-1);
	}

	errno = 0;
	tty_winsize->ws_row = strtol(tmp_vector[0], NULL, 10);
	if(errno){
		print_error(io, "%s: %d: strtol(%s): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		return(-1);
	}

	if(tmp_vector[1] == NULL){
		print_error(io, "%s: %d: invalid initialization: tty_winsize->ws_col\r\n", \
				program_invocation_short_name, io->controller);
		return(-1);
	}

	errno = 0;
	tty_winsize->ws_col = strtol(tmp_vector[1], NULL, 10);
	if(errno){
		print_error(io, "%s: %d: strtol(%s): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		return(-1);
	}

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
	memset(buff_head, 0, buff_len);
	if(gethostname(buff_head, buff_len - 1) == -1){
		print_error(io, "%s: %d: gethostname(%lx, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) buff_head, buff_len - 1, strerror(errno));
		return(-1);
	}

	remote_printf(io, "################################\r\n");
	remote_printf(io, "# hostname: %s\r\n", buff_head);


	remote_printf(io, "# ip address: ");
	if(getsockname(io->remote_fd, &addr, &addrlen) != -1){
		memset(buff_head, 0, buff_len);
		if(inet_ntop(addr.sa_family, addr.sa_data + 2, buff_head, buff_len - 1)){
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
	remote_printf(io, "# real user: ");
	if(passwd_entry && passwd_entry->pw_name){
		remote_printf(io, "%s", passwd_entry->pw_name);
	}else{
		remote_printf(io, "I have no name!");
	}
	remote_printf(io, "\r\n");

	passwd_entry = getpwuid(geteuid());
	remote_printf(io, "# effective user: ");
	if(passwd_entry && passwd_entry->pw_name){
		remote_printf(io, "%s", passwd_entry->pw_name);
	}else{
		remote_printf(io, "I have no name!");
	}
	remote_printf(io, "\r\n");

	remote_printf(io, "################################\r\n");

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

	if(!config->verbose){
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

		if(retval == -1){
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
				config->shell, strerror(errno));
		return(-1);
	}

	free(config->shell);

	execve(exec_argv[0], exec_argv, exec_envp);
	print_error(io, "%s: %d: execve(%s, %lx, NULL): Shouldn't be here!\r\n", \
			program_invocation_short_name, io->controller, \
			exec_argv[0], (unsigned long) exec_argv);

	return(-1);
}

