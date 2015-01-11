
#include "common.h"
#include "keys/dh_params.c"


/* The plaintext case for I/O is really easy. Call the openssl BIO_* functions and return. */

/***********************************************************************************************************************
 *
 * remote_read_plaintext()
 *
 * Input: A pointer to our io_helper object, a pointer to the buffer we want to fill, and the count of characters
 *	we should try to read.
 * Output: The count of characters succesfully read, or an error code. (man BIO_read for more information.)
 *
 * Purpose: Fill our buffer, but this is the simple plaintext wrapper case. Nothing fancy here.
 *
 **********************************************************************************************************************/
int remote_read_plaintext(struct io_helper *io, void *buff, size_t count){

  int retval;
  int io_bytes;
  char *tmp_ptr;


  io_bytes = 0;
  tmp_ptr = buff;

	while(count){

		retval = BIO_read(io->connect, tmp_ptr, count);
		if(!retval){

			io->eof = 1;
			return(-1);

		}else if(retval == -1){

			return(-1);

		}else{

			count -= retval;
			io_bytes += retval;
			tmp_ptr += retval;

		}
	}

	return(io_bytes);
}


/***********************************************************************************************************************
 *
 * remote_write_plaintext()
 *
 * Input: A pointer to our io_helper object, a pointer to the buffer we want to empty, and the count of
 *	characters we should try to write.
 * Output: The count of characters succesfully written, or an error code. (man BIO_write for more information.)
 *
 * Purpose: Empty our buffer, but this is the simple plaintext wrapper case. Nothing fancy here.
 *
 **********************************************************************************************************************/
int remote_write_plaintext(struct io_helper *io, void *buff, size_t count){

  int retval;
  int io_bytes;
  char *tmp_ptr;


  io_bytes = 0;
  tmp_ptr = buff;

	while(count){

		retval = BIO_write(io->connect, tmp_ptr, count);
		retval = write(io->remote_fd, tmp_ptr, count);

		if(retval == -1){

			return(-1);

		}else{

			count -= retval;
			io_bytes += retval;
			tmp_ptr += retval;

		}
	}

	return(io_bytes);
}


/***********************************************************************************************************************
 *
 * remote_read_encrypted()
 *
 * Input: A pointer to our io_helper object, a pointer to the buffer we want to fill, and the count of characters
 *	we should try to read.
 * Output: The count of characters succesfully read, or an error code. (man BIO_read for more information.)
 *
 * Purpose: Fill our buffer. This is the SSL encrypted case.
 *
 * Note: This function won't return until it has satisfied the request to read count characters, or encountered an error
 *	trying. It assumes the socket is ready for action (either blocking, or has just passed a select() call.) If it 
 *	cannot fulfill the requested character count initially, it will call select() itself in a loop until it can.
 *
 **********************************************************************************************************************/
int remote_read_encrypted(struct io_helper *io, void *buff, size_t count){

	int retval;
	fd_set fd_select;
	int ssl_error = SSL_ERROR_NONE;	


	if(!count){
		return(count);
	}

	do{
		/* We've already been through the loop once, but now we need to wait for the socket to be ready. */
		if(ssl_error != SSL_ERROR_NONE){
			FD_ZERO(&fd_select);
			FD_SET(io->remote_fd, &fd_select);

			if(ssl_error == SSL_ERROR_WANT_READ){
				if(select(io->remote_fd + 1, &fd_select, NULL, NULL, NULL) == -1){
					return(-1);
				}

			}else /* if(ssl_error == SSL_ERROR_WANT_WRITE) */ {
				if(select(io->remote_fd + 1, NULL, &fd_select, NULL, NULL) == -1){
					return(-1);
				}
			}
		}

		retval = SSL_read(io->ssl, buff, count);

		switch(SSL_get_error(io->ssl, retval)){

			case SSL_ERROR_ZERO_RETURN:
				io->eof = 1;
				return(-1);

			case SSL_ERROR_NONE:
				return(retval);

			case SSL_ERROR_WANT_READ:
				ssl_error = SSL_ERROR_WANT_READ;
				break;

			case SSL_ERROR_WANT_WRITE:
				ssl_error = SSL_ERROR_WANT_WRITE;
				break;

			default:
				return(-1);
		}
	} while(ssl_error);

	return(-1);
}


/***********************************************************************************************************************
 *
 * remote_write_encrypted()
 *
 * Input: A pointer to our io_helper object, a pointer to the buffer we want to empty, and the count of
 *	characters we should try to write.
 * Output: The count of characters succesfully written, or an error code. (man BIO_write for more information.)
 *
 * Purpose: Empty our buffer, but this is the simple plaintext wrapper case. Nothing fancy here.
 *
 * Note: This function won't return until it has satisfied the request to write count characters, or encountered an
 *	error trying. It assumes the socket is ready for action (either blocking, or has just passed a select() call.) If
 *	it cannot fulfill the requested character count initially, it will call select() itself in a loop until it can.
 *
 **********************************************************************************************************************/
int remote_write_encrypted(struct io_helper *io, void *buff, size_t count){

	int retval;
	fd_set fd_select;
	int ssl_error = SSL_ERROR_NONE;	


	if(!count){
		return(count);
	}

	do{

		/* We've already been through the loop once, but now we need to wait for the socket to be ready. */
		if(ssl_error != SSL_ERROR_NONE){
			FD_ZERO(&fd_select);
			FD_SET(io->remote_fd, &fd_select);

			if(ssl_error == SSL_ERROR_WANT_READ){
				if(select(io->remote_fd + 1, &fd_select, NULL, NULL, NULL) == -1){
					print_error(io, "%s: %d: select(%d, %lx, NULL, NULL, NULL): %s\n", \
							program_invocation_short_name, io->controller, \
							io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
					return(-1);
				}

			}else /* if(ssl_error == SSL_ERROR_WANT_WRITE) */ {
				if(select(io->remote_fd + 1, NULL, &fd_select, NULL, NULL) == -1){
					print_error(io, "%s: %d: select(%d, NULL, %lx, NULL, NULL): %s\n", \
							program_invocation_short_name, io->controller, \
							io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
					return(-1);
				}
			}
		}

		retval = SSL_write(io->ssl, buff, count);


		switch(SSL_get_error(io->ssl, retval)){

			case SSL_ERROR_ZERO_RETURN:
				io->eof = 1;
				return(-1);

			case SSL_ERROR_NONE:
				return(retval);

			case SSL_ERROR_WANT_READ:
				ssl_error = SSL_ERROR_WANT_READ;
				break;

			case SSL_ERROR_WANT_WRITE:
				ssl_error = SSL_ERROR_WANT_WRITE;
				break;

			default:
				return(-1);
		}
	} while(ssl_error);

	
	return(-1);
}


/***********************************************************************************************************************
 *
 * init_io_controller()
 *
 * Input:  A pointer to our io_helper object and a pointer to our configuration_helper object.
 * Output: An int showing success (by returning the remote_fd) or failure (by returning -1).
 *
 * Purpose: To initialize the controller's network io interface.
 *
 **********************************************************************************************************************/
int init_io_controller(struct io_helper *io, struct config_helper *config){

	int i;
	int retval;

	wordexp_t keys_dir_exp;

	struct sigaction *act = NULL;

	unsigned int tmp_uint;
	unsigned int retry;
	struct timespec req;

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


	if(wordexp(config->keys_dir, &keys_dir_exp, 0)){
		fprintf(stderr, "%s: %d: wordexp(%s, %lx, 0): %s\r\n", \
				program_invocation_short_name, io->controller, \
				config->keys_dir, (unsigned long)  &keys_dir_exp, \
				strerror(errno));
		return(-1);
	}

	if(keys_dir_exp.we_wordc != 1){
		fprintf(stderr, "%s: %d: Invalid path: %s\r\n", \
				program_invocation_short_name, io->controller, \
				config->keys_dir);
		return(-1);
	}

	if((act = (struct sigaction *) calloc(1, sizeof(struct sigaction))) == NULL){
		fprintf(stderr, "%s: %d: calloc(1, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(int) sizeof(struct sigaction), strerror(errno));
		return(-1);
	}

	memset(allowed_fingerprint, 0, EVP_MAX_MD_SIZE);
	allowed_fingerprint_len = 0;

	memset(remote_fingerprint, 0, EVP_MAX_MD_SIZE);
	remote_fingerprint_len = 0;


	/*  - Open a socket / setup SSL. */
	if(config->encryption == EDH){
		if((controller_cert_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
			fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
					program_invocation_short_name, io->controller, PATH_MAX, (int) sizeof(char), \
					strerror(errno));
			return(-1);
		}

		memcpy(controller_cert_path_head, keys_dir_exp.we_wordv[0], strlen(keys_dir_exp.we_wordv[0]));
		controller_cert_path_tail = index(controller_cert_path_head, '\0');
		*(controller_cert_path_tail++) = '/';
		sprintf(controller_cert_path_tail, CONTROLLER_CERT_FILE);


		if((controller_cert_path_head - controller_cert_path_tail) > PATH_MAX){
			fprintf(stderr, "%s: %d: controller cert file: path too long!\n",
					program_invocation_short_name, io->controller);
			return(-1);
		}

		if((controller_key_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
			fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
					program_invocation_short_name, io->controller, PATH_MAX, (int) sizeof(char), \
					strerror(errno));
			return(-1);
		}

		memcpy(controller_key_path_head, keys_dir_exp.we_wordv[0], strlen(keys_dir_exp.we_wordv[0]));
		controller_key_path_tail = index(controller_key_path_head, '\0');
		*(controller_key_path_tail++) = '/';
		sprintf(controller_key_path_tail, CONTROLLER_KEY_FILE);


		if((controller_key_path_head - controller_key_path_tail) > PATH_MAX){
			fprintf(stderr, "%s: %d: controller key file: path too long!\n",
					program_invocation_short_name, io->controller);
			return(-1);
		}
	}

	if(config->encryption){

		if((io->ctx = SSL_CTX_new(TLSv1_server_method())) == NULL){
			fprintf(stderr, "%s: %d: SSL_CTX_new(TLSv1_server_method()): %s\n", \
					program_invocation_short_name, io->controller, strerror(errno));
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		if((io->dh = get_dh()) == NULL){
			fprintf(stderr, "%s: %d: get_dh(): %s\n", \
					program_invocation_short_name, io->controller, strerror(errno));
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		if(!SSL_CTX_set_tmp_dh(io->ctx, io->dh)){
			fprintf(stderr, "%s: %d: SSL_CTX_set_tmp_dh(%lx, %lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ctx, (unsigned long) io->dh, strerror(errno));
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		if(SSL_CTX_set_cipher_list(io->ctx, config->cipher_list) != 1){
			fprintf(stderr, "%s: %d: SSL_CTX_set_cipher_list(%lx, %s): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ctx, config->cipher_list, strerror(errno));
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		if(config->encryption == EDH){
			SSL_CTX_set_verify(io->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, dummy_verify_callback);

			if(SSL_CTX_use_certificate_file(io->ctx, controller_cert_path_head, SSL_FILETYPE_PEM) != 1){
				fprintf(stderr, "%s: %d: SSL_CTX_use_certificate_file(%lx, %s, SSL_FILETYPE_PEM): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ctx, controller_cert_path_head, strerror(errno));
				ERR_print_errors_fp(stderr);
				return(-1);
			}

			free(controller_cert_path_head);

			if(SSL_CTX_use_PrivateKey_file(io->ctx, controller_key_path_head, SSL_FILETYPE_PEM) != 1){
				fprintf(stderr, "%s: %d: SSL_CTX_use_PrivateKey_file(%lx, %s, SSL_FILETYPE_PEM): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ctx, controller_key_path_head, strerror(errno));
				ERR_print_errors_fp(stderr);
				return(-1);
			}

			free(controller_key_path_head);

			if(SSL_CTX_check_private_key(io->ctx) != 1){
				fprintf(stderr, "%s: %d: SSL_CTX_check_private_key(%lx): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ctx, strerror(errno));
				ERR_print_errors_fp(stderr);
				return(-1);
			}
		}
	}

	act->sa_handler = catch_alarm;

	if(sigaction(SIGALRM, act, NULL) == -1){
		fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
				program_invocation_short_name, io->controller, \
				SIGALRM, (unsigned long) act, NULL, strerror(errno));
		return(-1);
	}

	alarm(config->timeout);


	if(config->bindshell){

		/*  - Open a network connection back to the target. */
		if((io->connect = BIO_new_connect(config->ip_addr)) == NULL){
			fprintf(stderr, "%s: %d: BIO_new_connect(%s): %s\n", \
					program_invocation_short_name, io->controller, config->ip_addr, strerror(errno));
			ERR_print_errors_fp(stderr);
			return(-1);
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
			return(-1);
		}

	}else{

		if(config->verbose){
			printf("Listening on %s...", config->ip_addr);
			fflush(stdout);
		}

		if((accept = BIO_new_accept(config->ip_addr)) == NULL){
			fprintf(stderr, "%s: %d: BIO_new_accept(%s): %s\n", \
					program_invocation_short_name, io->controller, config->ip_addr, strerror(errno));
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		if(BIO_set_bind_mode(accept, BIO_BIND_REUSEADDR) <= 0){
			fprintf(stderr, "%s: %d: BIO_set_bind_mode(%lx, BIO_BIND_REUSEADDR): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		if(BIO_do_accept(accept) <= 0){
			fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		if(BIO_do_accept(accept) <= 0){
			fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		if((io->connect = BIO_pop(accept)) == NULL){
			fprintf(stderr, "%s: %d: BIO_pop(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		BIO_free(accept);
	}

	act->sa_handler = SIG_DFL;

	if(sigaction(SIGALRM, act, NULL) == -1){
		fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
				program_invocation_short_name, io->controller, \
				SIGALRM, (unsigned long) act, NULL, strerror(errno));
		return(-1);
	}

	alarm(0);

	if(config->verbose){
		printf("\tConnected!\n");
	}

	if(BIO_get_fd(io->connect, &(io->remote_fd)) < 0){
		fprintf(stderr, "%s: %d: BIO_get_fd(%lx, %lx): %s\n", \
				program_invocation_short_name, io->controller, (unsigned long) io->connect, (unsigned long) &(io->remote_fd), strerror(errno));
		ERR_print_errors_fp(stderr);
		return(-1);
	}


	if(config->encryption){
		if(!(io->ssl = SSL_new(io->ctx))){
			fprintf(stderr, "%s: %d: SSL_new(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ctx, strerror(errno));
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		SSL_set_bio(io->ssl, io->connect, io->connect);

		if(SSL_accept(io->ssl) < 1){
			fprintf(stderr, "%s: %d: SSL_accept(%lx): %s\n", \
					program_invocation_short_name, io->controller, (unsigned long) io->ssl, strerror(errno));
			ERR_print_errors_fp(stderr);
			return(-1);
		}

		if(config->encryption == EDH){
			if((allowed_cert_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
				fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
						program_invocation_short_name, io->controller, PATH_MAX, (int) sizeof(char), \
						strerror(errno));
				return(-1);
			}

			memcpy(allowed_cert_path_head, keys_dir_exp.we_wordv[0], strlen(keys_dir_exp.we_wordv[0]));
			allowed_cert_path_tail = index(allowed_cert_path_head, '\0');
			*(allowed_cert_path_tail++) = '/';
			sprintf(allowed_cert_path_tail, TARGET_CERT_FILE);


			if((allowed_cert_path_head - allowed_cert_path_tail) > PATH_MAX){
				fprintf(stderr, "%s: %d: target fingerprint file: path too long!\n",
						program_invocation_short_name, io->controller);
				return(-1);
			}

			if((target_fingerprint_fp = fopen(allowed_cert_path_head, "r")) == NULL){
				fprintf(stderr, "%s: %d: fopen(%s, 'r'): %s\n",
						program_invocation_short_name, io->controller, allowed_cert_path_head, strerror(errno));
				return(-1);
			}

			free(allowed_cert_path_head);

			if((allowed_cert = PEM_read_X509(target_fingerprint_fp, NULL, NULL, NULL)) == NULL){
				fprintf(stderr, "%s: %d: PEM_read_X509(%lx, NULL, NULL, NULL): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) target_fingerprint_fp, strerror(errno));
				ERR_print_errors_fp(stderr);
				return(-1);
			}

			if(fclose(target_fingerprint_fp)){
				fprintf(stderr, "%s: %d: fclose(%lx): %s\n",
						program_invocation_short_name, io->controller, (unsigned long) target_fingerprint_fp, strerror(errno));
				return(-1);
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
				return(-1);
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
				return(-1);
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
				return(-1);
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
				return(-1);
			}

			for(i = 0; i < (int) allowed_fingerprint_len; i++){
				if(allowed_fingerprint[i] != remote_fingerprint[i]){
					fprintf(stderr, "%s: %d: Fingerprint mistmatch. Possible mitm. Aborting!\n", \
							program_invocation_short_name, io->controller);
					return(-1);
				}
			}
		}
	}

	return(io->remote_fd);
}


/***********************************************************************************************************************
 *
 * init_io_target()
 *
 * Input:  A pointer to our io_helper object and a pointer to our configuration_helper object.
 * Output: An int showing success (by returning the remote_fd) or failure (by returning -1).
 *
 * Purpose: To initialize a target's network io interface.
 *
 **********************************************************************************************************************/
int init_io_target(struct io_helper *io, struct config_helper *config){

	int i;
	int retval;

	struct sigaction *act = NULL;

	unsigned int tmp_uint;
	unsigned int retry;
	struct timespec req;


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

	BIO *accept = NULL;


	if((act = (struct sigaction *) calloc(1, sizeof(struct sigaction))) == NULL){
		if(config->verbose){
			fprintf(stderr, "%s: %d: calloc(1, %d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(int) sizeof(struct sigaction), strerror(errno));
		}
		return(-1);
	}


	memset(remote_fingerprint, 0, EVP_MAX_MD_SIZE);
	remote_fingerprint_len = 0;


	/*  - Setup SSL. */
	if(config->encryption){

		if((io->ctx = SSL_CTX_new(TLSv1_client_method())) == NULL){
			if(config->verbose){
				fprintf(stderr, "%s: %d: SSL_CTX_new(TLSv1_client_method()): %s\n", \
						program_invocation_short_name, io->controller, strerror(errno));
				ERR_print_errors_fp(stderr);
			}
			return(-1);
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
			if(config->verbose){
				fprintf(stderr, "%s: %d: SSL_CTX_set_cipher_list(%lx, %s): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ctx, config->cipher_list, strerror(errno));
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		SSL_CTX_set_verify(io->ctx, SSL_VERIFY_PEER, dummy_verify_callback);

		if(SSL_CTX_use_certificate_ASN1(io->ctx, target_cert_len, target_cert) != 1){
			if(config->verbose){
				fprintf(stderr, "%s: %d: SSL_CTX_use_certificate_ASN1(%lx, %d, %lx): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ctx, target_cert_len, (unsigned long) target_cert, strerror(errno));
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(SSL_CTX_use_RSAPrivateKey_ASN1(io->ctx, target_key, target_key_len) != 1){
			if(config->verbose){
				fprintf(stderr, "%s: %d: SSL_CTX_use_RSAPrivateKey_ASN1(%lx, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ctx, (unsigned long) target_key, target_key_len, strerror(errno));
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(SSL_CTX_check_private_key(io->ctx) != 1){
			if(config->verbose){
				fprintf(stderr, "%s: %d: SSL_CTX_check_private_key(%lx): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ctx, strerror(errno));
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}
	}

	act->sa_handler = catch_alarm;

	if(sigaction(SIGALRM, act, NULL) == -1){
		if(config->verbose){
			fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
					program_invocation_short_name, io->controller, \
					SIGALRM, (unsigned long) act, NULL, strerror(errno));
		}
		return(-1);
	}

	alarm(config->timeout);

	if(config->bindshell){

		/*  - Listen for a connection. */

		if(config->keepalive){
			if(signal(SIGCHLD, SIG_IGN) == SIG_ERR){
				if(config->verbose){
					fprintf(stderr, "%s: %d: signal(SIGCHLD, SIG_IGN): %s\n", \
							program_invocation_short_name, io->controller, strerror(errno));
					return(-1);
				}
			}
		}

		do{

			if(config->verbose){
				printf("Listening on %s...", config->ip_addr);
				fflush(stdout);
			}

			if(accept){
				BIO_free(accept);
				alarm(config->timeout);
			}

			if((accept = BIO_new_accept(config->ip_addr)) == NULL){
				if(config->verbose){
					fprintf(stderr, "%s: %d: BIO_new_accept(%s): %s\n", \
							program_invocation_short_name, io->controller, config->ip_addr, strerror(errno));
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			if(BIO_set_bind_mode(accept, BIO_BIND_REUSEADDR) <= 0){
				if(config->verbose){
					fprintf(stderr, "%s: %d: BIO_set_bind_mode(%lx, BIO_BIND_REUSEADDR): %s\n", \
							program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			if(BIO_do_accept(accept) <= 0){
				if(config->verbose){
					fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
							program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			if(BIO_do_accept(accept) <= 0){
				if(config->verbose){
					fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
							program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			if((io->connect = BIO_pop(accept)) == NULL){
				if(config->verbose){
					fprintf(stderr, "%s: %d: BIO_pop(%lx): %s\n", \
							program_invocation_short_name, io->controller, (unsigned long) accept, strerror(errno));
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			BIO_free(accept);

			retval = 0;
			if(config->keepalive){
				if((retval = fork()) == -1){
					if(config->verbose){
						fprintf(stderr, "%s: %d: fork(): %s\n", \
								program_invocation_short_name, io->controller, strerror(errno));
						ERR_print_errors_fp(stderr);
					}
					return(-1);
				}
			}

		} while(config->keepalive && retval);

		if(config->keepalive){
			if(signal(SIGCHLD, SIG_DFL) == SIG_ERR){
				if(config->verbose){
					fprintf(stderr, "%s: %d: signal(SIGCHLD, SIG_IGN): %s\n", \
							program_invocation_short_name, io->controller, strerror(errno));
				}
				return(-1);
			}
		}

	}else{

		/*  - Open a network connection back to a controller. */
		if((io->connect = BIO_new_connect(config->ip_addr)) == NULL){
			if(config->verbose){
				fprintf(stderr, "%s: %d: BIO_new_connect(%s): %s\n", \
						program_invocation_short_name, io->controller, config->ip_addr, strerror(errno));
				ERR_print_errors_fp(stderr);
			}
			return(-1);
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
			if(config->verbose){
				fprintf(stderr, "%s: %d: BIO_do_connect(%lx): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->connect, strerror(errno));
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}
	}

	act->sa_handler = SIG_DFL;

	if(sigaction(SIGALRM, act, NULL) == -1){
		if(config->verbose){
			fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
					program_invocation_short_name, io->controller, \
					SIGALRM, (unsigned long) act, NULL, strerror(errno));
		}
		return(-1);
	}

	alarm(0);

	if(config->verbose){
		printf("\tConnected!\r\n");
	}

	if(BIO_get_fd(io->connect, &(io->remote_fd)) < 0){
		if(config->verbose){
			fprintf(stderr, "%s: %d: BIO_get_fd(%lx, %lx): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io->connect, (unsigned long) &(io->remote_fd), strerror(errno));
			ERR_print_errors_fp(stderr);
		}
		return(-1);
	}

	if(config->encryption > PLAINTEXT){

		if(!(io->ssl = SSL_new(io->ctx))){
			if(config->verbose){
				fprintf(stderr, "%s: %d: SSL_new(%lx): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ctx, strerror(errno));
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		SSL_set_bio(io->ssl, io->connect, io->connect);

		if(SSL_connect(io->ssl) < 1){
			if(config->verbose){
				fprintf(stderr, "%s: %d: SSL_connect(%lx): %s\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ssl, strerror(errno));
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if((current_cipher = SSL_get_current_cipher(io->ssl)) == NULL){
			if(config->verbose){
				fprintf(stderr, "%s: %d: SSL_get_current_cipher(%lx): No cipher set!\n", \
						program_invocation_short_name, io->controller, (unsigned long) io->ssl);
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(!strcmp(current_cipher->name, EDH_CIPHER)){

			if((remote_cert = SSL_get_peer_certificate(io->ssl)) == NULL){
				if(config->verbose){
					fprintf(stderr, "%s: %d: SSL_get_peer_certificate(%lx): %s\n", \
							program_invocation_short_name, io->controller, (unsigned long) io->ssl, strerror(errno));
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			if(!X509_digest(remote_cert, io->fingerprint_type, remote_fingerprint, &remote_fingerprint_len)){
				if(config->verbose){
					fprintf(stderr, "%s: %d: X509_digest(%lx, %lx, %lx, %lx): %s\n", \
							program_invocation_short_name, io->controller, \
							(unsigned long) remote_cert, \
							(unsigned long) io->fingerprint_type, \
							(unsigned long) remote_fingerprint, \
							(unsigned long) &remote_fingerprint_len, \
							strerror(errno));
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			if((remote_fingerprint_str = (char *) calloc(strlen(controller_cert_fingerprint) + 1, sizeof(char))) == NULL){
				if(config->verbose){
					fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
							program_invocation_short_name, io->controller, (int) strlen(controller_cert_fingerprint) + 1, (int) sizeof(char), \
							strerror(errno));
				}
				return(-1);
			}

			for(i = 0; i < (int) remote_fingerprint_len; i++){
				sprintf(remote_fingerprint_str + (i * 2), "%02x", remote_fingerprint[i]);
			}

			if(strncmp(controller_cert_fingerprint, remote_fingerprint_str, strlen(controller_cert_fingerprint))){
				if(config->verbose){
					fprintf(stderr, "Remote fingerprint expected:\n\t%s\n", controller_cert_fingerprint);
					fprintf(stderr, "Remote fingerprint received:\n\t%s\n", remote_fingerprint_str);
					fprintf(stderr, "%s: %d: Fingerprint mistmatch. Possible mitm. Aborting!\n", \
							program_invocation_short_name, io->controller);
				}
				return(-1);
			}

			free(remote_fingerprint_str);
		}
	}

	return(io->remote_fd);
}


/***********************************************************************************************************************
 *
 * dummy_verify_callback()
 *
 * Inputs: The stuff that openssl requires of a verify_callback function. We won't ever use these things, I promise.
 * Outputs: 1. Always 1.
 *
 * Purpose: This dummy function does nothing of interest, but satisfies openssl that a verify_callback function does 
 *  exist. The net effect of a dummy verify_callback function like this is that you can use self signed certs without
 *  any errors.
 *
 **********************************************************************************************************************/
int dummy_verify_callback(int preverify_ok, X509_STORE_CTX* ctx) {

	/*  The point of a dummy function is that it's components won't be used.  */
	/*  We will nop reference them however to silence the noise from the compiler. */
	preverify_ok += 0;
	ctx += 0;

	return(1);
}

