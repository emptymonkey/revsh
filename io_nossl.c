
#include "common.h"


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

	if((retval = read(io->remote_fd, buff, count)) == -1){
		fprintf(stderr, "%s: %d: read(%d, %lx, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				io->remote_fd, (unsigned long) buff, (int) count, \
				strerror(errno));
		return(-1);
	}

	return(retval);
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

	if((retval = write(io->remote_fd, buff, count)) == -1){
		fprintf(stderr, "%s: %d: write(%d, %lx, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				io->remote_fd, (unsigned long) buff, (int) count, \
				strerror(errno));
		return(-1);
	}

	return(retval);

}


/* The decision to use gethostbyname() in these next sections instead of getaddrinfo() is a design decision. */
/* If the application is being built without SSL, then the target host is most likely a much older host with */
/* equally old network libraries. The "no SSL" case would better be considered here as the "deprecated best */
/* effort, only around for extreame backward compatability" case. */


/***********************************************************************************************************************
 *
 * init_io_controller()
 *
 * Input:  A pointer to our io_helper object and a pointer to our configuration_helper object.
 * Output: An int showing success (by returning the remote_fd) or failure (by returning -1).
 *
 * Purpose: To initialize a controller's network io interface.
 *
 **********************************************************************************************************************/
int init_io_controller(struct io_helper *io, struct configuration_helper *config){

	int tmp_sock;

	int yes = 1;

	struct sockaddr_in name;
	struct hostent *host;

	char *ip_address;
	char *ip_port;
	int ip_address_len;

	struct sigaction *act = NULL;

	time_t epoch;


	/* In the no ssl build, there is no difference between a controller in bindshell mode, and a target. */
	/* As such, we'll just pass through to the other rather than repeat code. */
	if(io->controller && config->bindshell){
		return(init_io_target(io, config));
	}

	if((act = (struct sigaction *) calloc(1, sizeof(struct sigaction))) == NULL){
		fprintf(stderr, "%s: %d: calloc(1, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				(int) sizeof(struct sigaction), strerror(errno));
		return(-1);
	}

	ip_address_len = strlen(config->ip_addr);
	if((ip_address = calloc(ip_address_len + 1, sizeof(char))) == NULL){
		fprintf(stderr, "%s: %d: calloc(%d, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				ip_address_len, (int) sizeof(char), \
				strerror(errno));
		return(-1);
	}

	memcpy(ip_address, config->ip_addr, ip_address_len);

	if((ip_port = strchr(ip_address, ':')) == NULL){
		fprintf(stderr, "%s: %d: strchr(%s, ':'): Port not found!\n", \
				program_invocation_short_name, io->controller, \
				ip_address);
		return(-1);
	}
	*ip_port = '\0';
	ip_port++;


	if((host = gethostbyname(ip_address)) == NULL){
		fprintf(stderr, "%s: %d: gethostbyname(%s): %s\n", \
				program_invocation_short_name, io->controller, \
				ip_address, \
				strerror(errno));
		return(-1);
	}

	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	name.sin_addr.s_addr = *((unsigned long *) host->h_addr);
	name.sin_port = htons(strtol(ip_port, NULL, 10));

	if((tmp_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		fprintf(stderr, "%s: %d: socket(AF_INET, SOCK_STREAM, 0): %s\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		return(-1);
	}

	if(setsockopt(tmp_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1){
		fprintf(stderr, "%s: %d: setsockopt(%d, SOL_SOCKET, SO_REUSEADDR, %lx, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				tmp_sock, (unsigned long) &yes, (int) sizeof(yes), \
				strerror(errno));
		return(-1);
	}


	act->sa_handler = catch_alarm;

	if(sigaction(SIGALRM, act, NULL) == -1){
		fprintf(stderr, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
				program_invocation_short_name, io->controller, \
				SIGALRM, (unsigned long) act, NULL, strerror(errno));
		return(-1);
	}

	alarm(config->timeout);

	if(config->retry_start){
		epoch = time(NULL);
		srand(epoch);
	}


	if(config->verbose){
		printf("Listening on %s...", config->ip_addr);
		fflush(stdout);
	}

	if(bind(tmp_sock, (struct sockaddr *) &name, sizeof(name)) == -1){
		fprintf(stderr, "%s: %d: bind(%d, %lx, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				tmp_sock, (unsigned long) &name, (int) sizeof(name), \
				strerror(errno));
		return(-1);
	}

	if(listen(tmp_sock, 1) == -1){
		fprintf(stderr, "%s: %d: listen(%d, 1): %s\n", \
				program_invocation_short_name, io->controller, \
				tmp_sock, \
				strerror(errno));
		return(-1);
	}  

	if((io->remote_fd = accept(tmp_sock, NULL, NULL)) == -1){
		fprintf(stderr, "%s: %d: accept(%d, NULL, NULL): %s\n", \
				program_invocation_short_name, io->controller, \
				tmp_sock, \
				strerror(errno));
		return(-1);
	}

	if(close(tmp_sock) == -1){
		fprintf(stderr, "%s: %d: close(%d): %s\n", \
				program_invocation_short_name, io->controller, \
				tmp_sock, \
				strerror(errno));
		return(-1);
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

	free(ip_address);
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
int init_io_target(struct io_helper *io, struct configuration_helper *config){

	int retval;

	struct sockaddr_in name;
	struct hostent *host;

	char *ip_address;
	char *ip_port;
	int ip_address_len;

	int tmp_sock;

	struct sigaction *act = NULL;

	unsigned int tmp_uint;
	unsigned int retry;
	struct timespec req;

	time_t epoch;


  /* In the no ssl build, there is no difference between a target in bindshell mode, and a controller. */
  /* As such, we'll just pass through to the other rather than repeat code. */
  if(!io->controller && config->bindshell){
    return(init_io_controller(io, config));
  }

	if((act = (struct sigaction *) calloc(1, sizeof(struct sigaction))) == NULL){
		if(config->verbose){
			fprintf(stderr, "%s: %d: calloc(1, %d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(int) sizeof(struct sigaction), strerror(errno));
		}
		return(-1);
	}

	ip_address_len = strlen(config->ip_addr);
	if((ip_address = calloc(ip_address_len + 1, sizeof(char))) == NULL){
		fprintf(stderr, "%s: %d: calloc(%d, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				ip_address_len, (int) sizeof(char), \
				strerror(errno));
		return(-1);
	}

	memcpy(ip_address, config->ip_addr, ip_address_len);


	if((ip_port = strchr(ip_address, ':')) == NULL){
		fprintf(stderr, "%s: %d: strchr(%s, ':'): Port not found!\n", \
				program_invocation_short_name, io->controller, \
				ip_address);
		return(-1);
	}
	*ip_port = '\0';
	ip_port++;


	if((host = gethostbyname(ip_address)) == NULL){
		fprintf(stderr, "%s: %d: gethostbyname(%s): %s\n", \
				program_invocation_short_name, io->controller, \
				ip_address, \
				strerror(errno));
		return(-1);
	}


	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	name.sin_addr.s_addr = *((unsigned long *) host->h_addr);
	name.sin_port = htons(strtol(ip_port, NULL, 10));


	if((tmp_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		fprintf(stderr, "%s: %d: socket(AF_INET, SOCK_STREAM, 0): %s\n", \
				program_invocation_short_name, io->controller, \
				strerror(errno));
		return(-1);
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

	epoch = time(NULL);
	srand(epoch);


	if(config->verbose){
		printf("Connecting to %s...", config->ip_addr);
		fflush(stdout);
	}

	while((retval = connect(tmp_sock, (struct sockaddr *) &name, sizeof(name))) && config->retry_start){
		
		if(retval == -1 && !(errno == ECONNREFUSED || errno == ETIMEDOUT)){
			fprintf(stderr, "%s: %d: connect(%d, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					io->remote_fd, (unsigned long) &name, (int) sizeof(name), \
					strerror(errno));
			return(-1);
		}

		if(config->retry_stop){
			tmp_uint = rand();
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

	io->remote_fd = tmp_sock;


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
		printf("\tConnected!\n");
	}

	free(ip_address);
	return(io->remote_fd);
}
