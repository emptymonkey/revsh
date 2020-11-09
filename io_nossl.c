
#include "common.h"


/***********************************************************************************************************************
 *
 * remote_read_plaintext()
 *
 * Input: A pointer to the buffer we want to fill, and the count of characters we need to read. 
 *   We will also use the the global io struct.
 * Output: The count of characters succesfully read, or -1 on error.
 *
 * Purpose: Fill our buffer.
 *
 **********************************************************************************************************************/
int remote_read_plaintext(void *buff, size_t count){

	int retval;
	int io_bytes;
	char *tmp_ptr;

	fd_set fd_select;

	int seen = 0;


	io_bytes = 0;
	tmp_ptr = buff;

	while(count){

		/* Skip the select() statement the first time through, as the common case won't need it. */
		if(seen){
			FD_ZERO(&fd_select);
			FD_SET(io->remote_fd, &fd_select);

			if(select(io->remote_fd + 1, &fd_select, NULL, NULL, NULL) == -1){
				report_error("remote_read_plaintext(): select(%d, %lx, NULL, NULL, NULL): %s", \
						io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
				return(-1);
			}
		}else{
			seen = 1;
		}

		retval = read(io->remote_fd, tmp_ptr, count);

		if(!retval){
			io->eof = 1;
			return(-1);

		}else if(retval == -1){
			if(!(errno == EINTR  || errno == EAGAIN)){
				report_error("remote_read_plaintext(): read(%d, %lx, %d): %s", \
						io->remote_fd, (unsigned long) &tmp_ptr, (int) count, strerror(errno));
				return(-1);
			}

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
 * Input: A pointer to the buffer we want to empty, and the count of characters we should write.
 *   We will also use the the global io struct.
 * Output: The count of characters succesfully written, or -1 on error.
 *
 * Purpose: Empty our buffer.
 *
 **********************************************************************************************************************/
int remote_write_plaintext(void *buff, size_t count){

	int retval;
	int io_bytes;
	char *tmp_ptr;

	fd_set fd_select;

	int seen = 0;


	io_bytes = 0;
	tmp_ptr = buff;

	while(count){

		/* Skip the select() statement the first time through, as the common case won't need it. */
		if(seen){
			FD_ZERO(&fd_select);
			FD_SET(io->remote_fd, &fd_select);

			if(select(io->remote_fd + 1, NULL, &fd_select, NULL, NULL) == -1){
				report_error("remote_write_plaintext(): select(%d, NULL, %lx, NULL, NULL): %s", \
						io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
				return(-1);
			}
		}else{
			seen = 1;
		}

		retval = write(io->remote_fd, tmp_ptr, count);

		if(retval == -1){
			if(!(errno == EINTR || errno == EAGAIN)){
				report_error("remote_write_plaintext(): read(%d, %lx, %d): %s", \
						io->remote_fd, (unsigned long) &tmp_ptr, (int) count, strerror(errno));
				return(-1);
			}

		}else{
			count -= retval;
			io_bytes += retval;
			tmp_ptr += retval;
		}
	}

	return(io_bytes);
}


/* The decision below to use gethostbyname() instead of getaddrinfo() is a design decision. */
/* If the application is being built without SSL, then the target host is probably a much older host with */
/* equally old network libraries. The "no SSL" case would better be considered here as the "deprecated best */
/* effort, only around for extreame backward compatability" case. */


/***********************************************************************************************************************
 *
 * init_io_control()
 *
 * Input: None. We will use the global io and config structs.
 * Output: An int showing success (by returning the remote_fd) or failure (by returning -1).
 *
 * Purpose: To initialize the control nodes network io layer.
 *
 **********************************************************************************************************************/
int init_io_control(){

	int tmp_sock;

	int yes = 1;

	struct sockaddr_in name;
	struct hostent *host;

	char *ip_address;
	char *ip_port;
	int ip_address_len;

	struct sigaction act;

	socklen_t len;
	struct sockaddr_storage addr;
	char ipstr[INET6_ADDRSTRLEN];
	int port;
	struct sockaddr_in *s;
	struct sockaddr_in6 *s6;


	/* In the no ssl build, there is no difference between a control in bindshell mode, and a target. */
	/* As such, we'll just pass through to the other rather than repeat code. */
	if(!io->target && config->bindshell){
		return(init_io_target(config));
	}

	/* Initialize the structures we will be using. */

	/* Set up our socket. */
	ip_address_len = strlen(config->ip_addr);
	if((ip_address = calloc(ip_address_len + 1, sizeof(char))) == NULL){
		report_error("init_io_control(): calloc(%d, %d): %s", ip_address_len, (int) sizeof(char), strerror(errno));
		return(-1);
	}

	memcpy(ip_address, config->ip_addr, ip_address_len);

	if((ip_port = strchr(ip_address, ':')) == NULL){
		report_error("init_io_control(): strchr(%s, ':'): Port not found!", ip_address);
		return(-1);
	}
	*ip_port = '\0';
	ip_port++;

	if((host = gethostbyname(ip_address)) == NULL){
		report_error("init_io_control(): gethostbyname(%s): %s", ip_address, strerror(errno));
		return(-1);
	}

	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	name.sin_port = htons(strtol(ip_port, NULL, 10));

	free(ip_address);

	if((tmp_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		report_error("init_io_control(): socket(AF_INET, SOCK_STREAM, 0): %s", strerror(errno));
		return(-1);
	}

	if(setsockopt(tmp_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1){
		report_error("init_io_control(): setsockopt(%d, SOL_SOCKET, SO_REUSEADDR, %lx, %d): %s", \
				tmp_sock, (unsigned long) &yes, (int) sizeof(yes), strerror(errno));
		return(-1);
	}

	/* Seppuku if left alone too long. */
	memset(&act, 0, sizeof(act));
	act.sa_handler = seppuku;

	if(sigaction(SIGALRM, &act, NULL) == -1){
		report_error("init_io_control(): sigaction(%d, %lx, %p): %s", SIGALRM, (unsigned long) &act, NULL, strerror(errno));
		return(-1);
	}

	if(verbose){
		printf("Listening on %s...", config->ip_addr);
		fflush(stdout);
	}
	report_log("Controller: Listening on %s.", config->ip_addr);

	if(bind(tmp_sock, (struct sockaddr *) &name, sizeof(name)) == -1){
		report_error("init_io_control(): bind(%d, %lx, %d): %s", \
				tmp_sock, (unsigned long) &name, (int) sizeof(name), strerror(errno));
		return(-1);
	}

	if(listen(tmp_sock, 1) == -1){
		report_error("init_io_control(): listen(%d, 1): %s", tmp_sock, strerror(errno));
		return(-1);
	}  

	if((io->remote_fd = accept(tmp_sock, NULL, NULL)) == -1){
		report_error("init_io_control(): accept(%d, NULL, NULL): %s", tmp_sock, strerror(errno));
		return(-1);
	}

	if(close(tmp_sock) == -1){
		report_error("init_io_control(): close(%d): %s", tmp_sock, strerror(errno));
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

	return(io->remote_fd);
}



/***********************************************************************************************************************
 *
 * init_io_target()
 *
 * Input: None. We will use the global io and config structs.
 * Output: An int showing success (by returning the remote_fd) or failure (by returning -1).
 *
 * Purpose: To initialize a target's network io layer.
 *
 **********************************************************************************************************************/
int init_io_target(){

	int retval;

	struct sockaddr_in name;
	struct hostent *host;

	char *ip_address;
	char *ip_port;
	int ip_address_len;

	int tmp_sock;

	struct sigaction act;


	/* In the no ssl build, there is no difference between a target in bindshell mode, and the control node for networking. */
	/* As such, we'll just pass through to the other rather than repeat code. */
	if(io->target && config->bindshell){
		return(init_io_control(config));
	}

	/* Initialize the structures we will need. */

	/* Open our socket. */
	ip_address_len = strlen(config->ip_addr);
	if((ip_address = calloc(ip_address_len + 1, sizeof(char))) == NULL){
		report_error("init_io_target(): calloc(%d, %d): %s", ip_address_len, (int) sizeof(char), strerror(errno));
		return(-1);
	}

	memcpy(ip_address, config->ip_addr, ip_address_len);


	if((ip_port = strchr(ip_address, ':')) == NULL){
		report_error("init_io_target(): strchr(%s, ':'): Port not found!", ip_address);
		return(-1);
	}
	*ip_port = '\0';
	ip_port++;

	if((host = gethostbyname(ip_address)) == NULL){
		report_error("init_io_target(): gethostbyname(%s): %s", ip_address, strerror(errno));
		return(-1);
	}

	memset(&name, 0, sizeof(name));
	name.sin_family = AF_INET;
	name.sin_port = htons(strtol(ip_port, NULL, 10));

    if(inet_pton(AF_INET, ip_address, &name.sin_addr)<=0)
    {
		report_error("init_io_target(): inet_pton(AF_INET, \"%s\", %p): %s", ip_address, &name.sin_addr, strerror(errno));
		return(-1);
    }

	free(ip_address);

	if((tmp_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1){
		report_error("init_io_target(): socket(AF_INET, SOCK_STREAM, 0): %s", strerror(errno));
		return(-1);
	}

	/* Sepuku if left alone too long. */
	memset(&act, 0, sizeof(act));
	act.sa_handler = seppuku;

	if(sigaction(SIGALRM, &act, NULL) == -1){
		report_error("init_io_target(): sigaction(%d, %lx, %p): %s", SIGALRM, (unsigned long) &act, NULL, strerror(errno));
		return(-1);
	}

	alarm(config->timeout);

	if(verbose){
		printf("Connecting to %s...", config->ip_addr);
		fflush(stdout);
	}

	while((retval = connect(tmp_sock, (struct sockaddr *) &name, sizeof(name)))){

		if(retval == -1){
			report_error("init_io_target(): connect(%d, %lx, %d): %s", io->remote_fd, (unsigned long) &name, (int) sizeof(name), strerror(errno));
			if((errno == ECONNREFUSED || errno == ETIMEDOUT)){
				return(-2);
			}
			return(-1);
		}

		if(verbose){
			printf("Connecting to %s...", config->ip_addr);
			fflush(stdout);
		}
	}

	io->remote_fd = tmp_sock;

	act.sa_handler = SIG_DFL;

	if(sigaction(SIGALRM, &act, NULL) == -1){
		report_error("init_io_target(): sigaction(%d, %lx, %p): %s", SIGALRM, (unsigned long) &act, NULL, strerror(errno));
		return(-1);
	}

	alarm(0);

	if(verbose){
		printf("\tConnected!\n");
	}

	return(io->remote_fd);
}
