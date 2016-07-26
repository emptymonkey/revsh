
/* The ssl and non-ssl portions of this file have been split out into their own separate files. */

#ifdef OPENSSL

#include "io_ssl.c"

#else

#include "io_nossl.c"

#endif /* OPENSSL */


/***********************************************************************************************************************
 *
 * negotiate_protocol()
 *
 * Input: An io object.
 *
 * Output: 0 on success, -1 on error.
 *
 * Purpose: To gather agreement between the communicating parties on how big the max message size should be.
 *
 **********************************************************************************************************************/
int negotiate_protocol(struct io_helper *io){

	struct message_helper *message;
	unsigned short remote_data_size;

	int fcntl_flags;


	message = &io->message;

	io->message_data_size = 0;
	io->message_data_size--;

	/* Make sure that the data_size variable will be able to hold the pagesize on this platform. */
	if(pagesize > io->message_data_size){
		if(verbose){
			fprintf(stderr, "%s: %d: pagesize bigger than max message size!\r\n", \
					program_invocation_short_name, io->controller);
		}
		return(-1);
	}

	io->message_data_size = pagesize;

	/* Set the socket to non-blocking. */
	if((fcntl_flags = fcntl(io->remote_fd, F_GETFL, 0)) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: fcntl(%d, FGETFL, 0): %s\r\n", \
					program_invocation_short_name, io->controller, \
					io->remote_fd, \
					strerror(errno));
		}
		return(-1);
	}

	fcntl_flags |= O_NONBLOCK;
	if(fcntl(io->remote_fd, F_SETFL, fcntl_flags) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: fcntl(%d, FGETFL, %d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					io->remote_fd, fcntl_flags, \
					strerror(errno));
		}
		return(-1);
	}

	/* Send our desired message size. */
	if(io->remote_write(io, &io->message_data_size, sizeof(io->message_data_size)) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: io->remote_write(%lx, %lx, %d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &io->message_data_size, (int) sizeof(io->message_data_size), \
					strerror(errno));
		}
		return(-1);
	}

	/* Recieve their desired message size. */
	if(io->remote_read(io, &remote_data_size, sizeof(io->message_data_size)) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: io->remote_read(%lx, %lx, %d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &remote_data_size, (int) sizeof(io->message_data_size), \
					strerror(errno));
		}
		return(-1);
	}

	/* Make sure it isn't smaller than our totally reasonable minimum. */
	if(remote_data_size < MINIMUM_MESSAGE_SIZE){
		if(verbose){
			fprintf(stderr, "%s: %d: Can't agree on a message size!\r\n", \
					program_invocation_short_name, io->controller);
		}
		return(-1);
	}

	/* Set the message size to the smaller of the two, and malloc the space. */
	io->message_data_size = io->message_data_size < remote_data_size ? io->message_data_size : remote_data_size;

	if((message->data = (char *) malloc(io->message_data_size)) == NULL){
		if(verbose){
			fprintf(stderr, "%s: %d: malloc(%d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					io->message_data_size, \
					strerror(errno));
		}
		return(-1);
	}

	return(0);
}

/***********************************************************************************************************************
 * 
 * catch_alarm()
 *
 * Input: The signal being handled. (SIGALRM)
 * Output: None. 
 * 
 * Purpose: To catch SIGALRM and exit quietly.
 * 
 **********************************************************************************************************************/
void catch_alarm(int signal){
	exit(-signal);
}
