
/* The ssl and non-ssl portions of the io have been split into separate files. */
#ifdef OPENSSL

#include "io_ssl.c"

#else

#include "io_nossl.c"

#endif /* OPENSSL */


/***********************************************************************************************************************
 *
 * remote_printf()
 *
 * Input: A pointer to our io_helper object, and the fmt specification as you would find in a normal printf
 *  statement.
 * Output: 0 on success, -1 on failure.
 *
 * Purpose: Provide a printf() style wrapper that will do the right thing.
 *
 **********************************************************************************************************************/
int remote_printf(struct io_helper *io, char *fmt, ...){

  int retval;
  va_list list_ptr;

	struct message_helper *message;


	message = &io->message;
	
	message->data_type = DT_TTY;

  va_start(list_ptr, fmt);

  if((retval = vsnprintf(message->data, message->data_size, fmt, list_ptr)) < 0){
		if(verbose){
			fprintf(stderr, "%s: %d: vsnprintf(%lx, %d, %lx, %lx): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) message->data, message->data_size, (unsigned long) fmt, (unsigned long) list_ptr, \
					strerror(errno));
		}
		return(-1);
	}

	va_end(list_ptr);
	if(retval == message->data_size){
		message->data[message->data_size - 1] = '\0';
	}

	message->data_len = retval;

	if(message_push(io) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, \
					strerror(errno));
		}
		return(-1);
	}

	return(0);
}



/***********************************************************************************************************************
 *
 * print_error()
 *
 * Input: A pointer to our io_helper object, and the fmt specification as you would find in a normal printf
 *  statement.
 * Output: The count of characters succesfully printed.
 *
 * Purpose: Provide a wrapper that allows us to just call print_error() and have the correct thing happen regardless of
 *  being a target or a controller. This simplifies the error reporting code greatly.
 *
 **********************************************************************************************************************/
int print_error(struct io_helper *io, char *fmt, ...){

	int retval;
	va_list list_ptr;

	struct message_helper *message;


	message = &io->message;

	va_start(list_ptr, fmt);

	if(io->controller){
		if(verbose){
			if((retval = vfprintf(stderr, fmt, list_ptr)) < 0){
				fprintf(stderr, "%s: %d: vfprintf(stderr, %lx, %lx): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) fmt, (unsigned long) list_ptr, \
						strerror(errno));
				return(-1);
			}
		}

	}else{
		message->data_type = DT_TTY;
		va_start(list_ptr, fmt);

		if((retval = vsnprintf(message->data, message->data_size, fmt, list_ptr)) < 0){
			if(verbose){
				fprintf(stderr, "%s: %d: vsnprintf(%lx, %d, %lx, %lx): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) message->data, message->data_size, (unsigned long) fmt, (unsigned long) list_ptr, \
						strerror(errno));
			}
			return(-1);
		}

		va_end(list_ptr);
		if(retval == message->data_size){
			message->data[message->data_size - 1] = '\0';
		}

		message->data_len = retval;

		if(message_push(io) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, \
						strerror(errno));
			}
			return(-1);
		}
	}

	return(0);
}



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

	message->data_size = 0;
	message->data_size--;

	/* Make sure that the data_size variable will be able to hold the pagesize on this platform. */
	if(pagesize > message->data_size){
		if(verbose){
			fprintf(stderr, "%s: %d: pagesize bigger than max message size!\r\n", \
					program_invocation_short_name, io->controller);
		}
		return(-1);
	}

	message->data_size = pagesize;

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
	if(io->remote_write(io, &message->data_size, sizeof(message->data_size)) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: io->remote_write(%lx, %lx, %d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &message->data_size, (int) sizeof(message->data_size), \
					strerror(errno));
		}
		return(-1);
	}

	/* Recieve their desired message size. */
	if(io->remote_read(io, &remote_data_size, sizeof(message->data_size)) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: io->remote_read(%lx, %lx, %d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &remote_data_size, (int) sizeof(message->data_size), \
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
	message->data_size = message->data_size < remote_data_size ? message->data_size : remote_data_size;

	if((message->data = (char *) malloc(message->data_size)) == NULL){
		if(verbose){
			fprintf(stderr, "%s: %d: malloc(%d): %s\r\n", \
					program_invocation_short_name, io->controller, \
					message->data_size, \
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
