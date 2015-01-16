
#include "common.h"

/***********************************************************************************************************************
 *
 * message_pull()
 *
 * Input: Our io helper object.
 * Output: 0 on success, -1 on error.
 *
 * Purpose: This is our message interface for receiving data.
 *
 **********************************************************************************************************************/
int message_pull(struct io_helper *io){

	unsigned short header_len;
	struct message_helper *message;

	int retval;


  /* We use this as a shorthand to make message syntax more readable. */
	message = &io->message;

	/* Grab the header. */
	if((retval = io->remote_read(io, &header_len, sizeof(header_len))) == -1){

		/* During a normal disconnect condition, this is where the message_pull should fail, so check for EOF. */
		if(verbose && !io->eof){
			fprintf(stderr, "%s: %d: remote_read(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &header_len, (int) sizeof(header_len), \
					strerror(errno));
		}
		return(-1);
	}
	header_len = ntohs(header_len);

	if((retval = io->remote_read(io, &message->data_type, sizeof(message->data_type))) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: remote_read(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &message->data_type, (int) sizeof(message->data_type), \
					strerror(errno));
		}
		return(-1);
	}	
	header_len -= sizeof(message->data_type);

	if((retval = io->remote_read(io, &message->data_len, sizeof(message->data_len))) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: remote_read(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &message->data_len, (int) sizeof(message->data_len), \
					strerror(errno));
		}
		return(-1);
	}	
	message->data_len = ntohs(message->data_len);
	header_len -= sizeof(message->data_len);

	if(header_len > message->data_size){
		if(verbose){
			fprintf(stderr, "%s: %d: message: remote header too long!\n", \
					program_invocation_short_name, io->controller);
		}
		return(-1);
	}

	/* Ignore any remaining header data as unknown, and probably from a more modern version of the */
	/* protocol than we were compiled with. */
	if(header_len){
		if((retval = io->remote_read(io, message->data, header_len)) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: remote_read(%lx, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, (unsigned long) message->data, header_len, \
						strerror(errno));
			}
			return(-1);
		}	
	}

	/* Grab the data. */
	if(message->data_len > message->data_size){
		if(verbose){
			fprintf(stderr, "%s: %d: message: remote data too long!\n", \
					program_invocation_short_name, io->controller);
		}
		return(-1);
	}

	if((retval = io->remote_read(io, message->data, message->data_len)) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: remote_read(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) message->data, message->data_len, \
					strerror(errno));
		}
		return(-1);
	}	

	return(0);
}



/***********************************************************************************************************************
 *
 * message_push()
 *
 * Input: Our io helper object.
 * Output: 0 on success, -1 on error.
 *
 * Purpose: This is our message interface for sending data.
 *
 **********************************************************************************************************************/
int message_push(struct io_helper *io){

	unsigned short header_len;
	struct message_helper *message;

	unsigned short tmp_short;


	/* We use this as a shorthand to make message syntax more readable. */
	message = &io->message;

	/* Send the header. */
	header_len = sizeof(message->data_type) + sizeof(message->data_len);

	if(header_len > message->data_size){
		if(verbose){
			fprintf(stderr, "%s: %d: message: local header too long!\n", \
					program_invocation_short_name, io->controller);
		}
		return(-1);
	}

	tmp_short = htons(header_len);
	if(io->remote_write(io, &tmp_short, sizeof(tmp_short)) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &tmp_short, (int) sizeof(tmp_short), \
					strerror(errno));
		}
		return(-1);
	}

	if(io->remote_write(io, &message->data_type, sizeof(message->data_type)) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &message->data_type, (int) sizeof(message->data_type), \
					strerror(errno));
		}
		return(-1);
	}	

	/* Send the data. */
	if(message->data_len > message->data_size){
		if(verbose){
			fprintf(stderr, "%s: %d: message: local data too long!\n", \
					program_invocation_short_name, io->controller);
		}
		return(-1);
	}

	tmp_short = htons(message->data_len);
	if(io->remote_write(io, &tmp_short, sizeof(tmp_short)) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) &tmp_short, (int) sizeof(tmp_short), \
					strerror(errno));
		}
		return(-1);
	}	

	if(io->remote_write(io, message->data, message->data_len) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: remote_write(%lx, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, (unsigned long) message->data, message->data_len, \
					strerror(errno));
		}
		return(-1);
	}	

	return(0);
}
