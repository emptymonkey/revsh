
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

//	fprintf(stderr, "\rDEBUG: inside message_pull()\n");
  /* We use this as a shorthand to make message syntax more readable. */
	message = &io->message;

	memset(message->data, '\0', io->message_data_size);

//	fprintf(stderr, "\rDEBUG: 0\n");
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

//	fprintf(stderr, "\rDEBUG: 1\n");
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

//	fprintf(stderr, "\rDEBUG: 2\n");
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

	if(header_len > io->message_data_size){
		if(verbose){
			fprintf(stderr, "%s: %d: message: remote header too long!\n", \
					program_invocation_short_name, io->controller);
		}
		return(-1);
	}

//	fprintf(stderr, "\rDEBUG: message->data_type: %d\n", message->data_type);
//	fprintf(stderr, "\rDEBUG: message->header_type: %d\n", message->header_type);
	if(message->data_type == DT_PROXY || message->data_type == DT_CONNECTION){

		if((retval = io->remote_read(io, &message->header_type, sizeof(message->header_type))) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: remote_read(%lx, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, (unsigned long) &message->header_type, (int) sizeof(message->header_type), \
						strerror(errno));
			}
			return(-1);
		}	
		message->header_type = ntohs(message->header_type);
		header_len -= sizeof(message->header_type);

		if((retval = io->remote_read(io, &message->header_origin, sizeof(message->header_origin))) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: remote_read(%lx, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, (unsigned long) &message->header_origin, (int) sizeof(message->header_origin), \
						strerror(errno));
			}
			return(-1);
		}	
		message->header_origin = ntohs(message->header_origin);
		header_len -= sizeof(message->header_origin);

		if((retval = io->remote_read(io, &message->header_id, sizeof(message->header_id))) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: remote_read(%lx, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, (unsigned long) &message->header_id, (int) sizeof(message->header_id), \
						strerror(errno));
			}
			return(-1);
		}	
		message->header_id = ntohs(message->header_id);
		header_len -= sizeof(message->header_id);

		if((retval = io->remote_read(io, &message->header_errno, sizeof(message->header_errno))) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: remote_read(%lx, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, (unsigned long) &message->header_errno, (int) sizeof(message->header_errno), \
						strerror(errno));
			}
			return(-1);
		}	
		message->header_errno = ntohs(message->header_errno);
		header_len -= sizeof(message->header_errno);
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
	if(message->data_len > io->message_data_size){
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

	if(message->data_type == DT_PROXY || message->data_type == DT_CONNECTION){
		header_len += sizeof(message->header_type) + sizeof(message->header_origin) + sizeof(message->header_id) + sizeof(message->header_errno);
	}

	if(header_len > io->message_data_size){
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

	if(message->data_type == DT_NOP){
		message->data_len = 0;
	}

	/* Send the data. */
	if(message->data_len > io->message_data_size){
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

	if(message->data_type == DT_PROXY || message->data_type == DT_CONNECTION){
		tmp_short = htons(message->header_type);
		if(io->remote_write(io, &tmp_short, sizeof(tmp_short)) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: remote_write(%lx, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, (unsigned long) &tmp_short, (int) sizeof(tmp_short), \
						strerror(errno));
			}
			return(-1);
		}

		tmp_short = htons(message->header_origin);
		if(io->remote_write(io, &tmp_short, sizeof(tmp_short)) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: remote_write(%lx, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, (unsigned long) &tmp_short, (int) sizeof(tmp_short), \
						strerror(errno));
			}
			return(-1);
		}

		tmp_short = htons(message->header_id);
		if(io->remote_write(io, &tmp_short, sizeof(tmp_short)) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: remote_write(%lx, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, (unsigned long) &tmp_short, (int) sizeof(tmp_short), \
						strerror(errno));
			}
			return(-1);
		}

		tmp_short = htons(message->header_errno);
		if(io->remote_write(io, &tmp_short, sizeof(tmp_short)) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: remote_write(%lx, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, (unsigned long) &tmp_short, (int) sizeof(tmp_short), \
						strerror(errno));
			}
			return(-1);
		}
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

struct message_helper *message_helper_create(char *data, unsigned short data_len, unsigned short message_data_size){
	// just the malloc and setup of a new message_helper node.

	struct message_helper *new_mh;

	new_mh = (struct message_helper *) calloc(1, sizeof(struct message_helper));	
	if(!new_mh && verbose){
      fprintf(stderr, "%s: calloc(1, %d): %s\n", \
          program_invocation_short_name, \
					(int) sizeof(struct message_helper), \
          strerror(errno));
    return(NULL);
	}

	new_mh->data = (char *) calloc(message_data_size, sizeof(char));	
	if(!new_mh->data && verbose){
      fprintf(stderr, "%s: calloc(1, %d): %s\n", \
          program_invocation_short_name, \
					(int) sizeof(struct message_helper), \
          strerror(errno));
		free(new_mh);	
    return(NULL);
	}

	memcpy(new_mh->data, data, data_len);
	new_mh->data_len = data_len;

	return(new_mh);
}

void message_helper_destroy(struct message_helper *mh){
	free(mh->data);
	free(mh);
}
