
#include "common.h"


int message_pull(struct io_helper *io){

	unsigned short header_len;
	struct message_helper *message;

	int retval;


	message = &io->message;

	if((retval = io->remote_read(io, &header_len, sizeof(header_len))) == -1){
		return(-1);
	}
	header_len = ntohs(header_len);

	if((retval = io->remote_read(io, &message->data_type, sizeof(message->data_type))) == -1){
		return(-1);
	}	
	header_len -= sizeof(message->data_type);

	if((retval = io->remote_read(io, &message->data_len, sizeof(message->data_len))) == -1){
		return(-1);
	}	
	message->data_len = ntohs(message->data_len);
	header_len -= sizeof(message->data_len);

	/*
		 switch(message->data_type){
		 default:
		 }
	 */

	if(header_len > message->data_size){
		fprintf(stderr, "%s: %d: message: remote header too long!\n", \
				program_invocation_short_name, io->controller);
		return(-1);
	}

	/* Ignore any remaining header data as unknown, and probably from a more modern version of the */
	/* protocol than we were compiled with. */
	if(header_len){
		if((retval = io->remote_read(io, message->data, header_len)) == -1){
			return(-1);
		}	
	}

	if(message->data_len > message->data_size){
		fprintf(stderr, "%s: %d: message: remote data too long!\n", \
				program_invocation_short_name, io->controller);
		return(-1);
	}

	if((retval = io->remote_read(io, message->data, message->data_len)) == -1){
		return(-1);
	}	

	return(0);
}



int message_push(struct io_helper *io){

	unsigned short header_len;
	struct message_helper *message;

	unsigned short tmp_short;


	message = &io->message;

	header_len = sizeof(message->data_type) + sizeof(message->data_len);

	/* Fill in with header extensions here.
		 switch(message->data_type){

		 default:
		 print_error(io, "Unknown data type: %d\n", message->data_type);
		 return(-1);
		 }
	 */


	if(header_len > message->data_size){
		fprintf(stderr, "%s: %d: message: local header too long!\n", \
				program_invocation_short_name, io->controller);
		return(-1);
	}

	tmp_short = htons(header_len);
	if(io->remote_write(io, &tmp_short, sizeof(tmp_short)) == -1){
		return(-1);
	}

	if(io->remote_write(io, &message->data_type, sizeof(message->data_type)) == -1){
		return(-1);
	}	


	if(message->data_len > message->data_size){
		fprintf(stderr, "%s: %d: message: local data too long!\n", \
				program_invocation_short_name, io->controller);
		return(-1);
	}

	tmp_short = htons(message->data_len);
	if(io->remote_write(io, &tmp_short, sizeof(tmp_short)) == -1){
		return(-1);
	}	

	if(io->remote_write(io, message->data, message->data_len) == -1){
		return(-1);
	}	

	return(0);
}
