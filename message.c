
#include "common.h"


/***********************************************************************************************************************
 *
 * message_push()
 *
 * Input: Nothing, but we will heavily reference the global io_helper struct.
 * Output: 0 on success, -1 on error.
 *
 * Purpose: This is our message interface for sending data.
 *
 **********************************************************************************************************************/
int message_push(){

	unsigned short header_len;
	unsigned short tmp_short;


	/* Send the header. */
	header_len = sizeof(message->data_type) + sizeof(message->data_len);

	if(message->data_type == DT_PROXY || message->data_type == DT_CONNECTION){
		header_len += sizeof(message->header_type) + sizeof(message->header_origin) + sizeof(message->header_id);
		if(message->header_type == DT_PROXY_HT_CREATE || message->header_type == DT_PROXY_HT_REPORT || message->header_type == DT_CONNECTION_HT_CREATE){
			header_len += sizeof(message->header_proxy_type);
		}
	}

	if(header_len > io->message_data_size){
		report_error("message_push(): message: local header too long!");
		return(-1);
	}

	tmp_short = htons(header_len);
	if(io->remote_write(&tmp_short, sizeof(tmp_short)) == -1){
		report_error("message_push(): remote_write(%lx, %d): %s", \
				(unsigned long) &tmp_short, (int) sizeof(tmp_short), strerror(errno));
		return(-1);
	}

	if(io->remote_write(&message->data_type, sizeof(message->data_type)) == -1){
		report_error("message_push(): remote_write(%lx, %d): %s", \
				(unsigned long) &message->data_type, (int) sizeof(message->data_type), strerror(errno));
		return(-1);
	}	

	if(message->data_type == DT_NOP){
		message->data_len = 0;
	}

	/* Send the data. */
	if(message->data_len > io->message_data_size){
		report_error("message_push(): message: local data too long!");
		return(-1);
	}

	tmp_short = htons(message->data_len);
	if(io->remote_write(&tmp_short, sizeof(tmp_short)) == -1){
		report_error("message_push(): remote_write(%lx, %d): %s", \
				(unsigned long) &tmp_short, (int) sizeof(tmp_short), strerror(errno));
		return(-1);
	}

	if(message->data_type == DT_PROXY || message->data_type == DT_CONNECTION){
		tmp_short = htons(message->header_type);
		if(io->remote_write(&tmp_short, sizeof(tmp_short)) == -1){
			report_error("message_push(): remote_write(%lx, %d): %s", \
					(unsigned long) &tmp_short, (int) sizeof(tmp_short), strerror(errno));
			return(-1);
		}

		tmp_short = htons(message->header_origin);
		if(io->remote_write(&tmp_short, sizeof(tmp_short)) == -1){
			report_error("message_push(): remote_write(%lx, %d): %s", \
					(unsigned long) &tmp_short, (int) sizeof(tmp_short), strerror(errno));
			return(-1);
		}

		tmp_short = htons(message->header_id);
		if(io->remote_write(&tmp_short, sizeof(tmp_short)) == -1){
			report_error("message_push(): remote_write(%lx, %d): %s", \
					(unsigned long) &tmp_short, (int) sizeof(tmp_short), strerror(errno));
			return(-1);
		}

		if(message->header_type == DT_PROXY_HT_CREATE || message->header_type == DT_PROXY_HT_REPORT || message->header_type == DT_CONNECTION_HT_CREATE){
			tmp_short = htons(message->header_proxy_type);
			if(io->remote_write(&tmp_short, sizeof(tmp_short)) == -1){
				report_error("message_push(): remote_write(%lx, %d): %s", \
						(unsigned long) &tmp_short, (int) sizeof(tmp_short), strerror(errno));
				return(-1);
			}
		}
	}

	if(io->remote_write(message->data, message->data_len) == -1){
		report_error("message_push(): remote_write(%lx, %d): %s", \
				(unsigned long) message->data, message->data_len, strerror(errno));
		return(-1);
	}

	return(0);
}



/***********************************************************************************************************************
 *
 * message_pull()
 *
 * Input: Nothing, but we will heavily reference the global io_helper struct.
 * Output: 0 on success, -1 on error.
 *
 * Purpose: This is our message interface for receiving data.
 *
 **********************************************************************************************************************/
int message_pull(){

	unsigned short header_len;
	int retval;


	memset(message->data, '\0', io->message_data_size);

	/* Grab the header. */
	if((retval = io->remote_read(&header_len, sizeof(header_len))) == -1){

		/* During a normal disconnect condition, this is where the message_pull should fail, so check for EOF. */
		if(!io->eof){
			report_error("message_pull(): remote_read(%lx, %d): %s", (unsigned long) &header_len, (int) sizeof(header_len), strerror(errno));
		}
		return(-1);
	}
	header_len = ntohs(header_len);

	if((retval = io->remote_read(&message->data_type, sizeof(message->data_type))) == -1){
		report_error("message_pull(): remote_read(%lx, %d): %s", \
				(unsigned long) &message->data_type, (int) sizeof(message->data_type), strerror(errno));
		return(-1);
	}	
	header_len -= sizeof(message->data_type);

	if((retval = io->remote_read(&message->data_len, sizeof(message->data_len))) == -1){
		report_error("message_pull(): remote_read(%lx, %d): %s", (unsigned long) &message->data_len, (int) sizeof(message->data_len), strerror(errno));
		return(-1);
	}	
	message->data_len = ntohs(message->data_len);
	header_len -= sizeof(message->data_len);

	if(header_len > io->message_data_size){
		report_error("message_pull(): message: remote header too long!\n");
		return(-1);
	}

	if(message->data_type == DT_PROXY || message->data_type == DT_CONNECTION){

		if((retval = io->remote_read(&message->header_type, sizeof(message->header_type))) == -1){
			report_error("message_pull(): remote_read(%lx, %d): %s", \
					(unsigned long) &message->header_type, (int) sizeof(message->header_type), strerror(errno));
			return(-1);
		}	
		message->header_type = ntohs(message->header_type);
		header_len -= sizeof(message->header_type);

		if((retval = io->remote_read(&message->header_origin, sizeof(message->header_origin))) == -1){
			report_error("message_pull(): remote_read(%lx, %d): %s", \
					(unsigned long) &message->header_origin, (int) sizeof(message->header_origin), strerror(errno));
			return(-1);
		}	
		message->header_origin = ntohs(message->header_origin);
		header_len -= sizeof(message->header_origin);

		if((retval = io->remote_read(&message->header_id, sizeof(message->header_id))) == -1){
			report_error("message_pull(): remote_read(%lx, %d): %s", \
					(unsigned long) &message->header_id, (int) sizeof(message->header_id), strerror(errno));
			return(-1);
		}	
		message->header_id = ntohs(message->header_id);
		header_len -= sizeof(message->header_id);

		if(message->header_type == DT_PROXY_HT_CREATE || message->header_type == DT_PROXY_HT_REPORT || message->header_type == DT_CONNECTION_HT_CREATE){
			if((retval = io->remote_read(&message->header_proxy_type, sizeof(message->header_proxy_type))) == -1){
				report_error("message_pull(): remote_read(%lx, %d): %s", \
						(unsigned long) &message->header_proxy_type, (int) sizeof(message->header_proxy_type), strerror(errno));
				return(-1);
			}	
			message->header_proxy_type = ntohs(message->header_proxy_type);
			header_len -= sizeof(message->header_proxy_type);
		}
	}

	/* Ignore any remaining header data as unknown, and probably from a more modern version of the */
	/* protocol than we were compiled with. */
	if(header_len){

		if(header_len > io->message_data_size){
			report_error("message_pull(): headers bigger than buffer!");
			return(-1);
		}

		if((retval = io->remote_read(message->data, header_len)) == -1){
			report_error("message_pull(): remote_read(%lx, %d): %s", (unsigned long) message->data, header_len, strerror(errno));
			return(-1);
		}	
	}

	/* Grab the data. */
	if(message->data_len > io->message_data_size){
		report_error("message_pull(): message: remote data too long!");
		return(-1);
	}

	if((retval = io->remote_read(message->data, message->data_len)) == -1){
		report_error("message_pull(): remote_read(%lx, %d): %s", (unsigned long) message->data, message->data_len, strerror(errno));
		return(-1);
	}	

	return(0);
}


/***********************************************************************************************************************
 *
 * message_helper_create()
 *
 * Input:  A pointer to the data.
 *         The length of that data.
 *         The max size that data is allowed to be in this run.
 * Output: A pointer to a new message_helper node if successful, NULL if not.
 *
 * Purpose: Make a new message_helper node and fill it with data. Probably for the write buffering case where a write()
 *          somewhere is failing non-fataly. 
 *
 **********************************************************************************************************************/
struct message_helper *message_helper_create(char *data, unsigned short data_len, unsigned short message_data_size){

	struct message_helper *new_mh;

	new_mh = (struct message_helper *) calloc(1, sizeof(struct message_helper));
	if(!new_mh){
		report_error("message_helper_create(): calloc(1, %d): %s", (int) sizeof(struct message_helper), strerror(errno));
		return(NULL);
	}

	new_mh->data = (char *) calloc(message_data_size, sizeof(char));
	if(!new_mh->data){
		report_error("message_helper_create(): calloc(1, %d): %s", (int) sizeof(struct message_helper), strerror(errno));
		free(new_mh);
		return(NULL);
	}

	memcpy(new_mh->data, data, data_len);
	new_mh->data_len = data_len;

	return(new_mh);
}



/***********************************************************************************************************************
 *
 * message_helper_destroy()
 *
 * Input:  The message_helper node that we want to destroy.
 * Output: None.
 *
 * Purpose: Destroy a message_helper node.
 *
 **********************************************************************************************************************/
void message_helper_destroy(struct message_helper *mh){
	free(mh->data);
	free(mh);
}
