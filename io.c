
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
int negotiate_protocol(){

	unsigned short remote_data_size;

	int fcntl_flags;

	unsigned short tmp_ushort;


	io->message_data_size = 0;
	io->message_data_size--;

	/* Make sure that the data_size variable will be able to hold the pagesize on this platform. */
	if(pagesize > io->message_data_size){
		report_error("negotiate_protocol(): pagesize bigger than max message size!");
		return(-1);
	}

	io->message_data_size = pagesize;

	/* Set the socket to non-blocking. */
	if((fcntl_flags = fcntl(io->remote_fd, F_GETFL, 0)) == -1){
		report_error("negotiate_protocol(): fcntl(%d, FGETFL, 0): %s", io->remote_fd, strerror(errno));
		return(-1);
	}

	fcntl_flags |= O_NONBLOCK;
	if(fcntl(io->remote_fd, F_SETFL, fcntl_flags) == -1){
		report_error("negotiate_protocol(): fcntl(%d, FGETFL, %d): %s", io->remote_fd, fcntl_flags, strerror(errno));
		return(-1);
	}

	/* Send and receive protocol major and minor numbers. */
	// This information isn't used outside of reporting yet. 
	tmp_ushort = htons(io->control_proto_major);
	if(io->remote_write(&tmp_ushort, sizeof(tmp_ushort)) == -1){
		report_error("negotiate_protocol(): io->remote_write(%lx, %d): %s", \
				(unsigned long) &tmp_ushort, (int) sizeof(tmp_ushort), strerror(errno));
		return(-1);
	}
	tmp_ushort = htons(io->control_proto_minor);
	if(io->remote_write(&tmp_ushort, sizeof(tmp_ushort)) == -1){
		report_error("negotiate_protocol(): io->remote_write(%lx, %d): %s", \
				(unsigned long) &tmp_ushort, (int) sizeof(tmp_ushort), strerror(errno));
		return(-1);
	}
	if(io->remote_read(&tmp_ushort, sizeof(tmp_ushort)) == -1){
		report_error("negotiate_protocol(): io->remote_read(%lx, %d): %s", \
				(unsigned long) &tmp_ushort, (int) sizeof(tmp_ushort), strerror(errno));
		return(-1);
	}
	io->target_proto_major = ntohs(tmp_ushort);
	if(io->remote_read(&tmp_ushort, sizeof(tmp_ushort)) == -1){
		report_error("negotiate_protocol(): io->remote_read(%lx, %d): %s", \
				(unsigned long) &tmp_ushort, (int) sizeof(tmp_ushort), strerror(errno));
		return(-1);
	}
	io->target_proto_minor = ntohs(tmp_ushort);

	/* Send our desired message size. */
	tmp_ushort = htons(io->message_data_size);
	if(io->remote_write(&tmp_ushort, sizeof(tmp_ushort)) == -1){
		report_error("negotiate_protocol(): io->remote_write(%lx, %d): %s", \
				(unsigned long) &tmp_ushort, (int) sizeof(tmp_ushort), strerror(errno));
		return(-1);
	}

	/* Recieve their desired message size. */
	if(io->remote_read(&tmp_ushort, sizeof(tmp_ushort)) == -1){
		report_error("negotiate_protocol(): io->remote_read(%lx, %d): %s", \
				(unsigned long) &tmp_ushort, (int) sizeof(tmp_ushort), strerror(errno));
		return(-1);
	}
	remote_data_size = ntohs(tmp_ushort);

	/* Make sure it isn't smaller than our totally reasonable minimum. */
	if(remote_data_size < MINIMUM_MESSAGE_SIZE){
		report_error("negotiate_protocol(): Can't agree on a message size!");
		return(-1);
	}

	/* Set the message size to the smaller of the two, and malloc the space. */
	io->message_data_size = io->message_data_size < remote_data_size ? io->message_data_size : remote_data_size;
	// free() called in io_clean().
	if((message->data = (char *) malloc(io->message_data_size)) == NULL){
		report_error("negotiate_protocol(): malloc(%d): %s", io->message_data_size, strerror(errno));
		return(-1);
	}

	return(0);
}

/***********************************************************************************************************************
 * 
 * seppuku()
 *
 * Input: The signal being handled. (SIGALRM)
 * Output: None. 
 * 
 * Purpose: To catch SIGALRM and exit quietly. (切腹)
 * 
 **********************************************************************************************************************/
void seppuku(int signal){
	exit(-signal);
}
