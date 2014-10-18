
#include "common.h"


/* The plaintext case for I/O is really easy. Call the openssl BIO_* functions and return. */

/***********************************************************************************************************************
 *
 * remote_read_plaintext()
 *
 * Input: A pointer to our remote_io_helper object, a pointer to the buffer we want to fill, and the count of characters
 *	we should try to read.
 * Output: The count of characters succesfully read, or an error code. (man BIO_read for more information.)
 *
 * Purpose: Fill our buffer, but this is the simple plaintext wrapper case. Nothing fancy here.
 *
 **********************************************************************************************************************/
int remote_read_plaintext(struct remote_io_helper *io, void *buff, size_t count){
  return(BIO_read(io->connect, buff, count));
}


/***********************************************************************************************************************
 *
 * remote_write_plaintext()
 *
 * Input: A pointer to our remote_io_helper object, a pointer to the buffer we want to empty, and the count of
 *	characters we should try to write.
 * Output: The count of characters succesfully written, or an error code. (man BIO_write for more information.)
 *
 * Purpose: Empty our buffer, but this is the simple plaintext wrapper case. Nothing fancy here.
 *
 **********************************************************************************************************************/
int remote_write_plaintext(struct remote_io_helper *io, void *buff, size_t count){
  return(BIO_write(io->connect, buff, count));
}


/***********************************************************************************************************************
 *
 * remote_read_encrypted()
 *
 * Input: A pointer to our remote_io_helper object, a pointer to the buffer we want to fill, and the count of characters
 *	we should try to read.
 * Output: The count of characters succesfully read, or an error code. (man BIO_read for more information.)
 *
 * Purpose: Fill our buffer. This is the SSL encrypted case.
 *
 * Note: This function won't return until it has satisfied the request to read count characters, or encountered an error
 *	trying. It assumes the socket is ready for action (either blocking, or has just passed a select() call.) If it 
 *	cannot fulfill the requested character count initially, it will call select() itself in a loop until it can.
 *
 **********************************************************************************************************************/
int remote_read_encrypted(struct remote_io_helper *io, void *buff, size_t count){
	
	int retval;
	fd_set fd_select;
	int ssl_error = SSL_ERROR_NONE;	


	do{
		/* We've already been through the loop once, but now we need to wait for the socket to be ready. */
		if(ssl_error != SSL_ERROR_NONE){
			FD_ZERO(&fd_select);
			FD_SET(io->remote_fd, &fd_select);

			if(ssl_error == SSL_ERROR_WANT_READ){
				if((retval = select(io->remote_fd + 1, &fd_select, NULL, NULL, NULL)) == -1){
					print_error(io, "%s: %d: select(%d, %lx, NULL, NULL, NULL): %s\n", \
						program_invocation_short_name, io->controller, \
						io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
					return(-1);
				}

			}else /* if(ssl_error == SSL_ERROR_WANT_WRITE) */ {
				if((retval = select(io->remote_fd + 1, NULL, &fd_select, NULL, NULL)) == -1){
					print_error(io, "%s: %d: select(%d, NULL, %lx, NULL, NULL): %s\n", \
						program_invocation_short_name, io->controller, \
						io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
					return(-1);
				}
			}
		}

		retval = SSL_read(io->ssl, buff, count);

		switch(SSL_get_error(io->ssl, retval)){

			case SSL_ERROR_NONE:
			case SSL_ERROR_ZERO_RETURN:
				return(retval);
				break;

			case SSL_ERROR_WANT_READ:
				ssl_error = SSL_ERROR_WANT_READ;
				break;

			case SSL_ERROR_WANT_WRITE:
				ssl_error = SSL_ERROR_WANT_WRITE;
				break;

			default:
				return(-1);
		}
	} while(ssl_error);

	return(-1);
}


/***********************************************************************************************************************
 *
 * remote_write_encrypted()
 *
 * Input: A pointer to our remote_io_helper object, a pointer to the buffer we want to empty, and the count of
 *	characters we should try to write.
 * Output: The count of characters succesfully written, or an error code. (man BIO_write for more information.)
 *
 * Purpose: Empty our buffer, but this is the simple plaintext wrapper case. Nothing fancy here.
 *
 * Note: This function won't return until it has satisfied the request to write count characters, or encountered an
 *	error trying. It assumes the socket is ready for action (either blocking, or has just passed a select() call.) If
 *	it cannot fulfill the requested character count initially, it will call select() itself in a loop until it can.
 *
 **********************************************************************************************************************/
int remote_write_encrypted(struct remote_io_helper *io, void *buff, size_t count){
	
	int retval;
	fd_set fd_select;
	int ssl_error = SSL_ERROR_NONE;	


	do{

		/* We've already been through the loop once, but now we need to wait for the socket to be ready. */
		if(ssl_error != SSL_ERROR_NONE){
			FD_ZERO(&fd_select);
			FD_SET(io->remote_fd, &fd_select);

			if(ssl_error == SSL_ERROR_WANT_READ){
				if((retval = select(io->remote_fd + 1, &fd_select, NULL, NULL, NULL)) == -1){
					print_error(io, "%s: %d: select(%d, %lx, NULL, NULL, NULL): %s\n", \
						program_invocation_short_name, io->controller, \
						io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
					return(-1);
				}

			}else /* if(ssl_error == SSL_ERROR_WANT_WRITE) */ {
				if((retval = select(io->remote_fd + 1, NULL, &fd_select, NULL, NULL)) == -1){
					print_error(io, "%s: %d: select(%d, NULL, %lx, NULL, NULL): %s\n", \
						program_invocation_short_name, io->controller, \
						io->remote_fd + 1, (unsigned long) &fd_select, strerror(errno));
					return(-1);
				}
			}
		}

		retval = SSL_write(io->ssl, buff, count);

		switch(SSL_get_error(io->ssl, retval)){

			case SSL_ERROR_NONE:
			case SSL_ERROR_ZERO_RETURN:
				return(retval);
				break;

			case SSL_ERROR_WANT_READ:
				ssl_error = SSL_ERROR_WANT_READ;
				break;

			case SSL_ERROR_WANT_WRITE:
				ssl_error = SSL_ERROR_WANT_WRITE;
				break;

			default:
				return(-1);
		}
	} while(ssl_error);

	return(-1);
}


/***********************************************************************************************************************
 *
 * remote_printf()
 *
 * Input: A pointer to our remote_io_helper object, and the fmt specification as you would find in a normal printf
 *	statement.
 * Output: The count of characters succesfully printed.
 *
 * Purpose: Provide a printf() style wrapper that will do the right thing down our socket.
 *
 **********************************************************************************************************************/
int remote_printf(struct remote_io_helper *io, char *fmt, ...){

	int retval;
	char buff[BUFFER_SIZE];
	va_list list_ptr;


	va_start(list_ptr, fmt);

	/* XXX Add a loop here in case we need to print something longer than BUFFER_SIZE. */
	memset(buff, 0, BUFFER_SIZE);
	if((retval = vsnprintf(buff, BUFFER_SIZE - 1, fmt, list_ptr)) < 0){
		print_error(io, "%s: %d: vsnprintf(%lx, %d, %lx, %lx): %s\n", \
				program_invocation_short_name, io->controller, \
				(unsigned long) buff, BUFFER_SIZE - 1, (unsigned long) fmt, (unsigned long) list_ptr, \
				strerror(errno));
		return(retval);
	}
	io->remote_write(io, buff, retval + 1);

	va_end(list_ptr);

	return(retval);
}


/***********************************************************************************************************************
 *
 * print_error()
 *
 * Input: A pointer to our remote_io_helper object, and the fmt specification as you would find in a normal printf
 *	statement.
 * Output: The count of characters succesfully printed.
 *
 * Purpose: Provide a wrapper that allows us to just call print_error() and have the correct thing happen regardless of
 *	being a target or a controller. This simplifies the error reporting code greatly.
 *
 **********************************************************************************************************************/
int print_error(struct remote_io_helper *io, char *fmt, ...){

	int retval = 0;
	va_list list_ptr;


	va_start(list_ptr, fmt);

	if(io->controller){
		if((retval = vfprintf(stderr, fmt, list_ptr)) < 0){
			print_error(io, "%s: %d: vfprintf(stderr, %lx, %lx): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) fmt, (unsigned long) list_ptr, \
					strerror(errno));
		}
		fflush(stderr);
	}else{
		retval = remote_printf(io, fmt, list_ptr); 
	}

	return(retval);
}
