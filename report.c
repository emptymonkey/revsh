
#include "common.h"


/***********************************************************************************************************************
 *
 * report_error()
 *
 * Input: A pointer to our io_helper object, and the fmt specification as you would find in a normal printf
 *  statement.
 * Output: None. Error reporting is a best effort maneuver.
 *
 * Purpose: Provide a wrapper for error reporting that inspects the io state and does the right thing. Bonus points for
 *  offering a printf style interface for this functionality.
 *
 **********************************************************************************************************************/
void report_error(char *fmt, ...){

	int retval;
	va_list list_ptr;

	struct message_helper *message;


	va_start(list_ptr, fmt);

	if(verbose){

		if(io && io->controller){
			// io->controller's tty is raw right now. Stick a \r in there for legibility.
			fprintf(stderr, "\r");
		}

		vfprintf(stderr, fmt, list_ptr);
		fprintf(stderr, "\n");
	}

	// This may have been a case where we are handling errors before io was set up. Exit now if that's the case.
	if(!io){
		return;
	}

	message = &io->message;

	if(io->controller || io->init_complete){

		va_start(list_ptr, fmt);

		if(io->controller && io->log_stream){
			if(report_log(fmt, list_ptr) == -1){
				if(verbose){
					fprintf(stderr, "report_error(): report_log(%lx, %lx): %s\n", \
							(unsigned long) fmt, (unsigned long) list_ptr, strerror(errno));
				}
				return;
			}
		}else{

			message->data_type = DT_ERROR;

			if((retval = vsnprintf(message->data, io->message_data_size, fmt, list_ptr)) < 0){
				if(verbose){
					fprintf(stderr, "report_error(): vsnprintf(%lx, %d, %lx, %lx): %s\n", \
							(unsigned long) message->data, io->message_data_size, (unsigned long) fmt, (unsigned long) list_ptr, strerror(errno));
				}
				return;
			}

			// We want to ensure that the message data is a proper '\0' terminated string.
			// This will be the assumption on the recieving end.
			va_end(list_ptr);
			if(retval == io->message_data_size){
				message->data[io->message_data_size - 1] = '\0';
			}

			message->data_len = retval;

			if(message_push() == -1){
				if(verbose){
					fprintf(stderr, "report_error(): message_push(): %s\n", strerror(errno));
				}
				return;
			}
		}
	}
}

int report_log(char *fmt, ...){

	va_list list_ptr;

	char *date_string;
	char *tmp_ptr;

	time_t ts;

	ts = time(NULL);
	date_string = asctime(gmtime(&ts));  

	tmp_ptr = strchr(date_string, '\n');
	if(tmp_ptr){
		*tmp_ptr = '\0';
	}

	fprintf(io->log_stream, "%s\t", date_string);

	va_start(list_ptr, fmt);

	if(vfprintf(io->log_stream, fmt, list_ptr) < 0){
		if(verbose){
			fprintf(stderr, "report_log(): vfprintf(%lx, %lx, %lx): %s\n", \
					(unsigned long) io->log_stream, (unsigned long) fmt, (unsigned long) list_ptr, strerror(errno));
		}
		return(-1);

	}

	va_end(list_ptr);

	fprintf(io->log_stream, "\n");
	fflush(io->log_stream);

	return(0);
}
