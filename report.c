
#include "common.h"

#define ERROR_BUFF_SIZE 1024


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

	char error_string[ERROR_BUFF_SIZE] = {0};

	va_start(list_ptr, fmt);
	retval = vsnprintf(error_string, ERROR_BUFF_SIZE - 1, fmt, list_ptr);
	va_end(list_ptr);

	if(retval < 0){
		if(verbose){
			fprintf(stderr, "report_error(): vsnprintf(%lx, %d, %lx, %lx): %s\n", \
					(unsigned long) error_string, ERROR_BUFF_SIZE - 1, (unsigned long) fmt, (unsigned long) list_ptr, strerror(errno));
		}
		return;
	}

	if(verbose > 1){
		if(io && io->controller){
			// io->controller's tty is raw right now. Stick a \r in there for legibility.
			fprintf(stderr, "\r");
		}

		fprintf(stderr, "%s\n", error_string);
	}

	// This may have been a case where we are handling errors before io was set up. Exit now if that's the case.
	if(!io){
		return;
	}

	if(io->controller || io->init_complete){

		if(io->controller){
			if(io->log_stream){
				if(report_log_string(error_string) == -1){
					if(verbose){
						fprintf(stderr, "report_error(): report_log_string(%lx): %s\n", \
								(unsigned long) error_string, strerror(errno));
					}
					return;
				}
			}
		}else{

			message->data_type = DT_ERROR;

			message->data_len = strlen(error_string) + 1;
			if(message->data_len > io->message_data_size){
				message->data_len = io->message_data_size - 1;
				message->data[io->message_data_size - 1] = '\0';
			}
			memcpy(message->data, error_string, message->data_len);

			if(message_push() == -1){
				if(verbose){
					fprintf(stderr, "report_error(): message_push(): %s\n", strerror(errno));
				}
				return;
			}
		}
	}
}

/* variadic functions are tricky. Setting up report_log() (and report_error() above) as a wrapper that converts the variadic variables to a string before calling report_log_string. */
int report_log(char *fmt, ...){

	int retval;

	va_list list_ptr;
	char error_string[ERROR_BUFF_SIZE] = {0};

	va_start(list_ptr, fmt);
	retval = vsnprintf(error_string, ERROR_BUFF_SIZE - 1, fmt, list_ptr);
	va_end(list_ptr);

	if(retval < 0){
		if(verbose){
			fprintf(stderr, "report_log(): vsnprintf(%lx, %d, %lx, %lx): %s\n", \
					(unsigned long) error_string, ERROR_BUFF_SIZE - 1, (unsigned long) fmt, (unsigned long) list_ptr, strerror(errno));
		}
		return(retval);
	}

	if(verbose > 1){
		fprintf(stderr, "\r%s\n", error_string);
	}

	return(report_log_string(error_string));
}

int report_log_string(char *error_string){

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

	if(fprintf(io->log_stream, "%s\n", error_string) < 0){
		if(verbose){
			fprintf(stderr, "report_log_string(): fprintf(%lx, \"%%s\\n\", %lx): %s\n", \
					(unsigned long) io->log_stream, (unsigned long) error_string, strerror(errno));
		}
		return(-1);

	}

	fflush(io->log_stream);

	return(0);
}
