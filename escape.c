#include "common.h"

#define LOCAL_BUFF_SIZE 64
#define VALID_ESCAPE_ACTIONS ".#?"

/*
 * escape sequence processing strategy:
 *
 * escape_check() drives the functions in this file.
 * We will take a consume + shift approach to handling escape sequence processing.
 *
 * The process will look something like:
 *
 *   - Read first chunk of buffer.
 *     -- If first chunk is tty data, message_send() just that data.
 *     -- If the first chunk is consumed escape chars for a non-valid sequence, send_consumed() those characters.
 *     -- If the first chunk is consumed escape chars for a valid sequence, call the appropriate payload function.
 *   - message_shift() the remaining message data to the front.
 *   - Wash, rinse, repeat until the entire buffer has been checked.
 *      -- Handle the new smaller shifted message buffer by calling escape_check() recursively.
 *   - Keep state between read()s / escape_check() calls using:
 *     -- io->escape_state - Marks the spot in the state machine.
 *     -- io->escape_depth - Records the number of tildes seen.
 *
 * This approach should be reasonable because message_shift()s and partial message_send()s
 * (and the associated malloc()s + memcpy()s inside those functions to back up the remaining message data while
 * processing) will only occur in the worst case scenarios. In the average case, it will be one character at a time
 * at the control node (because humans are slow) or a couple of characters at a time as a full valid escape request
 * has been forwarded to a target node. This is almost certainly a robust approach and probably bordering on
 * over engineered. 
 *
 */


/******************************************************************************
 *
 *  ()
 *
 *  Inputs: 
 *
 *  Outputs: 
 *
 *  Purpose: 
 *
 ******************************************************************************/

// XXX return -2 for the '.' exit case.
// XXX If message_depth > 1 for a valid sequence, forward it off. Don't process locally. 


int escape_check(){

	int i, retval;

	//	fprintf(stderr, "\n\rDEBUG: escape_check(): message->data_len: %d\n", message->data_len);
	//	fprintf(stderr, "\rDEBUG: escape_check(): io->escape_state: %d\n", io->escape_state);

	for(i = 0; i < message->data_len; i++){

		if(io->escape_state == ESCAPE_NONE){
			//		fprintf(stderr, "\rDEBUG: ESCAPE_NONE\n");

			if(message->data[i] == '\r'){
				//				fprintf(stderr, "\rDEBUG: ESCAPE_NONE: \\r\n");
				if(message_send(i + 1) == -1){
					report_error("escape_check(): message_send(%d): %s", i + 1, strerror(errno));
					return(-1);
				}
				message_shift(i + 1);
				io->escape_state = ESCAPE_CR;
				return(escape_check()); 
			}

		}else if(io->escape_state == ESCAPE_CR){
			//		fprintf(stderr, "\rDEBUG: ESCAPE_CR\n");

			if(message->data[i] == '~'){
				//				fprintf(stderr, "\rDEBUG: ESCAPE_CR: ~\n");
				io->escape_state = ESCAPE_TILDE;
				io->escape_depth++;
				if(i + 1 == message->data_len){
					message_shift(i + 1);
				}
			}else{
				//				fprintf(stderr, "\rDEBUG: ESCAPE_CR: !~: %c\n", message->data[i]);

				// Check case when enter is hit multiple times.
				if(message->data[i] == '\r'){
					//					fprintf(stderr, "\rDEBUG: ESCAPE_NONE: \\r\n");
					if(message_send(i + 1) == -1){
						report_error("escape_check(): message_send(%d): %s", i + 1, strerror(errno));
						return(-1);
					}
					message_shift(i + 1);
					io->escape_state = ESCAPE_CR;
					return(escape_check()); 
				}

				io->escape_state = ESCAPE_NONE;
				io->escape_depth = 0;
			}

		}else if(io->escape_state == ESCAPE_TILDE){
			//			fprintf(stderr, "\rDEBUG: ESCAPE_TILDE\n");

			if(message->data[i] == '~'){
				//				fprintf(stderr, "\rDEBUG: ESCAPE_TILDE: ~\n");
				io->escape_depth++;
				if(i + 1 == message->data_len){
					message_shift(i + 1);
				}

			}else{
				//				fprintf(stderr, "\rDEBUG: ESCAPE_TILDE: !~: %c\n", message->data[i]);
				if(is_valid_escape(message->data[i])){
					//					fprintf(stderr, "\rDEBUG: ESCAPE_TILDE: !~: is_valid_escape()\n");

					if(io->escape_depth == 1){
						//						fprintf(stderr, "\rDEBUG: ESCAPE_TILDE: !~: is_valid_escape(): io->escape_depth == 1\n");
						if((retval = process_escape(message->data[i])) < 0){
							if(retval == -1){
								report_error("escape_check(): forward_escape('%c'): %s", message->data[i], strerror(errno));
							}
//							fprintf(stderr, "\rDEBUG: escape_check(): retval < 0: %d\n", retval);
							return(retval);
						}
//						fprintf(stderr, "\rDEBUG: escape_check(): retval: %d\n", retval);

					}else{
						//						fprintf(stderr, "\rDEBUG: ESCAPE_TILDE: !~: is_valid_escape(): io->escape_depth != 1\n");
						if(forward_escape(message->data[i]) == -1){
							report_error("escape_check(): forward_escape('%c'): %s", message->data[i], strerror(errno));
							return(-1);
						}
					}
					message_shift(i + 1);
					io->escape_state = ESCAPE_NONE;
					io->escape_depth = 0;
					return(escape_check()); 

				}else{
					//					fprintf(stderr, "\rDEBUG: ESCAPE_TILDE: !~: !is_valid_escape()\n");
					message_shift(i);
					if(send_consumed() == -1){
						report_error("escape_check(): send_consumed(): %s", strerror(errno));
						return(-1);
					}
					io->escape_state = ESCAPE_NONE;
					io->escape_depth = 0;
					return(escape_check()); 
				}
			}
		}
	}

	return(0);
}




int send_consumed(){

	unsigned int i;
	int return_code = 0;

	char common_case[LOCAL_BUFF_SIZE];

	// No need to backup or mangle the data_type. Everything here is DT_TTY, and that was set by the handler.
	int backup_data_len;
	char *backup_data;


	if(io->escape_depth > io->message_data_size){
		// Did you really just try sending more than 4k of tildes?!
		// Truncate. I don't care that you don't get them all. You're just being silly anyway. 
		io->escape_depth = io->message_data_size;
	}

	// In the common case, we'll be sending a couple of characters.
	// We'll use the stack storage for that case and only malloc() if we really need to.
	backup_data_len = message->data_len;
	if(backup_data_len > LOCAL_BUFF_SIZE){
		// free() called in this function.
		if((backup_data = (char *) calloc(backup_data_len, sizeof(char))) == NULL){
			report_error("send_consumed(): calloc(%d, %d): %s", backup_data_len, (int) sizeof(char), strerror(errno));
			return_code = -1;
			goto CLEANUP;
		}
	}else{
		backup_data = common_case;
	}
	memcpy(backup_data, message->data, backup_data_len);

	message->data_type = DT_TTY;
	message->data_len = io->escape_depth;
	for(i = 0; i < io->escape_depth; i++){
		message->data[i] = '~';
	}

	if(message_push() == -1){
		report_error("handle_local_read(): message_push(): %s", strerror(errno));
		return_code = -1;
		goto CLEANUP;
	}

	memcpy(message->data, backup_data, backup_data_len);
	message->data_len = backup_data_len;

CLEANUP:
	if(backup_data && backup_data != common_case){
		free(backup_data);
	}

	return(return_code);
}





int message_send(int count){

	int backup_data_len = message->data_len;

	if(!count){
		return(0);
	}

	message->data_type = DT_TTY;
	message->data_len = count;
	if(message_push() == -1){
		report_error("handle_local_read(): message_push(): %s", strerror(errno));
		return(-1);
	}
	message->data_len = backup_data_len;

	return(0);
}


void message_shift(int count){
	int i;

	for(i = 0; i < message->data_len - count; i++){
		message->data[i] = message->data[i + count];
	}
	message->data_len -= count;
}




int is_valid_escape(char c){

	char valid_escapes[] = VALID_ESCAPE_ACTIONS;
	char *escape_ptr = valid_escapes;

//	fprintf(stderr, "\rDEBUG: is_valid_escape(): start\n");
//	fprintf(stderr, "\rDEBUG: is_valid_escape(): c: 0x%02x\n", c);

	while(*escape_ptr){
//		fprintf(stderr, "\rDEBUG: is_valid_escape(): *escape_ptr: %c\n", *escape_ptr);
		if(c == *escape_ptr){
//			fprintf(stderr, "\rDEBUG: is_valid_escape(): MATCH!\n");
			return(1);
		}
		escape_ptr++;
	}

//	fprintf(stderr, "\rDEBUG: is_valid_escape(): start\n");
	return(0);	
}



int process_escape(char c){

//	fprintf(stderr, "\rDEBUG: process_escape(): start\n");
//	fprintf(stderr, "\rDEBUG: process_escape(): c: 0x%02x\n", c);

	switch(c){

		case '.':
			return(-2);

		case '#':
			list_connections();
			break;

		case '?':
			list_valid_escapes();
			break;

		default:
			//			report_error("process_escape(): Unknown escape action \'%c\'. Maybe it was added to the is_valid_escape() map, but forgot to add a process_escape() case to handle it?!\n", c);
			report_error("process_escape(): Unknown escape action. Should not be here.");
			return(-1);
	}

//	fprintf(stderr, "\rDEBUG: process_escape(): stop\n");
	return(0);
}


void list_connections(){
	fprintf(stderr, "\r\n\nDEBUG: list_connections(): Do the needful!\n");
}

void list_valid_escapes(){
	fprintf(stderr, "\r\n\nDEBUG: list_valid_escapes(): Do the needful!\n");
}

int forward_escape(char c){

	fprintf(stderr, "\r\n\nDEBUG: forward_escape(): c: %c\n", c);
	return(0);
}
