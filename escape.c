#include "common.h"

#define LOCAL_BUFF_SIZE 64
#define VALID_ESCAPE_ACTIONS ".#C?"

/*
 * escape sequence processing strategy:
 *
 * escape_check() drives the functions in this file.
 * We will take a consume + shift approach to handling escape sequence processing.
 *
 * The process will look something like:
 *
 *   - Read first chunk of buffer.
 *     -- If first chunk is tty data, send_message() just that data.
 *     -- If the first chunk is consumed escape chars for a non-valid sequence, send_consumed() those characters.
 *     -- If the first chunk is consumed escape chars for a valid sequence, call the appropriate payload function.
 *   - message_shift() the remaining message data to the front.
 *   - Wash, rinse, repeat until the entire buffer has been checked.
 *      -- Handle the new smaller shifted message buffer by calling escape_check() recursively.
 *   - Keep state between read()s / escape_check() calls using:
 *     -- io->escape_state - Marks the spot in the state machine.
 *     -- io->escape_depth - Records the number of tildes seen.
 *
 * This approach should be reasonable because message_shift()s and partial send_message()s
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

int escape_check(){

	int i, retval;
	char esc_char;


	for(i = 0; i < message->data_len; i++){

		if(io->escape_state == ESCAPE_NONE){

			if(message->data[i] == '\r'){
				if(send_message(i + 1) == -1){
					report_error("escape_check(): send_message(%d): %s", i + 1, strerror(errno));
					return(-1);
				}
				message_shift(i + 1);
				io->escape_state = ESCAPE_CR;
				return(escape_check()); 
			}

		}else if(io->escape_state == ESCAPE_CR){

			if(message->data[i] == '~'){
				io->escape_state = ESCAPE_TILDE;
				io->escape_depth++;
				if(i + 1 == message->data_len){
					message_shift(i + 1);
				}
			}else{

				// Check case when enter is hit multiple times.
				if(message->data[i] == '\r'){
					if(send_message(i + 1) == -1){
						report_error("escape_check(): send_message(%d): %s", i + 1, strerror(errno));
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

			if(message->data[i] == '~'){
				io->escape_depth++;
				if(i + 1 == message->data_len){
					message_shift(i + 1);
				}

			}else{
				if(is_valid_escape(message->data[i])){

					if(io->escape_depth == 1){

						esc_char = message->data[i];
						message_shift(i + 1);
						if((retval = process_escape(esc_char)) < 0){
							report_error("escape_check(): process_escape('%c'): %s", message->data[i], strerror(errno));
							if(retval == -1){
								return(retval);
							}
						}

						io->escape_state = ESCAPE_NONE;
						io->escape_depth = 0;
						return(0); 
					}else{

						message_shift(i);
						io->escape_depth--;

						if(send_consumed() == -1){
							report_error("escape_check(): send_consumed(): %s", strerror(errno));
							return(-1);
						}
						io->escape_state = ESCAPE_NONE;
						io->escape_depth = 0;
						return(escape_check()); 
					}

				}else{
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


int send_message(int count){

	int backup_data_len = message->data_len;

	if(!count){
		return(0);
	}

	message->data_type = DT_TTY;
	message->data_len = count;
	if(message_push() == -1){
		report_error("send_message(): message_push(): %s", strerror(errno));
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


	while(*escape_ptr){
		if(c == *escape_ptr){
			return(1);
		}
		escape_ptr++;
	}

	return(0);	
}


int process_escape(char c){

	switch(c){

		case '.':
			return(-2);

		case '#':
			list_all();
			break;

		case 'C':
			if(esc_shell_start() == -1){
				report_error("process_escape(): esc_shell_start(): %s", strerror(errno));
				return(-1);
			}
			break;

		case '?':
			print_valid_escapes();
			break;

		default:
			report_error("process_escape(): Unknown escape action for character w/hex value 0x%02x. Should not be here.", c);
			return(-1);
	}

	return(0);
}



void list_all(){
	printf("\n\n");
	list_listeners();
	list_connections();
}


void list_listeners(){

  struct proxy_node *cur_proxy_node;

	char *proxy_type_strings[] = {PROXY_STATIC_STRING, PROXY_DYNAMIC_STRING, PROXY_TUN_STRING, PROXY_TAP_STRING, PROXY_FILE_STRING};
	char *target_strings[] = {"Local", "Remote"};

	printf("\r################################################################################\n");
	printf("\r# Proxy listeners:\n");
	printf("\r################################################################################\n");
	printf("\n");
	printf("\rCID\tOrigin\tType\tDescription\n");
	cur_proxy_node = io->proxy_head;
	while(cur_proxy_node){

		printf("\r%d-%d\t%s\t%s\t%s\n", cur_proxy_node->origin, cur_proxy_node->id,\
				target_strings[cur_proxy_node->origin], proxy_type_strings[cur_proxy_node->proxy_type], cur_proxy_node->orig_request);

		cur_proxy_node = cur_proxy_node->next;
	}
	printf("\r\n");
}

void list_connections(){

  struct connection_node *cur_connection_node;

	char *proxy_type_strings[] = {PROXY_STATIC_STRING, PROXY_DYNAMIC_STRING, PROXY_TUN_STRING, PROXY_TAP_STRING, PROXY_FILE_STRING};
	char *target_strings[] = {"Local", "Remote"};

	printf("\r################################################################################\n");
	printf("\r# Active connections:\n");
	printf("\r################################################################################\n");
	printf("\n");
	printf("\rCID\tRead\tWritten\tOrigin\tType\tDescription\n");

	printf("\r%d-%d\t%ld\t%ld\tLocal\ttty\tTerminal\n", io->target, io->remote_fd,\
			io->tty_io_read, io->tty_io_written);

	cur_connection_node = io->connection_head;
	while(cur_connection_node){
		printf("\r%d-%d\t%ld\t%ld\t%s\t%s\t%s\n", cur_connection_node->origin, cur_connection_node->id,\
				cur_connection_node->io_read, cur_connection_node->io_written, \
				target_strings[cur_connection_node->origin], proxy_type_strings[cur_connection_node->proxy_type], cur_connection_node->rhost_rport);

		cur_connection_node = cur_connection_node->next;
	}


	printf("\r\n");

}

void print_valid_escapes(){

	printf("\n\n");
	printf("\rSupported revsh escape sequences:\n");
	printf("\n");
	printf("\r~.\tExit. (Good for killing an unresponsive session.)\n");
	printf("\r~#\tList active connections with usage statistics.\n");
	printf("\r~C\tOpen the revsh command shell. Type \"help\" inside that shell for more information.\n");
	printf("\r~?\tList the supported revsh escape sequences.\n");
	printf("\r\n");

}

