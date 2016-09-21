/*
 *  In the beginning there was input and output, and it was good.
 *  Then the BOFH added signal handling.
 *  The broker loop was more complicated, but still within the understanding of man.
 *  The kiddies then cried out "Where be our tunnels?! How canz we be 1337 w/out crypto tunnels?!! CAN HAS SOCKS?!"
 *  The BOFH heard the wailing, lamenting, and gnashing of kiddie teeths and added socks proxy support to the broker loop.
 *  It worked and the kiddies were happy, but now the loop was complicated beyond the understanding of man.
 *  It was in this age that the BOFA moved the inner workings of the broker loop here, with a handler for each case.
 *  Only now is the loop back within the understanding of man.
 *  Once again, it is good.
 */

#include "common.h"

#ifdef LINENOISE
extern const struct esc_shell_command null_sub_commands;
extern const struct esc_shell_command device_sub_commands;
extern const struct esc_shell_command file_sub_commands;
extern const struct esc_shell_command proxy_sub_commands;
extern const struct esc_shell_command menu;
#endif

/******************************************************************************
 *
 * handle_signal_sigwinch()
 *
 * Inputs: None, but we will leverage the global io struct.
 * Outputs: 0 for success. -1 on error.
 *
 * Purpose: Handle the broker case where select() was interrupted by a
 *   SIGWINCH signal.
 *
 * Strategy: Query the OS for the new window size, then message_push() it to
 *   the remote node.
 *
 ******************************************************************************/
int handle_signal_sigwinch(){

	int retval;

	if((retval = ioctl(io->local_out_fd, TIOCGWINSZ, io->tty_winsize)) == -1){
		report_error("handle_signal_sigwinch(): ioctl(%d, TIOCGWINSZ, %lx): %s", io->local_out_fd, (unsigned long) io->tty_winsize, strerror(errno));
		return(-1);
	}

	message->data_type = DT_WINRESIZE;
	*((unsigned short *) message->data) = htons(io->tty_winsize->ws_row);
	message->data_len = sizeof(io->tty_winsize->ws_row);
	*((unsigned short *) (message->data + message->data_len)) = htons(io->tty_winsize->ws_col);
	message->data_len += sizeof(io->tty_winsize->ws_col);

	if((retval = message_push()) == -1){
		report_error("handle_signal_sigwinch(): message_push(): %s", strerror(errno));
		return(-1);
	}

	return(0);
}


/******************************************************************************
 *
 * handle_local_write()
 *
 * Inputs: None, but we will leverage the global io struct.
 * Outputs: 0 for success. -1 on error.
 *
 * Purpose: Handle the broker case where there is a message queue to write to
 *   the tty / shell and the local fd now seems to be ready to take it.
 *
 ******************************************************************************/
int handle_local_write(){

	int retval;
	struct message_helper *tmp_message;


	while(io->tty_write_head){

		tmp_message = io->tty_write_head;

		retval = write(io->local_out_fd, tmp_message->data, tmp_message->data_len);

		if(retval == -1){
			if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK){
				report_error("handle_local_write(): write(%d, %lx, %d): %s", io->local_out_fd, (unsigned long) tmp_message->data, tmp_message->data_len, strerror(errno));
				return(-1);
			}
		}

		if(retval != tmp_message->data_len){
			tmp_message->data_len -= retval;
			memmove(tmp_message->data, tmp_message->data + retval, tmp_message->data_len);
			break;
		}

		io->tty_write_head = tmp_message->next;
		message_helper_destroy(tmp_message);
	}

	return(0);
}


/******************************************************************************
 *
 * handle_local_read()
 *
 * Inputs: None, but we will leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error. -2 on non-fatal error.
 *
 * Purpose: Handle the broker case where the tty / shell is ready to be read.
 *
 ******************************************************************************/
int handle_local_read(){

	int retval;

	message->data_type = DT_TTY;

	if((retval = read(io->local_in_fd, message->data, io->message_data_size)) == -1){
		if(errno != EINTR){
			if(errno == EIO){
				return(-2);
			}else{
				report_error("handle_local_read(): read(%d, %lx, %d): %s", io->local_in_fd, (unsigned long) message->data, io->message_data_size, strerror(errno));
				return(retval);
			}
		}

	}else{

		io->tty_io_written += retval;
		message->data_len = retval;

		if(message->data_len){

			if(!io->target){
				if((retval = escape_check()) < 0){
					if(retval == -1){
						report_error("handle_local_read(): escape_check(): %s", strerror(errno));
					}
					return(retval);
				}
//				fprintf(stderr, "\r\nDEBUG: handle_local_read(): escape_check() retval: %d\n", retval);
//				fprintf(stderr, "\r\nDEBUG: handle_local_read(): message->data_len: %d\n", message->data_len);
			}

			// Check again for data_len, because we may have consumed the characters in the buffer during the escape_check().
			if(message->data_len){
				if((retval = message_push()) == -1){
					report_error("handle_local_read(): message_push(): %s", strerror(errno));
					return(-1);
				}
			}
		}
	}

	return(0);
}


// XXX
int handle_command_shell_read(){

	int retval;
	char **command_vec;
	const struct esc_shell_command *command_node;
	char *tmp_ptr;
	unsigned short tmp_origin, tmp_id;

	struct proxy_node *tmp_proxy_node;
	struct connection_node *tmp_connection_node;

	int return_code = 0;


	if((retval = read(io->command_fd[0], io->command_buff, ESC_COMMAND_MAX)) == -1){
		report_error("handle_command_shell_read(): read(%d, %lx, %d): %s", io->command_fd[0], (unsigned long) io->command_buff, ESC_COMMAND_MAX, strerror(errno));
		return(-1);
	}

	if(!retval){
		return(0);
	}

	if(io->command_buff[retval - 1] != '\0'){
		report_error("handle_command_shell_read(): read(%d, %lx, %d): Incomplete command string. Ignoring.", io->command_fd[1], (unsigned long) io->command_buff, ESC_COMMAND_MAX);
		return(-1);
	}

//	fprintf(stderr, "\r\nDEBUG: handle_command_shell_read(): io->command_buff: %s\r\n", io->command_buff);

	if((command_vec = string_to_vector(io->command_buff)) == NULL){
		report_error("handle_command_shell_read(): string_to_vector(%lx): %s", io->command_buff, strerror(errno));
		return(-1);
	}

	if((command_node = find_in_menu(command_vec)) == NULL){
		fprintf(stderr, "\r\nCommand shell error: Unknown command: \"%s\"\n\r", io->command_buff);
		return_code = -2;
		goto CLEANUP;
	}

	// XXX
//	fprintf(stderr, "\r\nDEBUG: command_node->completion_string: %s\n", command_node->completion_string);

	if(!strcmp(command_node->completion_string, "list")){
		list_all();

	}else if(!strcmp(command_node->completion_string, "kill")){

		tmp_origin = (unsigned short) strtol(command_vec[1], &tmp_ptr, 10);
		tmp_id = (unsigned short) strtol(tmp_ptr + 1, NULL, 10);

		if((tmp_origin == io->target) && (tmp_id == io->remote_fd)){
			fprintf(stderr, "\r\nCommand shell error: Attempting to kill the revsh connection is not allowed. Please exit the process normally.\n\r");
			return_code = -2;
			goto CLEANUP;
		}

		if((tmp_proxy_node = proxy_node_find(tmp_origin, tmp_id))){
			if(handle_send_dt_proxy_ht_destroy(tmp_origin, tmp_id, 0) == -1){
				report_error("handle_command_shell_read(): handle_send_dt_proxy_ht_destroy(%d, %d, 0): %s", tmp_origin, tmp_id, strerror(errno));
				return_code = -1;
				goto CLEANUP;
			}
			proxy_node_delete(tmp_proxy_node);

		}else if((tmp_connection_node = connection_node_find(tmp_origin, tmp_id))){
			if(handle_send_dt_connection_ht_destroy(tmp_origin, tmp_id, 0) == -1){
				report_error("handle_command_shell_read(): handle_send_dt_connection_ht_destroy(%d, %d, 0): %s", tmp_origin, tmp_id, strerror(errno));
				return_code = -1;
				goto CLEANUP;
			}
			connection_node_delete(tmp_connection_node);

		}else{
			fprintf(stderr, "\r\nCommand shell error: Attempting to kill CID \"%s\": No such connection found. Ignoring.\n\r", command_vec[1]);
			return_code = -2;
		}

	}else if(!strcmp(command_node->completion_string, "proxy local")){

		if(proxy_node_new(command_vec[2], PROXY_STATIC) == NULL){
			if(errno){
				report_error("handle_command_shell_read(): proxy_node_new(%lx, PROXY_STATIC): %s", (unsigned long) command_vec[2], strerror(errno));
				return_code = -1;
				goto CLEANUP;
			}
			fprintf(stderr, "\r\nCommand shell error: Unable to create local proxy \"%s\": Illegal string?\n\r", command_vec[1]);
			return_code = -2;
			goto CLEANUP;
		}

	}else if(!strcmp(command_node->completion_string, "proxy dynamic")){

		if(proxy_node_new(command_vec[2], PROXY_DYNAMIC) == NULL){
			if(errno){
				report_error("handle_command_shell_read(): proxy_node_new(%lx, PROXY_DYNAMIC): %s", (unsigned long) command_vec[2], strerror(errno));
				return_code = -1;
				goto CLEANUP;
			}
			fprintf(stderr, "\r\nCommand shell error: Unable to create local proxy \"%s\": Illegal string?\n\r", command_vec[1]);
			return_code = -2;
			goto CLEANUP;
		}

	}else if(!strcmp(command_node->completion_string, "proxy remote")){

		if(handle_send_dt_proxy_ht_create(command_vec[2], PROXY_STATIC) < 0){
			report_error("handle_command_shell_read(): handle_send_dt_proxy_ht_create(%lx, PROXY_STATIC): %s", (unsigned long) command_vec[2], strerror(errno));
			if(retval == -1){
				return_code = -1;
			}
			return_code = -2;
			goto CLEANUP;
		}

	}else if(!strcmp(command_node->completion_string, "proxy bypass")){
		if(handle_send_dt_proxy_ht_create(command_vec[2], PROXY_DYNAMIC) < 0){
			report_error("handle_command_shell_read(): handle_send_dt_proxy_ht_create(%lx, PROXY_DYNAMIC): %s", (unsigned long) command_vec[2], strerror(errno));
			if(retval == -1){
				return_code = -1;
			}
			return_code = -2;
			goto CLEANUP;
		}

#ifndef FREEBSD
	}else if(!strcmp(command_node->completion_string, "device tun")){

		if((tmp_connection_node = handle_tun_tap_init(IFF_TUN)) == NULL){
			report_error("handle_command_shell_read(): handle_tun_tap_init(IFF_TUN): %s", strerror(errno));
			return_code = -2;
		}else{
			if(handle_send_dt_connection_ht_create(tmp_connection_node) == -1){
				report_error("handle_command_shell_read(): handle_send_dt_connection_ht_create(%lx): %s", (unsigned long) tmp_connection_node, strerror(errno));
				return(-1);
				goto CLEANUP;
			}
		}

	}else if(!strcmp(command_node->completion_string, "device tap")){

		if((tmp_connection_node = handle_tun_tap_init(IFF_TAP)) == NULL){
			report_error("handle_command_shell_read(): handle_tun_tap_init(IFF_TAP): %s", strerror(errno));
			return_code = -2;
		}else{
			if(handle_send_dt_connection_ht_create(tmp_connection_node) == -1){
				report_error("handle_command_shell_read(): handle_send_dt_connection_ht_create(%lx): %s", (unsigned long) tmp_connection_node, strerror(errno));
				return(-1);
				goto CLEANUP;
			}
		}

#endif

		/*
			 }else if(!strcmp(command_node->completion_string, "")){
			 }else if(!strcmp(command_node->completion_string, "")){
		 */
}else{
	fprintf(stderr, "\r\nCommand shell error: \"%s\": Command not implemented. Ignoring.\n\r", command_node->completion_string);
	return_code = -2;
}

CLEANUP:
free_vector(command_vec);
return(return_code);
}
// XXX


/******************************************************************************
 *
 * handle_message_dt_tty()
 *
 * Inputs: None, but we will leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error.
 *
 * Purpose: Handle the broker case where a message has arrived from the 
 *   remote node, and it is data for the tty / shell.
 *
 ******************************************************************************/
int handle_message_dt_tty(){

	int retval;
	struct message_helper *new_message, *tmp_message;


	if(io->tty_write_head){
		retval = 0;
	} else {
		retval = write(io->local_out_fd, message->data, message->data_len);
	}

	if(retval == -1){
		if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK){
			report_error("handle_message_dt_tty(): write(%d, %lx, %d): %s", io->local_out_fd, (unsigned long) message->data, message->data_len, strerror(errno));
			return(-1);
		}
	}

	io->tty_io_read += retval;

	if(retval != message->data_len){
		new_message = message_helper_create(message->data + retval, message->data_len - retval, io->message_data_size);

		if(!new_message){
			report_error("handle_message_dt_tty(): message_helper_create(%lx, %d, %d): %s\n", \
					(unsigned long) message->data + retval, message->data_len - retval, io->message_data_size, strerror(errno));
			return(-1);
		}

		if(!io->tty_write_head){
			io->tty_write_head = new_message;
		}else{
			tmp_message = io->tty_write_head;
			while(tmp_message->next){
				tmp_message = tmp_message->next;
			}
			tmp_message->next = new_message;
		}
	}

	return(0);
}


/******************************************************************************
 *
 * handle_message_dt_winresize()
 *
 * Inputs: None, but we will leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error.
 *
 * Purpose: Handle the broker case where a message has arrived from the 
 *   remote node, and it is data relating to the window resize signal caught
 *   on the remote node.
 *
 ******************************************************************************/
int handle_message_dt_winresize(){

	int retval;

	if(message->data_len != sizeof(io->tty_winsize->ws_row) + sizeof(io->tty_winsize->ws_col)){
		report_error("handle_message_dt_winresize(): DT_WINRESIZE termios: not enough data!");
		return(-1);
	}

	io->tty_winsize->ws_row = ntohs(*((unsigned short *) message->data));
	io->tty_winsize->ws_col = ntohs(*((unsigned short *) (message->data + sizeof(unsigned short))));

	if((retval = ioctl(io->local_out_fd, TIOCSWINSZ, io->tty_winsize)) == -1){
		report_error("handle_message_dt_winresize(): ioctl(%d, %d, %lx): %s", io->local_out_fd, TIOCSWINSZ, (unsigned long) io->tty_winsize, strerror(errno));
		return(-1);
	}

	if((retval = kill(-(io->child_sid), SIGWINCH)) == -1){
		report_error("handle_message_dt_winresize(): kill(%d, SIGWINCH): %s", -(io->child_sid), strerror(errno));
		return(-1);
	}

	return(0);
}


// XXX
int handle_message_dt_proxy_ht_destroy(){

	struct proxy_node *cur_proxy_node;
	unsigned short header_errno;

	//	fprintf(stderr, "\rDEBUG: handle_message_dt_proxy_ht_destroy()\n");

	memcpy(&header_errno, message->data, sizeof(short));	
	header_errno = ntohs(header_errno);
	if((cur_proxy_node = proxy_node_find(message->header_origin, message->header_id))){
		if(verbose && header_errno){
			fprintf(stderr, "\rhandle_message_dt_proxy_ht_destroy(): Connection %s closed: %s\n", cur_proxy_node->rhost_rport, strerror(header_errno));
		}

		proxy_node_delete(cur_proxy_node);
	}

	return(0);
}

//XXX
int handle_message_dt_proxy_ht_create(){

	struct proxy_node *cur_proxy_node;

	//	fprintf(stderr, "\rDEBUG: handle_message_dt_proxy_ht_create()\n");

	if((cur_proxy_node = proxy_node_find(message->header_origin, message->header_id))){
		proxy_node_delete(cur_proxy_node);
	}

	if((cur_proxy_node = proxy_node_new(message->data, message->header_proxy_type)) == NULL){
		report_error("handle_message_dt_proxy_ht_create(): proxy_node_new(%lx, %d): %s", (unsigned long) message->data, message->header_proxy_type, strerror(errno));
		return(-1);
	}

	if(io->target){
		if(handle_send_dt_proxy_ht_report(cur_proxy_node) == -1){
			report_error("handle_message_dt_proxy_ht_create(): handle_send_dt_proxy_ht_report(%lx): %s", (unsigned long) cur_proxy_node, strerror(errno));
			return(-1);
		}
	}
	return(0);
}


// XXX
int handle_message_dt_proxy_ht_report(){

	struct proxy_node *cur_proxy_node;

	if((cur_proxy_node = proxy_node_create()) == NULL){
		report_error("proxy_node_new(): proxy_node_create(): %s", strerror(errno));
		return(-1);
	}

	cur_proxy_node->origin = message->header_origin;
	cur_proxy_node->id = message->header_id;
	cur_proxy_node->proxy_type = message->header_proxy_type;

	// free() called in proxy_node_destroy()
	if((cur_proxy_node->orig_request = (char *) calloc(message->data_len + 1, sizeof(char))) == NULL){
		report_error("handle_message_dt_proxy_ht_report(): calloc(%d, %d): %s", message->data_len + 1, (int) sizeof(char), strerror(errno));
		return(-1);
	}
	memcpy(cur_proxy_node->orig_request, message->data, message->data_len);

	return(0);
}


/******************************************************************************
 *
 * handle_message_dt_connection_ht_destroy()
 *
 * Inputs: None, but we will leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error.
 *
 * Purpose: Handle the broker case where a message has arrived from the 
 *   remote node, and it is a request to destroy an existing connection.
 *
 ******************************************************************************/
int handle_message_dt_connection_ht_destroy(){

	struct connection_node *cur_connection_node;
	unsigned short header_errno;

	//	fprintf(stderr, "\rDEBUG: handle_message_dt_connection_ht_destroy()\n");

	memcpy(&header_errno, message->data, sizeof(short));	
	header_errno = ntohs(header_errno);
	if((cur_connection_node = connection_node_find(message->header_origin, message->header_id))){
		if(verbose && header_errno){
			fprintf(stderr, "\rhandle_message_dt_connection_ht_destroy(): Connection %s closed: %s\n", cur_connection_node->rhost_rport, strerror(header_errno));
		}

		connection_node_delete(cur_connection_node);
	}

	return(0);
}


/******************************************************************************
 *
 * handle_message_dt_connection_ht_create()
 *
 * Inputs: None, but we will leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error. -2 on non-fatal error.
 *
 * Purpose: Handle the broker case where a message has arrived from the 
 *   remote node, and it is a request to create a new connection.
 *
 ******************************************************************************/
int handle_message_dt_connection_ht_create(){

	int retval;
	struct connection_node *cur_connection_node;

	//	fprintf(stderr, "\rDEBUG: handle_message_dt_connection_ht_create()\n");

	if((cur_connection_node = connection_node_find(message->header_origin, message->header_id))){
		connection_node_delete(cur_connection_node);
	}


	// Handle TUN / TAP case first.
	if(message->header_proxy_type == PROXY_TUN || message->header_proxy_type == PROXY_TAP){

		if((retval = handle_message_dt_connection_ht_create_tun_tap()) == -1){
			report_error("handle_message_dt_connection_ht_create(): handle_message_dt_connection_ht_create_tun_tap(): %s", strerror(errno));
		}

		if(retval == -2){
			if(verbose > 2){
				fprintf(stderr, "\rhandle_message_dt_connection_ht_create(): Unable to create tun/tap interface.\n");
			}
			if(handle_send_dt_connection_ht_destroy(message->header_origin, message->header_id, ENODEV) == -1){
				report_error("handle_message_dt_connection_ht_create(): handle_send_dt_connection_ht_destroy(%d, %d, ENODEV): %s", message->header_origin, message->header_id, strerror(errno));
				return(-1);
			}

		}
		return(retval);
	}

	// Remaining cases are a traditional proxy, either dynamic or static.

	if((cur_connection_node = connection_node_create()) == NULL){
		report_error("handle_message_dt_connection_ht_create(): connection_node_create(): %s", strerror(errno));
		return(-1);
	}

	cur_connection_node->origin = message->header_origin;
	cur_connection_node->id = message->header_id;
	cur_connection_node->proxy_type = message->header_proxy_type;

	// free() called in connection_node_delete().
	if((cur_connection_node->rhost_rport = (char *) calloc(message->data_len + 1, sizeof(char))) == NULL){
		report_error("handle_message_dt_connection_ht_create(): calloc(%d, %d): %s", message->data_len + 1, (int) sizeof(char), strerror(errno));
		return(-1);
	}

	memcpy(cur_connection_node->rhost_rport, message->data, message->data_len);

	errno = 0;
	if((cur_connection_node->fd = proxy_connect(cur_connection_node->rhost_rport)) < 0){

		if(cur_connection_node->fd == -1){
			if(verbose){
				report_error("handle_message_dt_connection_ht_create(): proxy_connect(\"%s\"): %s\n", cur_connection_node->rhost_rport, strerror(errno));
				return(-1);
			}
		}

		if(verbose > 2){
			fprintf(stderr, "\rproxy_connect(\"%s\"): Unable to connect: %s\n", cur_connection_node->rhost_rport, strerror(errno));
		}

		if(handle_send_dt_connection_ht_destroy(cur_connection_node->origin, cur_connection_node->id, errno) == -1){
			report_error("handle_message_dt_connection_ht_create(): handle_send_dt_connection_ht_destroy(%d, %d, errno): %s", cur_connection_node->origin, cur_connection_node->id, strerror(errno));
			return(-1);
		}
		connection_node_delete(cur_connection_node);

		return(0);
	}

	if(errno == EINPROGRESS){
		cur_connection_node->state = CON_EINPROGRESS;
	}else{
		cur_connection_node->state = CON_ACTIVE;
	}

	return(0);
}


/******************************************************************************
 *
 * handle_message_dt_connection_ht_create_tun_tap()
 *
 * Inputs: None, but we will leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error. -2 on non-fatal error.
 *
 * Purpose: Handle the broker case where a message has arrived from the 
 *   remote node, and it is a request to create a new tun/tap connection.
 *
 ******************************************************************************/
int handle_message_dt_connection_ht_create_tun_tap(){

	unsigned short origin = message->header_origin;
	unsigned short id = message->header_id;

#ifdef FREEBSD
	// ENOSYS : It's not clear to me if ENOSYS is reserved for the OS or if this is a reasonable use case. 
	handle_send_dt_connection_ht_destroy(origin, id, ENOSYS);
	report_error("handle_message_dt_connection_ht_create_tun_tap(): revsh does not currently support tun/tap devices on FreeBSD.");
	return(-2);
#else

	struct connection_node *cur_connection_node = NULL;

	//	fprintf(stderr, "\rDEBUG: handle_message_dt_connection_ht_create_tun_tap()\n");

	if(message->header_proxy_type == PROXY_TUN){
		if((cur_connection_node = handle_tun_tap_init(IFF_TUN)) == NULL){
			report_error("handle_message_dt_connection_ht_create_tun_tap(): handle_tun_tap_init(IFF_TUN): %s", strerror(errno));
			if(handle_send_dt_connection_ht_destroy(origin, id, errno) == -1){
				report_error("handle_message_dt_connection_ht_create_tun_tap(): handle_send_dt_connection_ht_destroy(%d, %d, errno): %s", origin, id, strerror(errno));
				return(-1);
			}
			return(-2);
		}

	}else if(message->header_proxy_type == PROXY_TAP){
		if((cur_connection_node = handle_tun_tap_init(IFF_TAP)) == NULL){
			report_error("handle_message_dt_connection_ht_create_tun_tap(): handle_tun_tap_init(IFF_TAP): %s", strerror(errno));
			if(handle_send_dt_connection_ht_destroy(origin, id, errno) == -1){
				report_error("handle_message_dt_connection_ht_create_tun_tap(): handle_send_dt_connection_ht_destroy(%d, %d, errno): %s", origin, id, strerror(errno));
				return(-1);
			}
			return(-2);
		}
	}

	if(cur_connection_node){
		cur_connection_node->origin = message->header_origin;
		cur_connection_node->id = message->header_id;

		cur_connection_node->state = CON_ACTIVE;
	}

	return(0);
#endif
}


/******************************************************************************
 *
 * handle_connection_activate()
 *
 * Inputs: A pointer to an active connection node.
 *    We will also leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error.
 *
 * Purpose: Handle the broker case where a local connection is ready to be
 *   set into an active state.
 *
 ******************************************************************************/
int handle_connection_activate(struct connection_node *cur_connection_node){

	int optval;
	socklen_t optlen;

	//	fprintf(stderr, "\rDEBUG: handle_connection_activate()\n");

	optlen = sizeof(optval);
	if(getsockopt(cur_connection_node->fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1){

		if(handle_send_dt_connection_ht_destroy(cur_connection_node->origin, cur_connection_node->id, errno) == -1){
			report_error("handle_connection_activate(): handle_send_dt_connection_ht_destroy(%d, %d, errno): %s", cur_connection_node->origin, cur_connection_node->id, strerror(errno));
			return(-1);
		}

		connection_node_delete(cur_connection_node);
		return(0);
	}

	if(optval != 0){
		if(verbose > 2){
			fprintf(stderr, "\rConnection failed: %s, %s\n", cur_connection_node->rhost_rport, strerror(optval));
		}

		if(handle_send_dt_connection_ht_destroy(cur_connection_node->origin, cur_connection_node->id, 0) == -1){
			report_error("handle_connection_activate(): handle_send_dt_connection_ht_destroy(%d, %d, 0): %s", cur_connection_node->origin, cur_connection_node->id, strerror(errno));
			return(-1);
		}

		connection_node_delete(cur_connection_node);
		return(0);
	}

	cur_connection_node->state = CON_ACTIVE;

	return(0);
}


int handle_message_dt_connection_ht_active_dormant(){
	struct connection_node *cur_connection_node;

	//	fprintf(stderr, "\rDEBUG: handle_message_dt_connection_ht_active_dormant()\n");

	if((cur_connection_node = connection_node_find(message->header_origin, message->header_id)) == NULL){

		if(handle_send_dt_connection_ht_destroy(message->header_origin, message->header_id, 0) == -1){
			report_error("handle_message_dt_connection(): handle_send_dt_connection_ht_destroy(%d, %d, 0): %s", message->header_origin, message->header_id, strerror(errno));
			return(-1);
		}
		return(-2);
	}

	if(message->header_type == DT_CONNECTION_HT_DORMANT){
		cur_connection_node->state = CON_DORMANT;
		return(0);
	}

	if(message->header_type == DT_CONNECTION_HT_ACTIVE){
		cur_connection_node->state = CON_ACTIVE;
		return(0);
	}

	if(handle_send_dt_connection_ht_destroy(message->header_origin, message->header_id, 0) == -1){
		report_error("handle_message_dt_connection(): handle_send_dt_connection_ht_destroy(%d, %d, 0): %s", message->header_origin, message->header_id, strerror(errno));
		return(-1);
	}
	return(-2);
}

/******************************************************************************
 *
 * handle_message_dt_connection()
 *
 * Inputs: None, but we will leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error. -2 on non-fatal error.
 *
 * Purpose: Handle the broker case where a message has arrived from the 
 *   remote node, and it is a request to handle an existing connection.
 *
 ******************************************************************************/
int handle_message_dt_connection_ht_data(){

	int retval;
	struct message_helper *new_message, *tmp_message;
	struct connection_node *cur_connection_node;
	int count, errno;

	//	fprintf(stderr, "\rDEBUG: handle_message_dt_connection()\n");

	if((cur_connection_node = connection_node_find(message->header_origin, message->header_id)) == NULL){

		if(handle_send_dt_connection_ht_destroy(message->header_origin, message->header_id, 0) == -1){
			report_error("handle_message_dt_connection(): handle_send_dt_connection_ht_destroy(%d, %d, 0): %s", message->header_origin, message->header_id, strerror(errno));
			return(-1);
		}
		return(-2);
	}

	if(cur_connection_node->write_head){
		retval = 0;
	} else {
		retval = write(cur_connection_node->fd, message->data, message->data_len);
	}

	if(retval == -1){
		if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK){
			report_error("handle_message_dt_connection(): write(%d, %lx, %d): %s", \
					cur_connection_node->fd, (unsigned long) message->data, message->data_len, strerror(errno));

			if(handle_send_dt_connection_ht_destroy(cur_connection_node->origin, cur_connection_node->id, 0) == -1){
				report_error("handle_message_dt_connection(): handle_send_dt_connection_ht_destroy(%d, %d, 0): %s", cur_connection_node->origin, cur_connection_node->id, strerror(errno));
				return(-1);
			}
			connection_node_delete(cur_connection_node);
			return(-2);
		}
		retval = 0;
	}

	cur_connection_node->io_read = retval;

	if(retval != message->data_len){
		new_message = message_helper_create(message->data + retval, message->data_len - retval, io->message_data_size);

		if(!new_message){
			report_error("handle_message_dt_connection(): message_helper_create(%lx, %d, %d): %s", \
					(unsigned long) message->data + retval, message->data_len - retval, io->message_data_size, strerror(errno));
			return(-1);
		}

		if(!cur_connection_node->write_head){
			cur_connection_node->write_head = new_message;
		}else{

			count = 1;
			tmp_message = cur_connection_node->write_head;
			while(tmp_message->next){
				tmp_message = tmp_message->next;
				count++;
			}
			tmp_message->next = new_message;

			if(count == MESSAGE_DEPTH_MAX){
				message->data_type = DT_CONNECTION;
				message->header_type = DT_CONNECTION_HT_DORMANT;
				message->header_origin = io->target;
				message->header_id = cur_connection_node->fd;
				message->data_len = 0;

				if((retval = message_push()) == -1){
					report_error("handle_message_dt_connection(): message_push(): %s", strerror(errno));
					return(-1);
				}
			}
		}
	}

	return(0);
}


/******************************************************************************
 *
 * handle_proxy_read()
 *
 * Inputs: A pointer to a proxy listener.
 *    We will also leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error.
 *
 * Purpose: Handle the broker case where a local proxy listener is ready to 
 *   be read. This will likely result in the creation of a new connection.
 *
 ******************************************************************************/
int handle_proxy_read(struct proxy_node *cur_proxy_node){

	int count;
	struct connection_node *cur_connection_node;

	//	fprintf(stderr, "\rDEBUG: handle_proxy_read()\n");

	/* Create a new connection object. */
	if((cur_connection_node = connection_node_create()) == NULL){
		report_error("handle_proxy_read(): connection_node_create(): %s", strerror(errno));
		return(-1);
	}

	if((cur_connection_node->fd = accept(cur_proxy_node->fd, NULL, NULL)) == -1){
		report_error("handle_proxy_read(): accept(%d, NULL, NULL): %s", cur_proxy_node->fd, strerror(errno));
		return(-1);
	}
	fcntl(cur_connection_node->fd, F_SETFL, O_NONBLOCK);

	cur_connection_node->origin = io->target;
	cur_connection_node->id = cur_connection_node->fd;

	if(cur_proxy_node->proxy_type == PROXY_DYNAMIC){
		// PROXY_DYNAMIC case goes here.

		// free() called in connection_node_delete().
		if((cur_connection_node->buffer_head = (char *) calloc(SOCKS_REQ_MAX, sizeof(char))) == NULL){
			report_error("handle_proxy_read(): calloc(%d, %d): %s\r", SOCKS_REQ_MAX, (int) sizeof(char), strerror(errno));
			return(-1);
		}

		cur_connection_node->buffer_tail = cur_connection_node->buffer_head;
		cur_connection_node->buffer_ptr = cur_connection_node->buffer_head;
		cur_connection_node->buffer_size = SOCKS_REQ_MAX;
		cur_connection_node->proxy_type = PROXY_DYNAMIC;

		cur_connection_node->state = CON_SOCKS_INIT;

	}else if(cur_proxy_node->proxy_type == PROXY_STATIC){

		count = strlen(cur_proxy_node->rhost_rport);
		// free() called in connection_node_delete().
		if((cur_connection_node->rhost_rport = (char *) calloc(count + 1, sizeof(char))) == NULL){
			report_error("handle_proxy_read(): calloc(%d, %d): %s", count + 1, (int) sizeof(char), strerror(errno));
			return(-1);
		}
		memcpy(cur_connection_node->rhost_rport, cur_proxy_node->rhost_rport, count);
		cur_connection_node->proxy_type = PROXY_STATIC;

		cur_connection_node->state = CON_ACTIVE;
		if(handle_send_dt_connection_ht_create(cur_connection_node) == -1){
			report_error("handle_proxy_read(): handle_send_dt_connection_ht_create(%lx): %s", (unsigned long) cur_connection_node, strerror(errno));
			return(-1);
		}
	}

	return(0);
}


/******************************************************************************
 *
 * handle_connection_write()
 *
 * Inputs: A pointer to an active connection node. 
 *    We will also leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error. -2 on non-fatal error.
 *
 * Purpose: Handle the broker case where a local connection has a write queue
 *   backed up and the related fd is ready for writting. 
 *
 ******************************************************************************/
int handle_connection_write(struct connection_node *cur_connection_node){

	int retval;
	struct message_helper *tmp_message;

	//	fprintf(stderr, "\rDEBUG: handle_connection_write()\n");


	while(cur_connection_node->write_head){

		tmp_message = cur_connection_node->write_head;

		retval = write(cur_connection_node->fd, tmp_message->data, tmp_message->data_len);

		if(retval == -1){
			if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK){
				report_error("handle_connection_write(): write(%d, %lx, %d): %s", \
						io->local_out_fd, (unsigned long) tmp_message->data, tmp_message->data_len, strerror(errno));

				if(handle_send_dt_connection_ht_destroy(cur_connection_node->origin, cur_connection_node->id, 0) == -1){
					report_error("handle_connection_write(): handle_send_dt_connection_ht_destroy(%d, %d, 0): %s", cur_connection_node->origin, cur_connection_node->id, strerror(errno));
					return(-1);
				}
				connection_node_delete(cur_connection_node);

				return(-2);
			}
		}

		if(retval != tmp_message->data_len){
			tmp_message->data_len -= retval;
			memmove(tmp_message->data, tmp_message->data + retval, tmp_message->data_len);
			return(0);
		}

		cur_connection_node->write_head = tmp_message->next;
		message_helper_destroy(tmp_message);

		if(!cur_connection_node->write_head){
			message->data_type = DT_CONNECTION;
			message->header_type = DT_CONNECTION_HT_ACTIVE;
			message->header_origin = io->target;
			message->header_id = cur_connection_node->fd;
			message->data_len = 0;

			if((retval = message_push()) == -1){
				report_error("handle_connection_write(): message_push(): %s", strerror(errno));
				return(-1);
			}
		}
	}

	return(0);
}


/******************************************************************************
 *
 * handle_connection_read()
 *
 * Inputs: A pointer to an active connection node. 
 *    We will also leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error. -2 on non-fatal error.
 *
 * Purpose: Handle the broker case where a local connection is read to be read.
 *
 ******************************************************************************/
int handle_connection_read(struct connection_node *cur_connection_node){

	int retval;

	//	fprintf(stderr, "\rDEBUG: handle_connection_read()\n");

	message->data_type = DT_CONNECTION;
	message->header_type = DT_CONNECTION_HT_DATA;
	message->header_origin = cur_connection_node->origin;
	message->header_id = cur_connection_node->id;

	errno = 0;
	if((retval = read(cur_connection_node->fd, message->data, io->message_data_size)) < 1){
		if((verbose > 2) && retval){
			fprintf(stderr, "\rhandle_connection_read(): Connection %s closed: %s\n", cur_connection_node->rhost_rport, strerror(errno));
		}

		if(handle_send_dt_connection_ht_destroy(cur_connection_node->origin, cur_connection_node->id, errno) == -1){
			report_error("handle_connection_read(): handle_send_dt_connection_ht_destroy(%d, %d, errno): %s", cur_connection_node->origin, cur_connection_node->id, strerror(errno));
			return(-1);
		}
		connection_node_delete(cur_connection_node);
		return(-2);

	}

	cur_connection_node->io_written = retval;
	message->data_len = retval;

	if((retval = message_push()) == -1){
		report_error("handle_connection_read(): message_push(): %s", strerror(errno));
		return(-1);
	}

	return(0);
}


/******************************************************************************
 *
 * handle_connection_socks_init()
 *
 * Inputs: A pointer to an active connection node. 
 *    We will also leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error. -2 on non-fatal error.
 *
 * Purpose: Handle the broker case where a local connection is read to be
 *   to be read, and it's a proxy connection that needs to handle its
 *   handshake.
 *
 * Note: Long story short, I hate Socks 5.
 *
 ******************************************************************************/
int handle_connection_socks_init(struct connection_node *cur_connection_node){

	int retval;
	char *reply_buff = NULL;
	int reply_buff_len = 0;
	int new_state;

	//	fprintf(stderr, "\rDEBUG: handle_connection_socks_init()\n");


	if((retval = read(cur_connection_node->fd, cur_connection_node->buffer_tail, cur_connection_node->buffer_size - (cur_connection_node->buffer_tail - cur_connection_node->buffer_head) - 1)) < 1){

		// Sorry if this syntax feels awkward. The case defined below is the re-call of the handle_connection_socks_init() by the handle_connection_socks_init() 
		// when CON_SOCKS_V5_AUTH has occured and the buffer may already be ready for processing. It will generally fail the read and want to drop
		// though below for processing. We are if()'ing on the negation of that case to handle when it's just a normal good ol'fashioned read() 
		// failure.
		if( !( \
					(cur_connection_node->state == CON_SOCKS_V5_AUTH) && \
					(cur_connection_node->buffer_tail - cur_connection_node->buffer_ptr) && \
					(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				 )){

			if(retval && (verbose > 2)){
				fprintf(stderr, "\rConnection %s closed: %s\n", cur_connection_node->rhost_rport, strerror(errno));
			}

			if(handle_send_dt_connection_ht_destroy(cur_connection_node->origin, cur_connection_node->id, 0) == -1){
				report_error("handle_connection_socks_init(): handle_send_dt_connection_ht_destroy(%d, %d, 0): %s", cur_connection_node->origin, cur_connection_node->id, strerror(errno));
				return(-1);
			}
			connection_node_delete(cur_connection_node);
			return(-2);
		}
	}

	cur_connection_node->buffer_tail = cur_connection_node->buffer_tail + retval;

	if((new_state = parse_socks_request(cur_connection_node)) == -1){
		report_error("handle_connection_socks_init(): parse_sock_request(%lx): Malformed SOCKS request.", (unsigned long) cur_connection_node);
		if(handle_send_dt_connection_ht_destroy(cur_connection_node->origin, cur_connection_node->id, 0) == -1){
			report_error("handle_connection_socks_init(): handle_send_dt_connection_ht_destroy(%d, %d, 0): %s", cur_connection_node->origin, cur_connection_node->id, strerror(errno));
			return(-1);
		}
		connection_node_delete(cur_connection_node);
		return(-2);
	}

	if(new_state == CON_SOCKS_INIT){

		// Buffer is full, but still no complete socks request?!
		if(!(cur_connection_node->buffer_size - (cur_connection_node->buffer_tail - cur_connection_node->buffer_head) - 1)){
			report_error("handle_connection_socks_init(): parse_sock_request(%lx): Malformed SOCKS request.", (unsigned long) cur_connection_node);
			if(handle_send_dt_connection_ht_destroy(cur_connection_node->origin, cur_connection_node->id, 0) == -1){
				report_error("handle_connection_socks_init(): handle_send_dt_connection_ht_destroy(%d, %d, 0): %s", cur_connection_node->origin, cur_connection_node->id, strerror(errno));
				return(-1);
			}
			connection_node_delete(cur_connection_node);
			return(-2);
		}

		return(0);
	}

	if(new_state == CON_SOCKS_V5_AUTH){
		reply_buff = SOCKS_V5_AUTH_REPLY;
		reply_buff_len = SOCKS_V5_AUTH_REPLY_LEN;
	}else if(new_state == CON_ACTIVE){
		if(cur_connection_node->state == CON_SOCKS_INIT){
			reply_buff = SOCKS_V4_REPLY;
			reply_buff_len = SOCKS_V4_REPLY_LEN;
		}else if(cur_connection_node->state == CON_SOCKS_V5_AUTH){
			reply_buff = SOCKS_V5_REPLY;
			reply_buff_len = SOCKS_V5_REPLY_LEN;
		}
	}

	retval = write(cur_connection_node->fd, reply_buff, reply_buff_len);

	if(retval == -1){
		report_error("handle_connection_socks_init(): write(%d, %lx, %d): %s", cur_connection_node->fd, (unsigned long) reply_buff, reply_buff_len, strerror(errno));
		return(-1);
	}

	if(retval != reply_buff_len){
		report_error("handle_connection_socks_init(): write(%d, %lx, %d): Unable to send SOCKS reply.", cur_connection_node->fd, (unsigned long) reply_buff, reply_buff_len);
		if(handle_send_dt_connection_ht_destroy(cur_connection_node->origin, cur_connection_node->id, 0) == -1){
			report_error("handle_connection_socks_init(): handle_send_dt_connection_ht_destroy(%d, %d, 0): %s", cur_connection_node->origin, cur_connection_node->id, strerror(errno));
			return(-1);
		}
		connection_node_delete(cur_connection_node);
	}

	cur_connection_node->state = new_state;

	// Handle the case where we have a rude client that doesn't wait for data and just fills our buffer with both halves of the 
	// socks 5 request in one read.
	if((cur_connection_node->state == CON_SOCKS_V5_AUTH) && (cur_connection_node->buffer_tail - cur_connection_node->buffer_ptr)){
		if((retval = handle_connection_socks_init(cur_connection_node)) == -1){
			report_error("broker(): handle_connection_socks_init(%lx): %s", (unsigned long) cur_connection_node, strerror(errno));
			return(-1);
		}
		return(retval);
	}

	if(cur_connection_node->state == CON_ACTIVE){

		if(handle_send_dt_connection_ht_create(cur_connection_node) == -1){
			report_error("handle_connection_socks_init(): handle_send_dt_connection_ht_create(%lx): %s", (unsigned long) cur_connection_node, strerror(errno));
			return(-1);
		}

		if(cur_connection_node->buffer_ptr != cur_connection_node->buffer_tail){
			message->data_type = DT_CONNECTION;
			message->header_type = DT_CONNECTION_HT_DATA;
			message->header_origin = cur_connection_node->origin;
			message->header_id = cur_connection_node->id;

			memcpy(message->data, cur_connection_node->buffer_ptr, cur_connection_node->buffer_tail - cur_connection_node->buffer_ptr);
			message->data_len = cur_connection_node->buffer_tail - cur_connection_node->buffer_ptr;

			if((retval = message_push()) == -1){
				report_error("handle_connection_socks_init(): message_push(): %s", strerror(errno));
				return(-1);
			}
		}

		cur_connection_node->io_written = retval;
	}

	return(0);
}

// XXX
int handle_send_dt_proxy_ht_destroy(unsigned short origin, unsigned short id, unsigned short header_errno){
	int retval;

	//	fprintf(stderr, "\rDEBUG: handle_send_dt_proxy_ht_destroy()\n");

	message->data_type = DT_PROXY;
	message->header_type = DT_PROXY_HT_DESTROY;
	message->header_origin = origin;
	message->header_id = id;

	if(header_errno){
		header_errno = htons(header_errno);
		message->data_len = sizeof(short);
		memcpy(message->data, &header_errno, message->data_len);
	}else{
		message->data_len = 0;
	}

	if((retval = message_push()) == -1){
		report_error("handle_send_dt_proxy_ht_destroy(): message_push(): %s", strerror(errno));
		return(-1);
	}

	return(0);
}

// XXX
int handle_send_dt_proxy_ht_create(char *proxy_string, int proxy_type){

	int count, retval;

	//	fprintf(stderr, "\rDEBUG: handle_send_dt_proxy_ht_create()\n");

	message->data_type = DT_PROXY;
	message->header_type = DT_PROXY_HT_CREATE;
	message->header_origin = 0;
	message->header_id = 0;
	message->header_proxy_type = proxy_type;

	memset(message->data, 0, io->message_data_size);

	count = strlen(proxy_string);
	if(count > io->message_data_size - 1){
		report_error("handle_proxy_read(): Proxy request string too long!\n");
		return(-2);
	}
	memcpy(message->data, proxy_string, count);
	message->data_len = count;

	if((retval = message_push()) == -1){
		report_error("handle_proxy_read(): message_push(): %s", strerror(errno));
		return(-1);
	}

	return(0);
}

// XXX
int handle_send_dt_proxy_ht_report(struct proxy_node *cur_proxy_node){
	int retval;

	message->data_type = DT_PROXY;
	message->header_type = DT_PROXY_HT_REPORT;
	message->header_origin = cur_proxy_node->origin;
	message->header_id = cur_proxy_node->id;
	message->header_proxy_type = cur_proxy_node->proxy_type;

	retval = strlen(cur_proxy_node->orig_request);
	message->data_len = retval > io->message_data_size ? io->message_data_size : retval;
	memcpy(message->data, cur_proxy_node->orig_request, message->data_len);

	if((retval = message_push()) == -1){
		report_error("handle_send_dt_proxy_ht_report(): message_push(): %s", strerror(errno));
		return(-1);
	}

	return(0);
}


/******************************************************************************
 *
 * handle_send_dt_connection_ht_destroy()
 *
 * Inputs: The origin and id tuple that identify the related connection.
 *   The errno related to the need for destruction.
 *   We will also leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error.
 *
 * Purpose: Handle the broker case where we need to notify the remote node 
 *   that a connection is no longer valid and needs to be destroyed.
 *
 ******************************************************************************/
int handle_send_dt_connection_ht_destroy(unsigned short origin, unsigned short id, unsigned short header_errno){

	int retval;

	//	fprintf(stderr, "\rDEBUG: handle_send_dt_connection_ht_destroy()\n");

	message->data_type = DT_CONNECTION;
	message->header_type = DT_CONNECTION_HT_DESTROY;
	message->header_origin = origin;
	message->header_id = id;

	if(header_errno){
		header_errno = htons(header_errno);
		message->data_len = sizeof(short);
		memcpy(message->data, &header_errno, message->data_len);
	}else{
		message->data_len = 0;
	}

	if((retval = message_push()) == -1){
		report_error("handle_send_dt_connection_ht_destroy(): message_push(): %s", strerror(errno));
		return(-1);
	}

	return(0);
}


/******************************************************************************
 *
 * handle_send_dt_connection_ht_create()
 *
 * Inputs: A pointer to an active connection node. 
 *   We will also leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error.
 *
 * Purpose: Handle the broker case where we need to notify the remote node 
 *   that a connection needs to be created.
 *
 ******************************************************************************/
int handle_send_dt_connection_ht_create(struct connection_node *cur_connection_node){

	int count, retval;

	//	fprintf(stderr, "\rDEBUG: handle_send_dt_connection_ht_create()\n");

	message->data_type = DT_CONNECTION;
	message->header_type = DT_CONNECTION_HT_CREATE;
	message->header_origin = cur_connection_node->origin;
	message->header_id = cur_connection_node->id;
	message->header_proxy_type = cur_connection_node->proxy_type;

	memset(message->data, 0, io->message_data_size);
	count = strlen(cur_connection_node->rhost_rport);

	memcpy(message->data, cur_connection_node->rhost_rport, count);
	message->data_len = count;

	if((retval = message_push()) == -1){
		report_error("handle_connection_read(): message_push(): %s", strerror(errno));
		return(-1);
	}

	return(0);
}


/******************************************************************************
 *
 * handle_send_dt_nop()
 *
 * Inputs: None, but we will leverage the global io struct.
 * Outputs: 0 for success. -1 on fatal error.
 *
 * Purpose: Handle the broker case where we need to notify the remote node 
 *   that...  well...  nothing.
 *
 * This reminds me of the BSD man page for /bin/true, which read:
 *   "Do nothing, successfully."
 * As opposed to the BSD man page for /bin/false, which read:
 *   "Do nothing, unsuccessfully."
 *
 ******************************************************************************/
int handle_send_dt_nop(){

	message->data_type = DT_NOP;
	message->data_len = 0;
	if(message_push() == -1){
		report_error("handle_send_dt_nop(): message_push(): %s", strerror(errno));
		return(-1);
	}

	return(0);
}


/******************************************************************************
 *
 * handle_tun_tap_init()
 *
 * Inputs: The flag defining if this is a TUN request or a TAP request.
 *   We will also leverage the global io struct.
 * Outputs: A pointer to a new connection node representing the TUN/TAP device.
 *
 * Purpose: Handle the broker case where we want to setup tun/tap support.
 *
 ******************************************************************************/
struct connection_node *handle_tun_tap_init(int ifr_flag){

#ifdef FREEBSD
	report_error("handle_tun_tap_init(): revsh does not currently support tun/tap devices on FreeBSD.");
	return(NULL);
#else

	int count;
	struct ifreq ifr;
	char *ifr_flag_name;

	struct connection_node *cur_connection_node;

	int tmp_sock = 0;

	//	fprintf(stderr, "\rDEBUG: handle_tun_tap_init()\n");


	if(ifr_flag == IFF_TUN){
		ifr_flag_name = "TUN";
	}else if(ifr_flag == IFF_TAP){
		ifr_flag_name = "TAP";
	}else{
		report_error("handle_tun_tap_init(): Unknown ifr_flag: %d", ifr_flag);
		return(NULL);
	}

	if((cur_connection_node = connection_node_create()) == NULL){
		report_error("handle_tun_tap_init(): connection_node_create(): %s", strerror(errno));
		return(NULL);
	}

	if((cur_connection_node->fd = open(DEV_NET_TUN, O_RDWR)) == -1){
		connection_node_delete(cur_connection_node);

		report_error("handle_tun_tap_init(): open(%s, O_RDWR): %s", DEV_NET_TUN, strerror(errno));
		return(NULL);
	}
	cur_connection_node->origin = io->target;
	cur_connection_node->id = cur_connection_node->fd;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = ifr_flag | IFF_NO_PI;

	if(ioctl(cur_connection_node->fd, TUNSETIFF, (void *) &ifr) == -1){
		report_error("handle_tun_tap_init(): ioctl(%d, TUNSETIFF, %lx): %s: %s", cur_connection_node->fd, (unsigned long) ((void *) &ifr), ifr_flag_name, strerror(errno));

		if(errno == EPERM){
			fprintf(stderr, "\rOnly root can initialize %s devices. Skipping...\n", ifr_flag_name);
		}

		connection_node_delete(cur_connection_node);
		return(NULL);
	}

	count = strlen(ifr.ifr_name);
	// free() called in connection_node_delete().
	if((cur_connection_node->rhost_rport = (char *) calloc(count + 1, sizeof(char))) == NULL){
		report_error("handle_tun_tap_init(): calloc(%d, %d): %s", count + 1, (int) sizeof(char), strerror(errno));
		connection_node_delete(cur_connection_node);
		return(NULL);
	}
	memcpy(cur_connection_node->rhost_rport, ifr.ifr_name, count);
	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, cur_connection_node->rhost_rport, count);

	if(ifr_flag == IFF_TUN){
		cur_connection_node->proxy_type = PROXY_TUN;
	}else if(ifr_flag == IFF_TAP){
		cur_connection_node->proxy_type = PROXY_TAP;
	}

	/*
		 Really Linux?! Are you fucking kidding me?? I can't perform the MTU set on the tun/tap fd directly??
		 I have to open a *random unrelated socket* just to pass it's fd to the MTU ioctl() call, only to close it out 
		 immediately after?! Holy shit that's janky!!
	 */
	if((tmp_sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
		report_error("handle_tun_tap_init(): socket(AF_LOCAL, SOCK_DGRAM, 0): %s", strerror(errno));
		connection_node_delete(cur_connection_node);
		return(NULL);
	}

	if(ioctl(tmp_sock, SIOCGIFMTU, (void *) &ifr) == -1){
		report_error("handle_tun_tap_init(): ioctl(%d, SIOCGIFMTU, %lx): %s", cur_connection_node->fd, (unsigned long) &ifr, strerror(errno));
		connection_node_delete(cur_connection_node);
		return(NULL);
	}

	/*
		 If the mtu on the tun / tap device is larger than the message data buffer, reduce it.
		 This ensures the we can always fit a full frame / packet inside one message.
		 Given that the default is that the message data buffer is probably a page of memory, and that is probably 4k in size, this will 
		 probably never be needed.
	 */
	if(ifr.ifr_mtu > io->message_data_size){

		ifr.ifr_mtu = io->message_data_size;
		if(ioctl(tmp_sock, SIOCSIFMTU, (void *) &ifr) == -1){
			report_error("handle_tun_tap_init(): ioctl(%d, SIOCSIFMTU, %lx): %s", cur_connection_node->fd, (unsigned long) &ifr, strerror(errno));
			connection_node_delete(cur_connection_node);
			return(NULL);
		}
	}

	close(tmp_sock);
	fcntl(cur_connection_node->fd, F_SETFL, O_NONBLOCK);

	cur_connection_node->state = CON_ACTIVE;

	return(cur_connection_node);
#endif
}

