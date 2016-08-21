/*
 *	In the beginning there was input and output, and it was good.
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

int handle_signal_sigwinch(){

	int retval;
	struct message_helper *message;

	message = &io->message;

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

// -2 -> EOF. Fatal non-error condition.
int handle_local_read(){

	int retval;
	struct message_helper *message = &(io->message);

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

		message->data_len = retval;

		if(!message->data_len){
			return(-2);
		}else{
			if((retval = message_push()) == -1){
				report_error("handle_local_read(): message_push(): %s", strerror(errno));
				return(-1);
			}
		}
	}

	return(0);
}


int handle_message_dt_tty(){

	int retval;
	struct message_helper *message = &(io->message);
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

int handle_message_dt_winresize(){
	int retval;
	struct message_helper *message = &(io->message);

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


int handle_message_dt_proxy_ht_destroy(){
	struct connection_node *cur_connection_node;
	struct message_helper *message = &(io->message);
	unsigned short header_errno;
	
	memcpy(&header_errno, message->data, sizeof(short));	
	header_errno = ntohs(header_errno);
	if((cur_connection_node = connection_node_find(message->header_origin, message->header_id))){
		if(verbose && header_errno){
			fprintf(stderr, "\rhandle_message_dt_proxy_ht_destroy(): Connection %s closed: %s\n", cur_connection_node->rhost_rport, strerror(header_errno));
		}
	}

	connection_node_delete(cur_connection_node);

	return(0);
}


int handle_message_dt_proxy_ht_create(){
	int retval;
	struct message_helper *message = &(io->message);

	struct connection_node *tmp_connection_node;
	int count, offset, errno;

	unsigned short header_errno;


	if((tmp_connection_node = connection_node_find(message->header_origin, message->header_id))){
		connection_node_delete(tmp_connection_node);
	}

	if(message->header_proxy_type == PROXY_TUN){
		if((tmp_connection_node = handle_tun_tap_init(IFF_TUN)) == NULL){
			report_error("broker(): handle_tun_tap_init(%d): %s", IFF_TUN, strerror(errno));
			return(-2);
		}

		tmp_connection_node->origin = message->header_origin;
		tmp_connection_node->id = message->header_id;

	}else if(message->header_proxy_type == PROXY_TAP){
		if((tmp_connection_node = handle_tun_tap_init(IFF_TAP)) == NULL){
			report_error("broker(): handle_tun_tap_init(%d): %s", IFF_TAP, strerror(errno));
			return(-2);
		}

		tmp_connection_node->origin = message->header_origin;
		tmp_connection_node->id = message->header_id;

	}else{

		if((tmp_connection_node = connection_node_create()) == NULL){
			report_error("handle_message_dt_proxy_ht_create(): connection_node_create(): %s", strerror(errno));
			return(-1);
		}

		tmp_connection_node->origin = message->header_origin;
		tmp_connection_node->id = message->header_id;
		tmp_connection_node->proxy_type = message->header_proxy_type;
	
		count = message->data_len;
		offset = 0;

		// the +/- 2 below is to handle the leading two chars which are the ver and the cmd of the proxy request.
		if(tmp_connection_node->proxy_type == PROXY_DYNAMIC){
			offset = 2;
			tmp_connection_node->ver = *(message->data);
			tmp_connection_node->cmd = *(message->data + 1);
			count -= offset;
		}

		if((tmp_connection_node->rhost_rport = (char *) calloc(count + 1, sizeof(char))) == NULL){
			report_error("handle_message_dt_proxy_ht_create(): calloc(%d, %d): %s", count + 1, (int) sizeof(char), strerror(errno));
			return(-1);
		}

		memcpy(tmp_connection_node->rhost_rport, message->data + offset, count);

		tmp_connection_node->origin = message->header_origin;
		tmp_connection_node->id = message->header_id;

		errno = 0;
		if((tmp_connection_node->fd = proxy_connect(tmp_connection_node->rhost_rport)) == -1){

			if(verbose){
				fprintf(stderr, "\rproxy_connect(\"%s\"): Unable to connect: %s\n", tmp_connection_node->rhost_rport, strerror(errno));
			}

			message->data_type = DT_PROXY;
			message->header_type = DT_PROXY_HT_DESTROY;
			message->header_origin = tmp_connection_node->origin;
			message->header_id = tmp_connection_node->id;
			header_errno = htons(errno);
			message->data_len = sizeof(short);
			memcpy(message->data, &header_errno, message->data_len);

			if((retval = message_push()) == -1){
				report_error("handle_message_dt_proxy_ht_create(): message_push(): %s", strerror(errno));
				return(-1);
			}
			connection_node_delete(tmp_connection_node);

			return(0);
		}

		if(errno == EINPROGRESS){
			tmp_connection_node->state = CON_EINPROGRESS;
		}
	}

	if(tmp_connection_node->state != EINPROGRESS){
		handle_con_activate(tmp_connection_node);
	}

	return(0);
}


int handle_con_activate(struct connection_node *cur_connection_node){
	int retval, optval;
	socklen_t optlen;
	struct message_helper *message = &(io->message);

	unsigned short header_errno;


	if(cur_connection_node->state == CON_EINPROGRESS){

		optlen = sizeof(optval);
		if(getsockopt(cur_connection_node->fd, SOL_SOCKET, SO_ERROR, &optval, &optlen) == -1){
			message->data_type = DT_PROXY;
			message->header_type = DT_PROXY_HT_DESTROY;
			message->header_origin = cur_connection_node->origin;
			message->header_id = cur_connection_node->id;
			message->data_len = 0;

			if((retval = message_push()) == -1){
				report_error("handle_message_dt_proxy_ht_activate(): message_push(): %s", strerror(errno));
				return(-1);
			}
			connection_node_delete(cur_connection_node);
			return(0);
		}

		if(optval != 0){
			if(verbose){
				fprintf(stderr, "\rConnection failed: %s, %s\n", cur_connection_node->rhost_rport, strerror(optval));
			}
			message->data_type = DT_PROXY;
			message->header_type = DT_PROXY_HT_DESTROY;
			message->header_origin = cur_connection_node->origin;
			message->header_id = cur_connection_node->id;
			header_errno = htons(optval);
			message->data_len = sizeof(short);
			memcpy(message->data, &header_errno, message->data_len);

			if((retval = message_push()) == -1){
				report_error("handle_message_dt_proxy_ht_activate(): message_push(): %s", strerror(errno));
				return(-1);
			}
			connection_node_delete(cur_connection_node);
			return(0);
		}
	}

	cur_connection_node->state = CON_ACTIVE;

	// Set up the response buffer here, and send it through as a message!
	if(cur_connection_node->proxy_type == PROXY_DYNAMIC){
		if((retval = proxy_response(cur_connection_node->fd, cur_connection_node->ver, cur_connection_node->cmd, message->data, io->message_data_size)) == -1){
			message->data_type = DT_PROXY;
			message->header_type = DT_PROXY_HT_DESTROY;
			message->header_origin = cur_connection_node->origin;
			message->header_id = cur_connection_node->id;
			message->data_len = 0;

			if((retval = message_push()) == -1){
				report_error("handle_message_dt_proxy_ht_activate(): message_push(): %s", strerror(errno));
				return(-1);
			}
			connection_node_delete(cur_connection_node);
			return(0);
		}

		message->data_len = retval;
	}else{
		message->data_len = 0;
	}

	message->data_type = DT_PROXY;
	message->header_type = DT_PROXY_HT_RESPONSE;
	message->header_origin = cur_connection_node->origin;
	message->header_id = cur_connection_node->id;

	if((retval = message_push()) == -1){
		report_error("handle_message_dt_proxy_ht_activate(): message_push(): %s", strerror(errno));
		return(-1);
	}

	return(0);
}


int handle_message_dt_proxy_ht_response(){
	int retval;
	struct message_helper *message = &(io->message);

	struct connection_node *cur_connection_node;
	int count, errno;

	struct message_helper *new_message, *tmp_message;

	if((cur_connection_node = connection_node_find(message->header_origin, message->header_id)) == NULL){
		message->header_type = DT_PROXY_HT_DESTROY;
		message->data_len = 0;

		if((retval = message_push()) == -1){
			report_error("handle_message_dt_proxy_ht_response(): message_push(): %s", strerror(errno));
			return(-1);
		}

		return(0);
	}

	if(cur_connection_node->proxy_type == PROXY_DYNAMIC){
		retval = write(cur_connection_node->fd, message->data, message->data_len);

		if(retval == -1){
			if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK){
				report_error("handle_message_dt_proxy_ht_response(): write(%d, %lx, %d): %s", \
						cur_connection_node->fd, (unsigned long) message->data, message->data_len, strerror(errno));

				message->data_type = DT_PROXY;
				message->header_type = DT_PROXY_HT_DESTROY;
				message->header_origin = cur_connection_node->origin;
				message->header_id = cur_connection_node->id;
				message->data_len = 0;

				if((retval = message_push()) == -1){
					report_error("handle_message_dt_proxy_ht_response(): message_push(): %s", strerror(errno));
					return(-1);
				}
				connection_node_delete(cur_connection_node);
				return(-2);
			}
		}

		if(retval != message->data_len){
			new_message = message_helper_create(message->data + retval, message->data_len - retval, io->message_data_size);

			if(!new_message){
				report_error("handle_message_dt_proxy_ht_response(): message_helper_create(%lx, %d, %d): %s", \
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
					message->header_origin = io->controller;
					message->header_id = cur_connection_node->fd;
					message->data_len = 0;

					if((retval = message_push()) == -1){
						report_error("handle_message_dt_proxy_ht_response(): message_push(): %s", strerror(errno));
						return(-1);
					}
				}
			}
		}

		// XXX after activation, free() cur_connection_node->buffer_head??
		// XXX is it ever used after socks handshake is complete?

		if(cur_connection_node->buffer_tail > cur_connection_node->buffer_ptr){

			message->data_type = DT_CONNECTION;
			message->header_type = DT_CONNECTION_HT_DATA;
			message->header_origin = cur_connection_node->origin;
			message->header_id = cur_connection_node->id;

			message->data_len = cur_connection_node->buffer_tail - cur_connection_node->buffer_ptr;
			memcpy(message->data, cur_connection_node->buffer_ptr, message->data_len);

			if((retval = message_push()) == -1){
				report_error("handle_message_dt_proxy_ht_response(): message_push(): %s", strerror(errno));
				return(-1);
			}
		}
	}

	cur_connection_node->state = CON_ACTIVE;

	return(0);
}

int handle_message_dt_connection(){
	int retval;
	struct message_helper *message = &(io->message);
	struct message_helper *new_message, *tmp_message;

	struct connection_node *cur_connection_node;
	int count, errno;


	if((cur_connection_node = connection_node_find(message->header_origin, message->header_id)) == NULL){

		message->data_type = DT_PROXY;
		message->header_type = DT_PROXY_HT_DESTROY;
		message->data_len = 0;

		if((retval = message_push()) == -1){
			report_error("handle_message_dt_connection(): message_push(): %s", strerror(errno));
			return(-1);
		}
		return(0);
	}


	if(message->header_type == DT_CONNECTION_HT_DORMANT){
		cur_connection_node->state = CON_DORMANT;
		return(0);
	}

	if(message->header_type == DT_CONNECTION_HT_ACTIVE){
		cur_connection_node->state = CON_ACTIVE;
		return(0);
	}

	// DT_CONNECTION_HT_DATA
	if(cur_connection_node->write_head){
		retval = 0;
	} else {
		retval = write(cur_connection_node->fd, message->data, message->data_len);
	}

	if(retval == -1){
		if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK){
			report_error("handle_message_dt_connection(): write(%d, %lx, %d): %s", \
					cur_connection_node->fd, (unsigned long) message->data, message->data_len, strerror(errno));

			message->data_type = DT_PROXY;
			message->header_type = DT_PROXY_HT_DESTROY;
			message->header_origin = cur_connection_node->origin;
			message->header_id = cur_connection_node->id;
			message->data_len = 0;

			if((retval = message_push()) == -1){
				report_error("handle_message_dt_connection(): message_push(): %s", strerror(errno));
				return(-1);
			}
			connection_node_delete(cur_connection_node);
			return(-2);
		}
	}

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
				message->header_origin = io->controller;
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

int handle_proxy_read(struct proxy_node *cur_proxy_node){
	int count;
	struct connection_node *tmp_connection_node;


	/* Create a new connection object. */
	if((tmp_connection_node = connection_node_create()) == NULL){
		report_error("handle_proxy_read(): connection_node_create(): %s", strerror(errno));
		return(-1);
	}

	if((tmp_connection_node->fd = accept(cur_proxy_node->fd, NULL, NULL)) == -1){
		report_error("handle_proxy_read(): accept(%d, NULL, NULL): %s", cur_proxy_node->fd, strerror(errno));
		return(-1);
	}
	fcntl(tmp_connection_node->fd, F_SETFL, O_NONBLOCK);

	tmp_connection_node->origin = io->controller;
	tmp_connection_node->id = tmp_connection_node->fd;

	if(cur_proxy_node->type == PROXY_DYNAMIC){
		// PROXY_DYNAMIC case goes here.

		tmp_connection_node->state = CON_SOCKS_NO_HANDSHAKE;

		if((tmp_connection_node->buffer_head = (char *) calloc(io->message_data_size, sizeof(char))) == NULL){
			report_error("handle_proxy_read(): calloc(%d, %d): %s\r", io->message_data_size, (int) sizeof(char), strerror(errno));
			return(-1);
		}

		tmp_connection_node->buffer_tail = tmp_connection_node->buffer_head;
		tmp_connection_node->buffer_ptr = tmp_connection_node->buffer_head;
		tmp_connection_node->buffer_size = io->message_data_size;

		tmp_connection_node->proxy_type = PROXY_DYNAMIC;

	}else if(cur_proxy_node->type == PROXY_LOCAL){

		count = strlen(cur_proxy_node->rhost_rport);
		if((tmp_connection_node->rhost_rport = (char *) calloc(count + 1, sizeof(char))) == NULL){
			report_error("handle_proxy_read(): calloc(%d, %d): %s", count + 1, (int) sizeof(char), strerror(errno));
			return(-1);
		}
		memcpy(tmp_connection_node->rhost_rport, cur_proxy_node->rhost_rport, count);
		tmp_connection_node->state = CON_READY;
		tmp_connection_node->proxy_type = PROXY_LOCAL;

		handle_connection_read(tmp_connection_node);
	}

	return(0);
}


int handle_connection_write(struct connection_node *cur_connection_node){

	int retval;
	struct message_helper *message = &(io->message);
	struct message_helper *tmp_message;


	while(cur_connection_node->write_head){

		tmp_message = cur_connection_node->write_head;

		retval = write(cur_connection_node->fd, tmp_message->data, tmp_message->data_len);

		if(retval == -1){
			if(errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK){
				report_error("handle_connection_write(): write(%d, %lx, %d): %s", \
						io->local_out_fd, (unsigned long) tmp_message->data, tmp_message->data_len, strerror(errno));

				message->data_type = DT_PROXY;
				message->header_type = DT_PROXY_HT_DESTROY;
				message->header_origin = cur_connection_node->origin;
				message->header_id = cur_connection_node->id;
				message->data_len = 0;

				if((retval = message_push()) == -1){
					report_error("handle_message_dt_proxy_ht_response(): message_push(): %s", strerror(errno));
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

		if(!io->tty_write_head){
			message->data_type = DT_CONNECTION;
			message->header_type = DT_CONNECTION_HT_ACTIVE;
			message->header_origin = io->controller;
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

int handle_connection_read(struct connection_node *cur_connection_node){

	int return_code, retval, count, offset;
	struct message_helper *message = &(io->message);

	unsigned short header_errno;

	return_code = 0;
	if(cur_connection_node->state == CON_ACTIVE){

		message->data_type = DT_CONNECTION;
		message->header_type = DT_CONNECTION_HT_DATA;
		message->header_origin = cur_connection_node->origin;
		message->header_id = cur_connection_node->id;

		errno = 0;
		if((retval = read(cur_connection_node->fd, message->data, io->message_data_size)) < 1){
			if(verbose && retval){
				fprintf(stderr, "\rhandle_connection_read(): Connection %s closed: %s\n", cur_connection_node->rhost_rport, strerror(errno));
			}
			message->data_type = DT_PROXY;
			message->header_type = DT_PROXY_HT_DESTROY;
			header_errno = htons(errno);
			message->data_len = sizeof(short);
			memcpy(message->data, &header_errno, message->data_len);

			connection_node_delete(cur_connection_node);
			return_code = -2;
		}

		message->data_len = retval;
		if((retval = message_push()) == -1){
			report_error("handle_connection_read(): message_push(): %s", strerror(errno));
			return_code = -1;
		}

		return(return_code);
	}

	// Socks connection, not finished initializing.
	if(cur_connection_node->proxy_type == PROXY_DYNAMIC){

		if((retval = read(cur_connection_node->fd, cur_connection_node->buffer_tail, cur_connection_node->buffer_size - (cur_connection_node->buffer_tail - cur_connection_node->buffer_head))) < 1){
			if(retval && verbose){
				fprintf(stderr, "\rConnection %s closed: %s\n", cur_connection_node->rhost_rport, strerror(errno));
			}
			connection_node_delete(cur_connection_node);
			return(-2);
		}

		cur_connection_node->buffer_tail = cur_connection_node->buffer_tail + retval;

		// XXX Check parse_socks_request() return codes. Differentiate between fatal and non-fatal errors.
		if((retval = parse_socks_request(cur_connection_node)) == -1){
			report_error("handle_connection_read(): parse_sock_request(%lx): Malformed SOCKS request.", (unsigned long) cur_connection_node);
			connection_node_delete(cur_connection_node);
			return(-2);
		}
		cur_connection_node->state = retval;

		if(cur_connection_node->state == CON_SOCKS_V5_AUTH){

			cur_connection_node->buffer_head[0] = 0x05;
			cur_connection_node->buffer_head[1] = cur_connection_node->auth_method;
			retval = write(cur_connection_node->fd, cur_connection_node->buffer_head, 2);

			if(retval == -1 || cur_connection_node->auth_method == 0xff){
				if(verbose){
					fprintf(stderr, "\rConnection %s closed: %s\n", cur_connection_node->rhost_rport, strerror(errno));
				}
				connection_node_delete(cur_connection_node);
				return(-2);
			}

			if(cur_connection_node->buffer_tail > cur_connection_node->buffer_ptr){

				// XXX Check parse_socks_request() return codes. Differentiate between fatal and non-fatal errors.
				if((retval = parse_socks_request(cur_connection_node)) == -1){
					report_error("handle_connection_read(): parse_sock_request(%lx): Malformed SOCKS request.", (unsigned long) cur_connection_node);
					connection_node_delete(cur_connection_node);
					return(-2);
				}
				cur_connection_node->state = retval;
			}
		}
	}

	if(cur_connection_node->state == CON_READY){

		message->data_type = DT_PROXY;
		message->header_type = DT_PROXY_HT_CREATE;
		message->header_origin = cur_connection_node->origin;
		message->header_id = cur_connection_node->id;
		message->header_proxy_type = cur_connection_node->proxy_type;

		memset(message->data, 0, io->message_data_size);
		count = strlen(cur_connection_node->rhost_rport);
		offset = 0;

		if(cur_connection_node->proxy_type == PROXY_DYNAMIC){
			offset = 2;
			count += offset; // account for the ver and cmd to be sent first.
			count = count < io->message_data_size ? count : io->message_data_size;
			*(message->data) = cur_connection_node->ver;
			*(message->data + 1) = cur_connection_node->cmd;
		}

		memcpy(message->data + offset, cur_connection_node->rhost_rport, count);
		message->data_len = count;

		if((retval = message_push()) == -1){
			report_error("handle_connection_read(): message_push(): %s", strerror(errno));
			return(-1);
		}
	}

	return(0);
}

int handle_send_nop(){
	struct message_helper *message = &(io->message);

	message->data_type = DT_NOP;
	message->data_len = 0;
	if(message_push() == -1){
		report_error("handle_send_nop(): message_push(): %s", strerror(errno));
		return(-1);
	}

	return(0);
}

struct connection_node *handle_tun_tap_init(int ifr_flag){

  int count;
  struct ifreq ifr;

  struct connection_node *tmp_connection_node;

  /* XXX Perform a full audit for memory leaks. */
  /* XXX Perform static analysis. */

  /* XXX Check the max data_size and set the mtu on the tun/tap fd accordingly! */
  if((tmp_connection_node = connection_node_create()) == NULL){
    report_error("tun_tap_init(): connection_node_create(): %s", strerror(errno));
    return(NULL);
  }

  if((tmp_connection_node->fd = open(DEV_NET_TUN, O_RDWR)) == -1){
		connection_node_delete(tmp_connection_node);

		report_error("tun_tap_init(): open(%s, O_RDWR): %s", DEV_NET_TUN, strerror(errno));
		if(errno == EACCES){
			report_error("Root needed to initialize tun/tap devices. Ignoring.");
		}
    return(NULL);
  }
  tmp_connection_node->origin = io->controller;
  tmp_connection_node->id = tmp_connection_node->fd;

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = ifr_flag | IFF_NO_PI;

  if(ioctl(tmp_connection_node->fd, TUNSETIFF, (void *) &ifr) == -1){
    report_error("tun_tap_init(): ioctl(%d, TUNSETIFF, %lx): %s", tmp_connection_node->fd, (unsigned long) ((void *) &ifr), strerror(errno));
    connection_node_delete(tmp_connection_node);
    return(NULL);
  }

  count = strlen(ifr.ifr_name);
  if((tmp_connection_node->rhost_rport = (char *) calloc(count + 1, sizeof(char))) == NULL){
    report_error("tun_tap_init(): calloc(%d, %d): %s", count + 1, (int) sizeof(char), strerror(errno));
    return(NULL);
  }
  memcpy(tmp_connection_node->rhost_rport, ifr.ifr_name, count);

  tmp_connection_node->state = CON_READY;

  if(ifr_flag == IFF_TUN){
    tmp_connection_node->proxy_type = PROXY_TUN;
  }else if(ifr_flag == IFF_TAP){
    tmp_connection_node->proxy_type = PROXY_TAP;
  }

  fcntl(tmp_connection_node->fd, F_SETFL, O_NONBLOCK);

  return(tmp_connection_node);
}

