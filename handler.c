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

int handle_signal_sigwinch(struct io_helper *io){

	int retval;
	struct message_helper *message;

	message = &io->message;

	if((retval = ioctl(io->local_out_fd, TIOCGWINSZ, io->tty_winsize)) == -1){
		print_error(io, "%s: %d: handle_signal_sigwinch(): ioctl(%d, TIOCGWINSZ, %lx): %s\n", \
				program_invocation_short_name, io->controller, \
				io->local_out_fd, (unsigned long) io->tty_winsize, \
				strerror(errno));
		return(-1);
	}

	message->data_type = DT_WINRESIZE;
	*((unsigned short *) message->data) = htons(io->tty_winsize->ws_row);
	message->data_len = sizeof(io->tty_winsize->ws_row);
	*((unsigned short *) (message->data + message->data_len)) = htons(io->tty_winsize->ws_col);
	message->data_len += sizeof(io->tty_winsize->ws_col);

	if((retval = message_push(io)) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: handle_signal_sigwinch(): message_push(%lx): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, \
					strerror(errno));
		}
		return(-1);
	}

	return(0);
}

int handle_local_write(struct io_helper *io){
	
	int retval;
  struct message_helper *tmp_message;

	while(io->tty_write_head){

		tmp_message = io->tty_write_head;

		retval = write(io->local_out_fd, tmp_message->data, tmp_message->data_len);

		if(retval == -1){
			if(errno != EINTR){
				print_error(io, "%s: %d: write(%d, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, \
						io->local_out_fd, (unsigned long) tmp_message->data, tmp_message->data_len, \
						strerror(errno));
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
int handle_local_read(struct io_helper *io){

	int retval;
	struct message_helper *message = &(io->message);

	message->data_type = DT_TTY;

	if((retval = read(io->local_in_fd, message->data, io->message_data_size)) == -1){

		if(errno != EINTR){
			if(errno == EIO){
				return(-2);
			}else{
				print_error(io, "%s: %d: read(%d, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, \
						io->local_in_fd, (unsigned long) message->data, io->message_data_size, \
						strerror(errno));
				return(retval);
			}
		}

	}else{

		message->data_len = retval;

		if(!message->data_len){
			return(-2);
		}else{
			if((retval = message_push(io)) == -1){
				if(verbose){
					fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
							program_invocation_short_name, io->controller, \
							(unsigned long) io, \
							strerror(errno));
				}
				return(-1);
			}
		}
	}

	return(0);
}


int handle_message_dt_tty(struct io_helper *io){

  int retval;
  struct message_helper *message = &(io->message);
	struct message_helper *new_message, *tmp_message;

	if(io->tty_write_head){
		retval = 0;
	} else {
		retval = write(io->local_out_fd, message->data, message->data_len);
	}

	if(retval == -1){
		if(errno != EINTR){
			print_error(io, "%s: %d: write(%d, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					io->local_out_fd, (unsigned long) message->data, message->data_len, \
					strerror(errno));
			return(-1);
		}
	}

	if(retval != message->data_len){
		new_message = message_helper_create(message->data + retval, message->data_len - retval, io->message_data_size);

		if(!new_message){
			print_error(io, "%s: %d: message_helper_create(%lx, %d, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) message->data + retval, message->data_len - retval, io->message_data_size, \
					strerror(errno));
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

int handle_message_dt_winresize(struct io_helper *io){
  int retval;
  struct message_helper *message = &(io->message);

	if(message->data_len != sizeof(io->tty_winsize->ws_row) + sizeof(io->tty_winsize->ws_col)){
		print_error(io, "%s: %d: DT_WINRESIZE termios: not enough data!\r\n", \
				program_invocation_short_name, io->controller);
		return(-1);
	}

	io->tty_winsize->ws_row = ntohs(*((unsigned short *) message->data));
	io->tty_winsize->ws_col = ntohs(*((unsigned short *) (message->data + sizeof(unsigned short))));

	if((retval = ioctl(io->local_out_fd, TIOCSWINSZ, io->tty_winsize)) == -1){
		print_error(io, "%s: %d: ioctl(%d, %d, %lx): %s\n", \
				program_invocation_short_name, io->controller, \
				io->local_out_fd, TIOCSWINSZ, (unsigned long) io->tty_winsize, \
				strerror(errno));
		return(-1);
	}

	if((retval = kill(-(io->child_sid), SIGWINCH)) == -1){
		print_error(io, "%s: %d: kill(%d, SIGWINCH): %s\n", \
				program_invocation_short_name, io->controller, \
				-(io->child_sid), \
				strerror(errno));
		return(-1);
	}
	
	return(0);
}

int handle_message_dt_proxy_ht_destroy(struct io_helper *io){
  struct message_helper *message = &(io->message);

	if(message->header_errno && verbose){
		print_error(io, "%s: %d: Proxy unable to connect to '%s': %s\n", \
				program_invocation_short_name, io->controller, \
				message->data, \
				strerror(message->header_errno));
		return(-1);
	}
	connection_node_delete(message->header_origin, message->header_id, &(io->connection_head));

	return(0);
}

int handle_message_dt_proxy_ht_create(struct io_helper *io){
	int retval;
	struct message_helper *message = &(io->message);

  struct connection_node *cur_connection_node, *tmp_connection_node;
	int count, errno;


	if((cur_connection_node = connection_node_find(message->header_origin, message->header_id, &(io->connection_head)))){
		connection_node_delete(message->header_origin, message->header_id, &(io->connection_head));
	}

	if((tmp_connection_node = connection_node_create(&(io->connection_head))) == NULL){
		print_error(io, "%s: %d: calloc(1, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				(int) sizeof(struct connection_node), \
				strerror(errno));
		return(-1);
	}

	tmp_connection_node->origin = message->header_origin;
	tmp_connection_node->id = message->header_id;

	// the +/- 2 below is to handle the leading two chars which are the ver and the cmd of the proxy request.
	count = message->data_len;
	tmp_connection_node->ver = *(message->data);
	tmp_connection_node->cmd = *(message->data + 1);
	count -= 2;

	if((tmp_connection_node->rhost_rport = (char *) calloc(count + 1, sizeof(char))) == NULL){
		print_error(io, "%s: %d: calloc(%d, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				count + 1, (int) sizeof(char), \
				strerror(errno));
		return(-1);
	}
	memcpy(tmp_connection_node->rhost_rport, message->data + 2, count);
	tmp_connection_node->origin = message->header_origin;
	tmp_connection_node->id = message->header_id;

	//            fprintf(stderr, "\rDEBUG: proxy_connect(%s)\r\n", tmp_connection_node->rhost_rport);
	errno = 0;
	if((tmp_connection_node->fd = proxy_connect(tmp_connection_node->rhost_rport)) == -1){
		message->header_type = DT_PROXY_HT_DESTROY;
		message->header_errno = errno;

		count = strlen(tmp_connection_node->rhost_rport) + 1;
		count = count < io->message_data_size ? count : io->message_data_size;
		memcpy(message->data, tmp_connection_node->rhost_rport, count);
		if((retval = message_push(io)) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, \
						strerror(errno));
			}
			return(-1);
		}
		connection_node_delete(message->header_origin, message->header_id, &(io->connection_head));

		return(0);
	}
	//            fprintf(stderr, "\rDEBUG: tmp_connection_node->fd: %d\r\n", tmp_connection_node->fd);
	tmp_connection_node->state = CON_ACTIVE;

	// Set up the response buffer here, and send it through as a message!
	if((retval = proxy_response(tmp_connection_node->fd, tmp_connection_node->ver, tmp_connection_node->cmd, message->data, io->message_data_size)) == -1){
		message->header_type = DT_PROXY_HT_DESTROY;
		message->header_errno = errno;
		if((retval = message_push(io)) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, \
						strerror(errno));
			}
			return(-1);
		}
		connection_node_delete(message->header_origin, message->header_id, &(io->connection_head));
		return(0);
	}

	message->header_type = DT_PROXY_HT_RESPONSE;
	message->data_len = retval;
	if((retval = message_push(io)) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) io, \
					strerror(errno));
		}
		return(-1);
	}

	return(0);
}

int handle_message_dt_proxy_ht_response(struct io_helper *io){
	int retval;
	struct message_helper *message = &(io->message);

  struct connection_node *cur_connection_node;
	int count, errno;

	struct message_helper *new_message, *tmp_message;

	//            fprintf(stderr, "DEBUG: (%d|%d): DT_PROXY_HT_RESPONSE\r\n", message->header_origin, message->header_id);
	if((cur_connection_node = connection_node_find(message->header_origin, message->header_id, &(io->connection_head))) == NULL){
		message->header_type = DT_PROXY_HT_DESTROY;
		message->header_errno = EBADR;

		if((retval = message_push(io)) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, \
						strerror(errno));
			}
			return(-1);
		}
	}

	//            fprintf(stderr, "\rDEBUG: cur_connection_node: %lx\n", (unsigned long) cur_connection_node);
	//            fprintf(stderr, "\rDEBUG: cur_connection_node->write_head: %lx\n", (unsigned long) cur_connection_node->write_head);
	//            fprintf(stderr, "\rDEBUG: cur_connection_node->fd: %d\n", cur_connection_node->fd);
	//            fprintf(stderr, "\rDEBUG: message->data_len: %d\n", message->data_len);
	//            fprintf(stderr, "\rDEBUG: message->data: %s\n", message->data);

	retval = write(cur_connection_node->fd, message->data, message->data_len);
	//            fprintf(stderr, "\rDEBUG: retval: %d\n", retval);

	if(retval == -1){
		if(errno != EINTR){
			print_error(io, "%s: %d: write(%d, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					cur_connection_node->fd, (unsigned long) message->data, message->data_len, \
					strerror(errno));

			message->data_type = DT_PROXY;
			message->header_type = DT_PROXY_HT_DESTROY;
			message->header_origin = cur_connection_node->origin;
			message->header_id = cur_connection_node->id;
			message->header_errno = EBADF;

			if((retval = message_push(io)) == -1){
				if(verbose){
					fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
							program_invocation_short_name, io->controller, \
							(unsigned long) io, \
							strerror(errno));
				}
				return(-1);
			}
			connection_node_delete(cur_connection_node->origin, cur_connection_node->id, &(io->connection_head));
		}
	}

	if(retval != message->data_len){
		new_message = message_helper_create(message->data + retval, message->data_len - retval, io->message_data_size);

		if(!new_message){
			print_error(io, "%s: %d: message_helper_create(%lx, %d, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) message->data + retval, message->data_len - retval, io->message_data_size, \
					strerror(errno));
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

				if((retval = message_push(io)) == -1){
					if(verbose){
						fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
								program_invocation_short_name, io->controller, \
								(unsigned long) io, \
								strerror(errno));
					}
					return(-1);
				}
			}
		}
	}

	return(0);
}

int handle_message_dt_connection(struct io_helper *io){
	int retval;
	struct message_helper *message = &(io->message);
	struct message_helper *new_message, *tmp_message;

  struct connection_node *cur_connection_node;
	int count, errno;


	//          fprintf(stderr, "DEBUG: (%d|%d): DT_CONNECTION\r\n", message->header_origin, message->header_id);
	if((cur_connection_node = connection_node_find(message->header_origin, message->header_id, &(io->connection_head))) == NULL){

		message->data_type = DT_PROXY;
		message->header_type = DT_PROXY_HT_DESTROY;
		message->header_errno = EBADF;

		if((retval = message_push(io)) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, \
						strerror(errno));
			}
			return(-1);
		}
		return(0);
	}

	//          fprintf(stderr, "\rDEBUG: case DT_CONNECTION_HT...: %d\n", message->header_type);

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
		if(errno != EINTR){
			print_error(io, "%s: %d: write(%d, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					cur_connection_node->fd, (unsigned long) message->data, message->data_len, \
					strerror(errno));

			message->data_type = DT_PROXY;
			message->header_type = DT_PROXY_HT_DESTROY;
			message->header_origin = cur_connection_node->origin;
			message->header_id = cur_connection_node->id;
			message->header_errno = EBADF;

			if((retval = message_push(io)) == -1){
				if(verbose){
					fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
							program_invocation_short_name, io->controller, \
							(unsigned long) io, \
							strerror(errno));
				}
				return(-1);
			}
			connection_node_delete(cur_connection_node->origin, cur_connection_node->id, &(io->connection_head));
		}
	}

	if(retval != message->data_len){
		new_message = message_helper_create(message->data + retval, message->data_len - retval, io->message_data_size);

		if(!new_message){
			print_error(io, "%s: %d: message_helper_create(%lx, %d, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) message->data + retval, message->data_len - retval, io->message_data_size, \
					strerror(errno));
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

				if((retval = message_push(io)) == -1){
					if(verbose){
						fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
								program_invocation_short_name, io->controller, \
								(unsigned long) io, \
								strerror(errno));
					}
					return(-1);
				}
			}
		}
	}

	return(0);
}

int handle_proxy_read(struct io_helper *io, struct proxy_node *cur_proxy_node){
	int count;
	struct connection_node *tmp_connection_node;

	//					fprintf(stderr, "\rDEBUG: PROXY: FD_ISSET: cur_proxy_node->fd: %d\r\n", cur_proxy_node->fd);

	/* Create a new connection object. */
	if((tmp_connection_node = connection_node_create(&(io->connection_head))) == NULL){
		print_error(io, "%s: %d: calloc(1, %d): %s\n", \
				program_invocation_short_name, io->controller, \
				(int) sizeof(struct connection_node), \
				strerror(errno));
		return(-1);
	}
	//					fprintf(stderr, "\rDEBUG: tmp_connection_node: %lx\n", (unsigned long) tmp_connection_node);

	if((tmp_connection_node->fd = accept(cur_proxy_node->fd, NULL, NULL)) == -1){
		print_error(io, "%s: %d: accept(%d, NULL, NULL): %s\n", \
				program_invocation_short_name, io->controller, \
				cur_proxy_node->fd, \
				strerror(errno));
		return(-1);
	}
	fcntl(tmp_connection_node->fd, F_SETFL, O_NONBLOCK);

	tmp_connection_node->origin = io->controller;
	tmp_connection_node->id = tmp_connection_node->fd;

	if(cur_proxy_node->type == PROXY_DYNAMIC){
		//						fprintf(stderr, "DEBUG: do PROXY_DYNAMIC\n");
		// PROXY_DYNAMIC case goes here.

		tmp_connection_node->state = CON_SOCKS_NO_HANDSHAKE;

		if((tmp_connection_node->buffer_head = (char *) calloc(io->message_data_size, sizeof(char))) == NULL){
			if(verbose){
				fprintf(stderr, "%s: calloc(%d, %d): %s\r\n", \
						program_invocation_short_name, io->message_data_size, (int) sizeof(char), strerror(errno));
			}
			return(-1);
		}
		//						fprintf(stderr, "DEBUG: tmp_connection_node->buffer_head: %lx\n", (unsigned long) tmp_connection_node->buffer_head);

		tmp_connection_node->buffer_tail = tmp_connection_node->buffer_head;
		tmp_connection_node->buffer_size = io->message_data_size;
		//						fprintf(stderr, "DEBUG: done PROXY_DYNAMIC\n");
	} else if(cur_proxy_node->type == PROXY_LOCAL){

		count = strlen(cur_proxy_node->rhost_rport);
		if((tmp_connection_node->rhost_rport = (char *) calloc(count + 1, sizeof(char))) == NULL){
			print_error(io, "%s: %d: calloc(%d, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					count + 1, (int) sizeof(char), \
					strerror(errno));
			return(-1);
		}
		memcpy(tmp_connection_node->rhost_rport, cur_proxy_node, count);
		tmp_connection_node->state = CON_ACTIVE;
	}

	return(0);

}


int handle_connection_write(struct io_helper *io, struct connection_node *cur_connection_node){

	int retval;
	struct message_helper *message = &(io->message);
	struct message_helper *tmp_message;

	//					fprintf(stderr, "\rDEBUG: CONNECTION: FD_ISSET: &write_fds: cur_connection_node->fd: %d\r\n", cur_connection_node->fd);

	while(cur_connection_node->write_head){

		tmp_message = cur_connection_node->write_head;

		retval = write(cur_connection_node->fd, tmp_message->data, tmp_message->data_len);

		if(retval == -1){
			if(errno != EINTR){
				print_error(io, "%s: %d: write(%d, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, \
						io->local_out_fd, (unsigned long) tmp_message->data, tmp_message->data_len, \
						strerror(errno));
				return(-1);
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

			if((retval = message_push(io)) == -1){
				if(verbose){
					fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
							program_invocation_short_name, io->controller, \
							(unsigned long) io, \
							strerror(errno));
				}
				return(-1);
			}
		}
	}
	return(0);
}

int handle_connection_read(struct io_helper *io, struct connection_node *cur_connection_node){

	int retval, count;
	struct message_helper *message = &(io->message);

	//					fprintf(stderr, "\rDEBUG: CONNECTION: FD_ISSET: &read_fds: cur_connection_node->fd: %d\r\n", cur_connection_node->fd);
	//					fprintf(stderr, "\rDEBUG: cur_connection_node->state: %d\n", cur_connection_node->state);

	if(cur_connection_node->state == CON_ACTIVE){

		message->data_type = DT_CONNECTION;
		message->header_type = DT_CONNECTION_HT_DATA;
		message->header_origin = cur_connection_node->origin;
		message->header_id = cur_connection_node->id;

		// XXX fix the error checking and report. 
		if((retval = read(cur_connection_node->fd, message->data, io->message_data_size)) < 1){
			if(retval){
				print_error(io, "%s: %d: read(%d, %lx, %d): %s\n", \
						program_invocation_short_name, io->controller, \
						io->local_in_fd, (unsigned long) message->data, io->message_data_size, \
						strerror(errno));
			}
			message->data_type = DT_PROXY;
			message->header_type = DT_PROXY_HT_DESTROY;
			message->header_errno = errno;
			connection_node_delete(cur_connection_node->origin, cur_connection_node->id, &(io->connection_head));
			return(0);
		}

		message->data_len = retval;
		if((retval = message_push(io)) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, \
						strerror(errno));
			}
			return(-1);
		}

		return(0);
	}

	// Socks connection, not finished initializing.

	if((retval = read(cur_connection_node->fd, cur_connection_node->buffer_tail, cur_connection_node->buffer_size - (cur_connection_node->buffer_tail - cur_connection_node->buffer_head))) < 1){
		if(verbose){
			fprintf(stderr, "%s: %d: read(%d, %lx, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					cur_connection_node->fd, (unsigned long) cur_connection_node->buffer_head, io->message_data_size, \
					strerror(errno));
		}

		connection_node_delete(cur_connection_node->origin, cur_connection_node->id, &(io->connection_head));
		return(0);
	}
	cur_connection_node->buffer_tail = cur_connection_node->buffer_tail + retval;

	/*
		 fprintf(stderr, "DEBUG: cur_connection_node->buffer_size: %d\n", cur_connection_node->buffer_size);
		 fprintf(stderr, "DEBUG: cur_connection_node->buffer_head: ");
		 int i;
		 for(i = 0; i < retval; i++){
		 fprintf(stderr, "%02x", cur_connection_node->buffer_head[i]);
		 }
		 fprintf(stderr, "\n");
	 */

	if((retval = parse_socks_request(cur_connection_node)) == -1){
		if(verbose){
			fprintf(stderr, "%s: %d: parse_sock_request(%lx): Malformed SOCKS request.\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) cur_connection_node);
		}
		connection_node_delete(cur_connection_node->origin, cur_connection_node->id, &(io->connection_head));
		return(0);
	}

	cur_connection_node->state = retval;

	if(cur_connection_node->state == CON_READY){
		//					fprintf(stderr, "DEBUG: (%d|%d): DT_PROXY_HT_CREATE 1: rhost_rport: %s\r\n", cur_connection_node->origin, cur_connection_node-> id, cur_connection_node->rhost_rport);
		//							fprintf(stderr, "\rDEBUG: cur_connection_node->state == CON_READY\n");
		//							fprintf(stderr, "\rDEBUG: cur_connection_node->fd: %d\n", cur_connection_node->fd);
		//							fprintf(stderr, "\rDEBUG: cur_connection_node->rhost_rport: %s\n", cur_connection_node->rhost_rport);
		message->data_type = DT_PROXY;
		message->header_type = DT_PROXY_HT_CREATE;
		message->header_origin = cur_connection_node->origin;
		message->header_id = cur_connection_node->id;

		memset(message->data, '\0', io->message_data_size);
		count = strlen(cur_connection_node->rhost_rport);
		count += 2; // account for the ver and cmd to be sent first.
		count = count < io->message_data_size ? count : io->message_data_size;
		*(message->data) = cur_connection_node->ver;
		*(message->data + 1) = cur_connection_node->cmd;
		memcpy(message->data + 2, cur_connection_node->rhost_rport, count - 2);
		message->data_len = count;

		if((retval = message_push(io)) == -1){
			if(verbose){
				fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
						program_invocation_short_name, io->controller, \
						(unsigned long) io, \
						strerror(errno));
			}
			return(-1);
		}
		cur_connection_node->state = CON_ACTIVE;

	}else if(cur_connection_node->state == CON_SOCKS_V5_AUTH){

		cur_connection_node->buffer_head[0] = 0x05;
		cur_connection_node->buffer_head[1] = cur_connection_node->auth_method;
		cur_connection_node->buffer_tail = cur_connection_node->buffer_head + 2;
		cur_connection_node->buffer_ptr = cur_connection_node->buffer_head;

		if(cur_connection_node->auth_method == 0xff){
			// best effort write() before we kill the connection.
			write(cur_connection_node->fd, cur_connection_node->buffer_head, cur_connection_node->buffer_tail - cur_connection_node->buffer_head);
			connection_node_delete(cur_connection_node->origin, cur_connection_node->id, &(io->connection_head));
		}
	}

	/*
		 if(cur_connection_node->state == CON_COMPLETE){
		 fprintf(stderr, "DEBUG: (%d|%d): ver: %d\r\n", cur_connection_node->origin, cur_connection_node-> id, (int) cur_connection_node->ver);
		 fprintf(stderr, "DEBUG: (%d|%d): cmd: %d\r\n", cur_connection_node->origin, cur_connection_node-> id, (int) cur_connection_node->cmd);
		 fprintf(stderr, "DEBUG: (%d|%d): rhost_rport: %s\r\n", cur_connection_node->origin, cur_connection_node-> id, cur_connection_node->rhost_rport);
		 }
	 */
	return(0);
}
