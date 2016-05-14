
#include "common.h"

volatile sig_atomic_t sig_found = 0;


/***********************************************************************************************************************
 *
 * broker()
 *
 * Input: A pointer to our io_helper object and a pointer to our config_helper object.
 * Output: 0 for EOF, -1 for errors.
 *
 * Purpose: Broker data between the terminal and the network socket. 
 *
 **********************************************************************************************************************/
int broker(struct io_helper *io, struct config_helper *config){

	int retval = -1;
	fd_set fd_select;
	int io_bytes, fd_max;

	struct sigaction act;
	int current_sig;

	struct winsize *tty_winsize = NULL;
	pid_t sig_pid = 0;

	char *tmp_ptr;
	int count = 0;

	struct message_helper *message;

	struct proxy_node *cur_proxy_node;
	struct connection_node *cur_connection_node, *tmp_connection_node;


	/* We use this as a shorthand to make message syntax more readable. */
	message = &io->message;

	if(config->interactive){

		/* Prepare for window resize event handling. */
		memset(&act, 0, sizeof(act));
		act.sa_handler = signal_handler;

		if((retval = sigaction(SIGWINCH, &act, NULL)) == -1){
			print_error(io, "%s: %d: sigaction(SIGWINCH, %lx, NULL): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) &act, \
					strerror(errno));
			return(-1);
		}

		if((tty_winsize = (struct winsize *) calloc(1, sizeof(struct winsize))) == NULL){
			print_error(io, "%s: %d: calloc(1, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(int) sizeof(struct winsize), \
					strerror(errno));
			return(-1);
		}
	}


	/*  Start the broker() loop. */
	while(1){

		FD_ZERO(&fd_select);
		FD_SET(io->local_in_fd, &fd_select);
		FD_SET(io->remote_fd, &fd_select);
		fd_max = (io->local_in_fd > io->remote_fd) ? io->local_in_fd : io->remote_fd;

		cur_proxy_node = io->proxy_head;
		while(cur_proxy_node){
			FD_SET(cur_proxy_node->fd, &fd_select);
			if(cur_proxy_node->fd > fd_max){
				fd_max = cur_proxy_node->fd;
			}
			cur_proxy_node = cur_proxy_node->next;
		}

		cur_connection_node = io->connection_head;
		while(cur_connection_node){
			FD_SET(cur_connection_node->fd, &fd_select);
			if(cur_connection_node->fd > fd_max){
				fd_max = cur_connection_node->fd;
			}
			cur_connection_node = cur_connection_node->next;
		}

		if(((retval = select(fd_max + 1, &fd_select, NULL, NULL, NULL)) == -1) \
				&& !sig_found){
			print_error(io, "%s: %d: select(%d, %lx, NULL, NULL, NULL): %s\n", \
					program_invocation_short_name, io->controller, \
					fd_max + 1, (unsigned long) &fd_select, \
					strerror(errno));
			goto CLEAN_UP;
		}

		/*  Case 1: select() was interrupted by a signal that we handle. */
		if(sig_found){

			current_sig = sig_found;
			sig_found = 0;

			if(config->interactive && io->controller){

				switch(current_sig){

					/* Gather and send the new window size. */
					case SIGWINCH:
						if((retval = ioctl(io->local_out_fd, TIOCGWINSZ, tty_winsize)) == -1){
							print_error(io, "%s: %d: ioctl(%d, TIOCGWINSZ, %lx): %s\n", \
									program_invocation_short_name, io->controller, \
									io->local_out_fd, (unsigned long) tty_winsize, \
									strerror(errno));
							goto CLEAN_UP;
						}

						message->data_type = DT_WINRESIZE;

						*((unsigned short *) message->data) = htons(tty_winsize->ws_row);
						message->data_len = sizeof(tty_winsize->ws_row);
						*((unsigned short *) (message->data + message->data_len)) = htons(tty_winsize->ws_col);
						message->data_len += sizeof(tty_winsize->ws_col);

						if((retval = message_push(io)) == -1){
							if(verbose){
								fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
										program_invocation_short_name, io->controller, \
										(unsigned long) io, \
										strerror(errno));
							}
							goto CLEAN_UP;
						}

						break;
				}
			}

			/*  Case 2: Data is ready on the local fd. */
		}else if(FD_ISSET(io->local_in_fd, &fd_select)){

			message->data_type = DT_TTY;

			if((retval = read(io->local_in_fd, message->data, message->data_size)) == -1){

				if(errno != EINTR){
					if(errno == EIO){
						retval = 0;
					}else{
						print_error(io, "%s: %d: read(%d, %lx, %d): %s\n", \
								program_invocation_short_name, io->controller, \
								io->local_in_fd, (unsigned long) message->data, message->data_size, \
								strerror(errno));
					}
					goto CLEAN_UP;
				}

			}else{

				message->data_len = retval;

				if(!message->data_len){
					retval = 0;
					goto CLEAN_UP;

				}else{ 
					if((retval = message_push(io)) == -1){
						if(verbose){
							fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
									program_invocation_short_name, io->controller, \
									(unsigned long) io, \
									strerror(errno));
						}
						goto CLEAN_UP;
					}
				}
			}

			/*  Case 3: Data is ready on the remote fd. */
		}else if(FD_ISSET(io->remote_fd, &fd_select)){

			if((retval = message_pull(io)) == -1){
				if(io->eof){
					retval = 0;
				}else if(verbose){
					fprintf(stderr, "%s: %d: message_pull(%lx): %s\n", \
							program_invocation_short_name, io->controller, \
							(unsigned long) io, \
							strerror(errno));
				}
				goto CLEAN_UP;
			}

			switch(message->data_type){

				case DT_TTY:

					io_bytes = 0;
					tmp_ptr = message->data;
					count = message->data_len;

					while(count){
						retval = write(io->local_out_fd, tmp_ptr, count);

						if(retval == -1){
							if(errno != EINTR){
								print_error(io, "%s: %d: write(%d, %lx, %d): %s\n", \
										program_invocation_short_name, io->controller, \
										io->local_out_fd, (unsigned long) tmp_ptr, count, \
										strerror(errno));
								goto CLEAN_UP;
							}

						}else{
							count -= retval;
							io_bytes += retval;
							tmp_ptr += retval;
						}
					}

					break;

					/* Receive the new window size, set up our terminal appropriately, and signal the children. */
				case DT_WINRESIZE:

					if(!io->controller){

						if(message->data_len != sizeof(tty_winsize->ws_row) + sizeof(tty_winsize->ws_col)){
							print_error(io, "%s: %d: DT_WINRESIZE termios: not enough data!\r\n", \
									program_invocation_short_name, io->controller);
							return(-1);
						}

						tty_winsize->ws_row = ntohs(*((unsigned short *) message->data));
						tty_winsize->ws_col = ntohs(*((unsigned short *) (message->data + sizeof(unsigned short))));

						if((retval = ioctl(io->local_out_fd, TIOCSWINSZ, tty_winsize)) == -1){
							print_error(io, "%s: %d: ioctl(%d, %d, %lx): %s\n", \
									program_invocation_short_name, io->controller, \
									io->local_out_fd, TIOCSWINSZ, (unsigned long) tty_winsize, \
									strerror(errno));
							goto CLEAN_UP;
						}

						if((retval = kill(-(io->child_sid), SIGWINCH)) == -1){
							print_error(io, "%s: %d: kill(%d, SIGWINCH): %s\n", \
									program_invocation_short_name, io->controller, \
									-sig_pid, \
									strerror(errno));
							goto CLEAN_UP;
						}
					}

					break;

				case DT_PROXY:

					if(message->header_type == DT_PROXY_HT_DESTROY){
						fprintf(stderr, "DEBUG: (%d|%d): DT_PROXY_HT_DESTROY\r\n", message->header_origin, message->header_id);
						if(message->header_errno){
							print_error(io, "%s: %d: Proxy unable to connect to '%s': %s\n", \
									program_invocation_short_name, io->controller, \
									message->data, \
									strerror(message->header_errno));
						}
						connection_node_delete(message->header_origin, message->header_id, &(io->connection_head));

					}else if(message->header_type == DT_PROXY_HT_CREATE){
						fprintf(stderr, "DEBUG: (%d|%d): DT_PROXY_HT_CREATE\r\n", message->header_origin, message->header_id);
						if((cur_connection_node = connection_node_find(message->header_origin, message->header_id, &(io->connection_head)))){
							connection_node_delete(message->header_origin, message->header_id, &(io->connection_head));
						}

						if((tmp_connection_node = connection_node_create(&(io->connection_head))) == NULL){
							print_error(io, "%s: %d: calloc(1, %d): %s\n", \
									program_invocation_short_name, io->controller, \
									(int) sizeof(struct connection_node), \
									strerror(errno));
							goto CLEAN_UP;
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
							goto CLEAN_UP;
						}
						memcpy(tmp_connection_node->rhost_rport, message->data + 2, count);
						tmp_connection_node->origin = message->header_origin;
						tmp_connection_node->id = message->header_id;

						// XXX We will want to set up the check here for connect or bind based on cmd.
						fprintf(stderr, "DEBUG: proxy_connect(%s)\r\n", tmp_connection_node->rhost_rport);
						errno = 0;
						if((tmp_connection_node->fd = proxy_connect(tmp_connection_node->rhost_rport)) == -1){
							message->header_type = DT_PROXY_HT_DESTROY;
							message->header_errno = errno;

							count = strlen(tmp_connection_node->rhost_rport) + 1;
							count = count < message->data_size ? count : message->data_size;
							memcpy(message->data, tmp_connection_node->rhost_rport, count);

							if((retval = message_push(io)) == -1){
								if(verbose){
									fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
											program_invocation_short_name, io->controller, \
											(unsigned long) io, \
											strerror(errno));
								}
								goto CLEAN_UP;
							}
							connection_node_delete(message->header_origin, message->header_id, &(io->connection_head));

							break;
						}
						fprintf(stderr, "DEBUG: tmp_connection_node->fd: %d\r\n", tmp_connection_node->fd);

						// Set up the response buffer here, and send it through as a message!
						if((retval = proxy_response(tmp_connection_node->fd, tmp_connection_node->ver, tmp_connection_node->cmd, message->data, message->data_size)) == -1){
							message->header_type = DT_PROXY_HT_DESTROY;
							message->header_errno = errno;
							if((retval = message_push(io)) == -1){
								if(verbose){
									fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
											program_invocation_short_name, io->controller, \
											(unsigned long) io, \
											strerror(errno));
								}
								goto CLEAN_UP;
							}
							connection_node_delete(message->header_origin, message->header_id, &(io->connection_head));
							break;
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
							goto CLEAN_UP;
						}

					}else if(message->header_type == DT_PROXY_HT_RESPONSE){

						fprintf(stderr, "DEBUG: (%d|%d): DT_PROXY_HT_RESPONSE\r\n", message->header_origin, message->header_id);
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
								goto CLEAN_UP;
							}

						}else{

							//	XXX Check the blocking / non-blocking of the write()s in here. May not be doing this properly...
							io_bytes = 0;
							tmp_ptr = message->data;
							count = message->data_len;

							while(count){
								if((retval = write(cur_connection_node->fd, tmp_ptr, count)) == -1){
									print_error(io, "%s: %d: write(%d, %lx, %d): %s\n", \
											program_invocation_short_name, io->controller, \
											io->local_out_fd, (unsigned long) tmp_ptr, count, \
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
										goto CLEAN_UP;
									}
									connection_node_delete(cur_connection_node->origin, cur_connection_node->id, &(io->connection_head));

								}else{
									count -= retval;
									io_bytes += retval;
									tmp_ptr += retval;
								}
							}

							fcntl(cur_connection_node->fd, F_SETFL, O_NONBLOCK);
						}
					}else{
						// Malformed request.
						print_error(io, "%s: %d: Unknown Proxy Header Type: %d\n", \
								program_invocation_short_name, io->controller, \
								message->header_type);
						goto CLEAN_UP;
					}
					break;

				case DT_CONNECTION:

					fprintf(stderr, "DEBUG: (%d|%d): DT_CONNECTION\r\n", message->header_origin, message->header_id);
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
							goto CLEAN_UP;
						}
					}

					io_bytes = 0;
					tmp_ptr = message->data;
					count = message->data_len;

					while(count){
						if((retval = write(cur_connection_node->fd, tmp_ptr, count)) == -1){
							print_error(io, "%s: %d: write(%d, %lx, %d): %s\n", \
									program_invocation_short_name, io->controller, \
									io->local_out_fd, (unsigned long) tmp_ptr, count, \
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
								goto CLEAN_UP;
							}
							connection_node_delete(cur_connection_node->origin, cur_connection_node->id, &(io->connection_head));

						}else{
							count -= retval;
							io_bytes += retval;
							tmp_ptr += retval;
						}
					}

					break;


				default:
					// Malformed request.
					print_error(io, "%s: %d: Unknown Proxy Header Type: %d\n", \
							program_invocation_short_name, io->controller, \
							message->header_type);
					goto CLEAN_UP;
					break;
			}

			/* Deal with other proxies / connections being received locally. */
			// This is handled here instead of in case 2 above to ensure that the TTY traffic receives priority. 
		}else{

			cur_proxy_node = io->proxy_head;
			while(cur_proxy_node){

				if(FD_ISSET(cur_proxy_node->fd, &fd_select)){
					fprintf(stderr, "DEBUG: FD_ISSET: cur_proxy_node->fd: %d\r\n", cur_proxy_node->fd);

					/* Create a new connection object. */
					if((tmp_connection_node = connection_node_create(&(io->connection_head))) == NULL){
						print_error(io, "%s: %d: calloc(1, %d): %s\n", \
								program_invocation_short_name, io->controller, \
								(int) sizeof(struct connection_node), \
								strerror(errno));
						goto CLEAN_UP;
					}

					if((tmp_connection_node->fd = accept(cur_proxy_node->fd, NULL, NULL)) == -1){
						print_error(io, "%s: %d: accept(%d, NULL, NULL): %s\n", \
								program_invocation_short_name, io->controller, \
								cur_proxy_node->fd, \
								strerror(errno));
						goto CLEAN_UP;
					}

					tmp_connection_node->origin = io->controller;
					tmp_connection_node->id = tmp_connection_node->fd;

					if(cur_proxy_node->type == PROXY_DYNAMIC){
						// PROXY_DYNAMIC case goes here.

						tmp_connection_node->socks_flag = SOCKS_NO_HANDSHAKE;

						if((tmp_connection_node->socks_buffer_head = (char *) calloc(MAX_SOCKS_BUFFER_SIZE, sizeof(char))) == NULL){
							if(verbose){
								fprintf(stderr, "%s: calloc(%d, %d): %s\r\n", \
										program_invocation_short_name, MAX_SOCKS_BUFFER_SIZE, (int) sizeof(char), strerror(errno));
							}
							goto CLEAN_UP;
						}

						if((retval = read(tmp_connection_node->fd, tmp_connection_node->socks_buffer_head, MAX_SOCKS_BUFFER_SIZE)) == -1){
							if(verbose){
								fprintf(stderr, "%s: %d: read(%d, %lx, %d): %s\n", \
										program_invocation_short_name, io->controller, \
										tmp_connection_node->fd, (unsigned long) tmp_connection_node->socks_buffer_head, MAX_SOCKS_BUFFER_SIZE, \
										strerror(errno));
							}
							goto CLEAN_UP;
						}
						tmp_connection_node->socks_buffer_ptr = tmp_connection_node->socks_buffer_head + retval;

						if(!retval){
							connection_node_delete(tmp_connection_node->origin, tmp_connection_node->id, &(io->connection_head));
							break;
						}

						if((retval = parse_socks_request(tmp_connection_node)) == -1){
							if(verbose){
								fprintf(stderr, "%s: %d: parse_sock_request(%lx): Malformed SOCKS request.\n", \
										program_invocation_short_name, io->controller, \
										(unsigned long) tmp_connection_node);
							}
							connection_node_delete(tmp_connection_node->origin, tmp_connection_node->id, &(io->connection_head));
							break;
						}

						if(retval == SOCKS_V5_AUTH){
							tmp_connection_node->socks_flag = retval;

							tmp_connection_node->socks_buffer_head[0] = 0x05;
							tmp_connection_node->socks_buffer_head[1] = tmp_connection_node->auth_method;
							tmp_connection_node->socks_buffer_ptr = tmp_connection_node->socks_buffer_head;

							if((retval = write(tmp_connection_node->fd, tmp_connection_node->socks_buffer_ptr, 2)) == -1){
								if(verbose){
									fprintf(stderr, "%s: %d: read(%d, %lx, %d): %s\n", \
											program_invocation_short_name, io->controller, \
											tmp_connection_node->fd, (unsigned long) tmp_connection_node->socks_buffer_head, MAX_SOCKS_BUFFER_SIZE, \
											strerror(errno));
								}
								goto CLEAN_UP;
							}

							if(tmp_connection_node->auth_method == 0xff){
								connection_node_delete(tmp_connection_node->origin, tmp_connection_node->id, &(io->connection_head));
							}

						}else if(retval == SOCKS_V4_COMPLETE || retval == SOCKS_V4A_COMPLETE || retval == SOCKS_V5_COMPLETE){
							tmp_connection_node->socks_flag = retval;

							fprintf(stderr, "DEBUG: (%d|%d): ver: %d\r\n", tmp_connection_node->origin, tmp_connection_node-> id, (int) tmp_connection_node->ver);
							fprintf(stderr, "DEBUG: (%d|%d): cmd: %d\r\n", tmp_connection_node->origin, tmp_connection_node-> id, (int) tmp_connection_node->cmd);
							fprintf(stderr, "DEBUG: (%d|%d): rhost_rport: %s\r\n", tmp_connection_node->origin, tmp_connection_node-> id, tmp_connection_node->rhost_rport);
						}
					}

					if(cur_proxy_node->type == PROXY_LOCAL){

						count = strlen(cur_proxy_node->rhost_rport);
						if((tmp_connection_node->rhost_rport = (char *) calloc(count + 1, sizeof(char))) == NULL){
							print_error(io, "%s: %d: calloc(%d, %d): %s\n", \
									program_invocation_short_name, io->controller, \
									count + 1, (int) sizeof(char), \
									strerror(errno));
							goto CLEAN_UP;
						}
						memcpy(tmp_connection_node->rhost_rport, cur_proxy_node, count);

					}

					// This case should only fire if it's PROXY_LOCAL or PROXY_DYNAMIC after a full negotiation.
					if(tmp_connection_node->rhost_rport){

						fprintf(stderr, "DEBUG: (%d|%d): DT_PROXY_HT_CREATE 1: rhost_rport: %s\r\n", tmp_connection_node->origin, tmp_connection_node-> id, tmp_connection_node->rhost_rport);
						message->data_type = DT_PROXY;
						message->header_type = DT_PROXY_HT_CREATE;
						message->header_origin = tmp_connection_node->origin;
						message->header_id = tmp_connection_node->id;

						memset(message->data, '\0', message->data_size);
						count = strlen(tmp_connection_node->rhost_rport);
						count += 2; // account for the ver and cmd to be sent first.
						count = count < message->data_size ? count : message->data_size;
						*(message->data) = tmp_connection_node->ver;
						*(message->data + 1) = tmp_connection_node->cmd;
						memcpy(message->data + 2, tmp_connection_node->rhost_rport, count - 2);
						message->data_len = count;


						if((retval = message_push(io)) == -1){
							if(verbose){
								fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
										program_invocation_short_name, io->controller, \
										(unsigned long) io, \
										strerror(errno));
							}
							goto CLEAN_UP;
						}	
					}

					break;
				}

				cur_proxy_node = cur_proxy_node->next;		
			}

			// Wasn't a socks listener. Let's try the connections.
			tmp_connection_node = io->connection_head;
			while(tmp_connection_node){

				if(FD_ISSET(tmp_connection_node->fd, &fd_select)){
					fprintf(stderr, "DEBUG: FD_ISSET: tmp_connection_node->fd: %d\r\n", tmp_connection_node->fd);

					if(tmp_connection_node->rhost_rport){
						message->data_type = DT_CONNECTION;
						message->header_origin = tmp_connection_node->origin;
						message->header_id = tmp_connection_node->id;

						// XXX fix the error checking and report. 
						if((retval = read(tmp_connection_node->fd, message->data, message->data_size)) < 1){
							if(retval){
								print_error(io, "%s: %d: read(%d, %lx, %d): %s\n", \
										program_invocation_short_name, io->controller, \
										io->local_in_fd, (unsigned long) message->data, message->data_size, \
										strerror(errno));
							}
							message->data_type = DT_PROXY;
							message->header_type = DT_PROXY_HT_DESTROY;
							message->header_errno = errno;
							connection_node_delete(tmp_connection_node->origin, tmp_connection_node->id, &(io->connection_head));
						}

						message->data_len = retval;
						if((retval = message_push(io)) == -1){
							if(verbose){
								fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
										program_invocation_short_name, io->controller, \
										(unsigned long) io, \
										strerror(errno));
							}
							goto CLEAN_UP;
						}
					}else{
						// Socks connection, not finished initializing.

						if((retval = read(tmp_connection_node->fd, tmp_connection_node->socks_buffer_ptr, MAX_SOCKS_BUFFER_SIZE)) == -1){
							if(verbose){
								fprintf(stderr, "%s: %d: read(%d, %lx, %d): %s\n", \
										program_invocation_short_name, io->controller, \
										tmp_connection_node->fd, (unsigned long) tmp_connection_node->socks_buffer_head, MAX_SOCKS_BUFFER_SIZE, \
										strerror(errno));
							}
							goto CLEAN_UP;
						}
						tmp_connection_node->socks_buffer_ptr = tmp_connection_node->socks_buffer_ptr + retval;

						if(!retval){
							connection_node_delete(tmp_connection_node->origin, tmp_connection_node->id, &(io->connection_head));
							break;
						}

						if((retval = parse_socks_request(tmp_connection_node)) == -1){
							if(verbose){
								fprintf(stderr, "%s: %d: parse_sock_request(%lx): Malformed SOCKS request.\n", \
										program_invocation_short_name, io->controller, \
										(unsigned long) tmp_connection_node);
							}
							connection_node_delete(tmp_connection_node->origin, tmp_connection_node->id, &(io->connection_head));
							break;
						}

						if(retval == SOCKS_V5_AUTH){
							tmp_connection_node->socks_flag = retval;

							tmp_connection_node->socks_buffer_head[0] = 0x05;
							tmp_connection_node->socks_buffer_head[1] = tmp_connection_node->auth_method;
							tmp_connection_node->socks_buffer_ptr = tmp_connection_node->socks_buffer_head;

							if((retval = write(tmp_connection_node->fd, tmp_connection_node->socks_buffer_ptr, 2)) == -1){
								if(verbose){
									fprintf(stderr, "%s: %d: read(%d, %lx, %d): %s\n", \
											program_invocation_short_name, io->controller, \
											tmp_connection_node->fd, (unsigned long) tmp_connection_node->socks_buffer_head, MAX_SOCKS_BUFFER_SIZE, \
											strerror(errno));
								}
								goto CLEAN_UP;
							}

							if(tmp_connection_node->auth_method == 0xff){
								connection_node_delete(tmp_connection_node->origin, tmp_connection_node->id, &(io->connection_head));
							}

						}else if(retval == SOCKS_V4_COMPLETE || retval == SOCKS_V4A_COMPLETE || retval == SOCKS_V5_COMPLETE){
							tmp_connection_node->socks_flag = retval;

							fprintf(stderr, "DEBUG: (%d|%d): ver: %d\r\n", tmp_connection_node->origin, tmp_connection_node-> id, (int) tmp_connection_node->ver);
							fprintf(stderr, "DEBUG: (%d|%d): cmd: %d\r\n", tmp_connection_node->origin, tmp_connection_node-> id, (int) tmp_connection_node->cmd);
							fprintf(stderr, "DEBUG: (%d|%d): rhost_rport: %s\r\n", tmp_connection_node->origin, tmp_connection_node-> id, tmp_connection_node->rhost_rport);
						}


						if(tmp_connection_node->rhost_rport){

							fprintf(stderr, "DEBUG: (%d|%d): DT_PROXY_HT_CREATE 2: rhost_rport: %s\r\n", tmp_connection_node->origin, tmp_connection_node-> id, tmp_connection_node->rhost_rport);
							message->data_type = DT_PROXY;
							message->header_type = DT_PROXY_HT_CREATE;
							message->header_origin = tmp_connection_node->origin;
							message->header_id = tmp_connection_node->id;

							memset(message->data, '\0', message->data_size);
							count = strlen(tmp_connection_node->rhost_rport);
							count += 2; // account for the ver and cmd to be sent first.
							count = count < message->data_size ? count : message->data_size;
							*(message->data) = tmp_connection_node->ver;
							*(message->data + 1) = tmp_connection_node->cmd;
							memcpy(message->data + 2, tmp_connection_node->rhost_rport, count - 2);
							message->data_len = count;


							if((retval = message_push(io)) == -1){
								if(verbose){
									fprintf(stderr, "%s: %d: message_push(%lx): %s\n", \
											program_invocation_short_name, io->controller, \
											(unsigned long) io, \
											strerror(errno));
								}
								goto CLEAN_UP;
							}
						}
					}

					break;
				}

				tmp_connection_node = tmp_connection_node->next;
			}
		}
	}

	print_error(io, "%s: %d: broker(): while(1): Should not be here!\r\n", \
			program_invocation_short_name, io->controller);
	retval = -1;

CLEAN_UP:
	free(tty_winsize);

	return(retval);
}



/***********************************************************************************************************************
 * 
 * signal_handler()
 *
 * Input: The signal being handled.
 * Output: None. 
 * 
 * Purpose: To handle signals! For best effort at avoiding race conditions, we simply mark that the signal was found
 *	and return. This allows the broker() select() call to manage signal generating events.
 * 
 **********************************************************************************************************************/
void signal_handler(int signal){
	sig_found = signal;
}
