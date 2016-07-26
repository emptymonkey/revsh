
#include "common.h"

extern sig_atomic_t sig_found;


// XXX Write buffers are now in place to be filled.
// XXX
// XXX * Stress test with read()s and write()s set to 1 character at a time.


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
	int found;

	fd_set read_fds, write_fds;
	int fd_max;

	struct sigaction act;
	int current_sig;

	struct message_helper *message;

	struct proxy_node *cur_proxy_node;
	struct connection_node *cur_connection_node, *next_connection_node;
	
	unsigned long tmp_ulong;
	struct timeval timeout, *timeout_ptr;


	/* We use this as a shorthand to make message syntax more readable. */
	message = &io->message;

	if(config->interactive){

		/* Prepare for window resize event handling. */
		memset(&act, 0, sizeof(act));
		act.sa_handler = signal_handler;

		if((retval = sigaction(SIGWINCH, &act, NULL)) == -1){
			report_error(io, "%s: %d: sigaction(SIGWINCH, %lx, NULL): %s\n", \
					program_invocation_short_name, io->controller, \
					(unsigned long) &act, \
					strerror(errno));
			return(-1);
		}

		if((io->tty_winsize = (struct winsize *) calloc(1, sizeof(struct winsize))) == NULL){
			report_error(io, "%s: %d: calloc(1, %d): %s\n", \
					program_invocation_short_name, io->controller, \
					(int) sizeof(struct winsize), \
					strerror(errno));
			return(-1);
		}
	}

	io->fd_count = 2;
	cur_proxy_node = io->proxy_head;
	while(cur_proxy_node && io->fd_count < FD_SETSIZE){
		io->fd_count++;
		cur_proxy_node = cur_proxy_node->next;
	}

	timeout_ptr = NULL;
	if(config->nop){
		timeout_ptr = &timeout;
	}

	/*  Start the broker() loop. */
	while(1){

		fd_max = 0;
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);

		FD_SET(io->local_in_fd, &read_fds);
		fd_max = io->local_in_fd > fd_max ? io->local_in_fd : fd_max;

		FD_SET(io->remote_fd, &read_fds);
		fd_max = io->remote_fd > fd_max ? io->remote_fd : fd_max;

		/*
			 Only add proxy file descriptors to select() if we have enough space for more connections.
			 Skip the proxy listeners from the select() loop otherwise.
		 */
		if(io->fd_count < FD_SETSIZE){
			cur_proxy_node = io->proxy_head;
			while(cur_proxy_node){

				FD_SET(cur_proxy_node->fd, &read_fds);
				fd_max = cur_proxy_node->fd > fd_max ? cur_proxy_node->fd : fd_max;

				cur_proxy_node = cur_proxy_node->next;
			}
		}

		cur_connection_node = io->connection_head;
		while(cur_connection_node){

			if(cur_connection_node->state != CON_DORMANT){
				FD_SET(cur_connection_node->fd, &read_fds);
				fd_max = cur_connection_node->fd > fd_max ? cur_connection_node->fd : fd_max;
			}

			if(cur_connection_node->write_head){
				FD_SET(cur_connection_node->fd, &write_fds);
				fd_max = cur_connection_node->fd > fd_max ? cur_connection_node->fd : fd_max;
			}

			cur_connection_node = cur_connection_node->next;
		}

		if(config->nop){
			tmp_ulong = rand();
			timeout.tv_sec = config->retry_start + (tmp_ulong % (config->retry_stop - config->retry_start));
			timeout.tv_usec = 0;
		}

		if(((retval = select(fd_max + 1, &read_fds, &write_fds, NULL, timeout_ptr)) == -1) \
				&& !sig_found){
			report_error(io, "%s: %d: broker(): select(%d, %lx, %lx, NULL, %lx): %s\n", \
					program_invocation_short_name, io->controller, \
					fd_max + 1, (unsigned long) &read_fds, (unsigned long) &write_fds, \
					(unsigned long) timeout_ptr, \
					strerror(errno));
			goto CLEAN_UP;
		}

		if(!retval){
			if((retval = handle_send_nop(io)) == -1){
				// XXX report_error();
				goto CLEAN_UP;
			}
		}

		/* Determine which case we are in and call the appropriate handler. */

		if(sig_found){

			current_sig = sig_found;
			sig_found = 0;

			if(config->interactive && io->controller){

				/* I set this up as a switch statement because I think we will want to handle other signals down the road. */
				switch(current_sig){

					/* Gather and send the new window size. */
					case SIGWINCH:
						if((retval = handle_signal_sigwinch(io)) == -1){
							report_error(io, "%s: %d: handle_signal_sigwinch(%d): %s\n", \
									program_invocation_short_name, io->controller, \
									(unsigned long) io, strerror(errno));
							goto CLEAN_UP;
						}
						break;
				}
			}

			continue;
		}

		if(FD_ISSET(io->local_in_fd, &write_fds)){

			if((retval = handle_local_write(io)) == -1){
				goto CLEAN_UP;
			}

			continue;
		}

		if(FD_ISSET(io->local_in_fd, &read_fds)){

			retval = handle_local_read(io);

			if(retval < 0){
				if(retval == -2){
					retval = 0;
				}
				goto CLEAN_UP;
			}	

			continue;
		}

		if(FD_ISSET(io->remote_fd, &read_fds)){

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

					if((retval = handle_message_dt_tty(io)) == -1){
						goto CLEAN_UP;
					}

					break;

				case DT_WINRESIZE:

					if(!io->controller){
						if((retval = handle_message_dt_winresize(io)) == -1){
							goto CLEAN_UP;
						}
					}

					break;

				case DT_PROXY:

					if(message->header_type == DT_PROXY_HT_DESTROY){

						if((retval = handle_message_dt_proxy_ht_destroy(io)) == -1){
							goto CLEAN_UP;
						}

					}else if(message->header_type == DT_PROXY_HT_CREATE){

						retval = handle_message_dt_proxy_ht_create(io);

						if(retval == -1){
							goto CLEAN_UP;
						}

					}else if(message->header_type == DT_PROXY_HT_RESPONSE){

						if((retval = handle_message_dt_proxy_ht_response(io)) == -1){
							goto CLEAN_UP;
						}

					}else{
						// Malformed request.
						report_error(io, "%s: %d: Unknown Proxy Header Type: %d\n", \
								program_invocation_short_name, io->controller, \
								message->header_type);
						retval = -1;
						goto CLEAN_UP;
					}
					break;

				case DT_CONNECTION:

					if((retval = handle_message_dt_connection(io)) == -1){
						goto CLEAN_UP;
					}

					break;

				case DT_NOP:
						// Cool story, bro.
					break;

				case DT_ERROR:
					if(io->controller){
						if((retval = report_log(io, "Target Error: %s", message->data)) == -1){
							goto CLEAN_UP;
						}
					}
					break;

				default:
					// Malformed request.
					// XXX make this a non-fatal log entry.
					/*
						 report_error(io, "%s: %d: Unknown Proxy Header Type: %d\n", \
						 program_invocation_short_name, io->controller, \
						 message->header_type);
						 goto CLEAN_UP;
					 */
					break;
			}

			continue;
		}

		found = 0;
		cur_proxy_node = io->proxy_head;
		while(cur_proxy_node){

			if(FD_ISSET(cur_proxy_node->fd, &read_fds)){
				if((retval = handle_proxy_read(io, cur_proxy_node)) == -1){
					goto CLEAN_UP;
				}

				found = 1;
				break;
			}

			cur_proxy_node = cur_proxy_node->next;		
		}

		if(found){
			continue;
		}


		cur_connection_node = io->connection_head;
		while(cur_connection_node){

			// Advancing to the next node in the list now, in case cur_connection_node gets deleted in the processing of the loop.
			next_connection_node = cur_connection_node->next;

			if(FD_ISSET(cur_connection_node->fd, &write_fds)){
				if((retval = handle_connection_write(io, cur_connection_node)) == -1){
					goto CLEAN_UP;
				}

				break;
			}

			if(FD_ISSET(cur_connection_node->fd, &read_fds)){

				if((retval = handle_connection_read(io, cur_connection_node)) == -1){
					goto CLEAN_UP;
				}

				if(retval == 0){
					connection_node_queue(io, cur_connection_node);
				}

				break;
			}

			cur_connection_node = next_connection_node;
		}

	}

	report_error(io, "%s: %d: broker(): while(1): Should not be here!\r\n", \
			program_invocation_short_name, io->controller);
	retval = -1;

CLEAN_UP:

	// right now things are fatal at this point, so we're letting the kernel clean up our mallocs and close our sockets.

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
