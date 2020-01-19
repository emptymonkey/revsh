
#include "common.h"

extern sig_atomic_t sig_found;

/***********************************************************************************************************************
 *
 * broker()
 *
 * Input: None, but we will use the global io_helper and config_helper objects.
 * Output: 0 for EOF, -1 for errors. (-2's returned to us are interpreted as non-fatal errors.
 *         We will report and ignore.)
 *
 * Purpose: Broker data between the terminal / connections and the network socket. 
 *
 **********************************************************************************************************************/
int broker(){

	int retval = -1;
	int found;

	fd_set read_fds, write_fds;
	int fd_max;

	struct sigaction act;
	int current_sig;

	struct proxy_node *cur_proxy_node;
	struct connection_node *cur_connection_node;

	unsigned long tmp_ulong;
	struct timeval timeout, *timeout_ptr;

	struct proxy_request_node *cur_proxy_req_node;


	/* Skip this stuff if we're just transferring a file... */
	if(io->interactive){

		/* Set up the default proxies. */
		if(!io->target){

			if(config->socks){
				if((cur_proxy_node = proxy_node_new(config->socks, PROXY_DYNAMIC)) == NULL){
					report_error("do_control(): proxy_node_new(%s, %d): %s", config->socks, PROXY_DYNAMIC, strerror(errno));
				}
			}

			// Localhost point-to-point listeners on both ends, one each direction of communication
			// Allows for easier in-band asynchronous file transfers.
			if(config->local_forward){
				if((cur_proxy_node = proxy_node_new(config->local_forward, PROXY_STATIC)) == NULL){
					report_error("do_control(): proxy_node_new(%s, %d): %s", config->local_forward, PROXY_STATIC, strerror(errno));
				}

				if((retval = handle_send_dt_proxy_ht_create(config->local_forward, PROXY_STATIC)) < 0){
					report_error("broker(): handle_send_dt_proxy_ht_create(): %s", strerror(errno));
					if(retval == -1){
						return(-1);
					}
				}
			}
		}

		/* Set up proxies requested during launch. */
		cur_proxy_req_node = config->proxy_request_head;
		while(cur_proxy_req_node){

			if(cur_proxy_req_node->remote){
				if((retval = handle_send_dt_proxy_ht_create(cur_proxy_req_node->request_string, cur_proxy_req_node->type)) < 0){
					report_error("broker(): handle_send_dt_proxy_ht_create(): %s", strerror(errno));
					if(retval == -1){
						return(-1);
					}
				}
			}else{
				cur_proxy_node = proxy_node_new(cur_proxy_req_node->request_string, cur_proxy_req_node->type);

				if(!cur_proxy_node){
					report_error("do_control(): proxy_node_new(%s, %d): %s", cur_proxy_req_node->request_string, cur_proxy_req_node->type, strerror(errno));
				}else{
					if(io->target){
						if((retval = handle_send_dt_proxy_ht_report(cur_proxy_node)) == -1){
							report_error("broker(): handle_send_dt_proxy_ht_report(): %s", strerror(errno));
							return(-1);
						}
					}
				}
			}
			cur_proxy_req_node = cur_proxy_req_node->next;
		}

		/* Prepare for broker() loop signal handling. */
		memset(&act, 0, sizeof(act));
		act.sa_handler = signal_handler;

		if((retval = sigaction(SIGWINCH, &act, NULL)) == -1){
			report_error("broker(): sigaction(SIGWINCH, %lx, NULL): %s", (unsigned long) &act, strerror(errno));
			return(-1);
		}

		if((io->tty_winsize = (struct winsize *) calloc(1, sizeof(struct winsize))) == NULL){
			report_error("broker(): calloc(1, %d): %s", (int) sizeof(struct winsize), strerror(errno));
			return(-1);
		}

		/* Setup the TUN and TAP devices. Once setup, handle them as yet another connection in the connection_node linked list. */
#if !defined( FREEBSD) && !defined(SOLARIS)
		if(!io->target){
			if(config->tun){
				if((cur_connection_node = handle_tun_tap_init(IFF_TUN)) == NULL){
					report_error("broker(): handle_tun_tap_init(IFF_TUN): %s", strerror(errno));
				}else{
					if(handle_send_dt_connection_ht_create(cur_connection_node) == -1){
						report_error("broker(): handle_send_dt_connection_ht_create(%lx): %s", (unsigned long) cur_connection_node, strerror(errno));
						return(-1);
					}
				}
			}

			if(config->tap){
				if((cur_connection_node = handle_tun_tap_init(IFF_TAP)) == NULL){
					report_error("broker(): handle_tun_tap_init(IFF_TAP): %s", strerror(errno));
				}else{
					if(handle_send_dt_connection_ht_create(cur_connection_node) == -1){
						report_error("broker(): handle_send_dt_connection_ht_create(%lx): %s", (unsigned long) cur_connection_node, strerror(errno));
						return(-1);
					}
				}
			}
		}
#endif
	}

	timeout_ptr = NULL;
	if(config->nop){
		timeout_ptr = &timeout;
	}


	/*  Start the broker() loop. */
	while(1){

		/* Initialize fds we will want to select() on this loop. */
		fd_max = 0;
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);

		FD_SET(io->local_in_fd, &read_fds);
		fd_max = io->local_in_fd > fd_max ? io->local_in_fd : fd_max;

		if(io->tty_write_head){
			FD_SET(io->local_out_fd, &write_fds);
			fd_max = io->local_out_fd > fd_max ? io->local_out_fd : fd_max;
		}

		FD_SET(io->remote_fd, &read_fds);
		fd_max = io->remote_fd > fd_max ? io->remote_fd : fd_max;

		io->fd_count = 2;

		/* Add connections that are active. */
		cur_connection_node = io->connection_head;
		while((io->fd_count < FD_SETSIZE) && cur_connection_node){

			if(! ((cur_connection_node->state == CON_DORMANT) || (cur_connection_node->state == CON_EINPROGRESS))){
				FD_SET(cur_connection_node->fd, &read_fds);
				fd_max = cur_connection_node->fd > fd_max ? cur_connection_node->fd : fd_max;
			}

			if(cur_connection_node->write_head || cur_connection_node->state == CON_EINPROGRESS){
				FD_SET(cur_connection_node->fd, &write_fds);
				fd_max = cur_connection_node->fd > fd_max ? cur_connection_node->fd : fd_max;
			}

			cur_connection_node = cur_connection_node->next;
			io->fd_count++;
		}

		/* Only add proxy file descriptors to select() if we have enough space for more connections.  */
		cur_proxy_node = io->proxy_head;
		while((io->fd_count < FD_SETSIZE) && cur_proxy_node && (cur_proxy_node->origin == io->target)){

			FD_SET(cur_proxy_node->fd, &read_fds);
			fd_max = cur_proxy_node->fd > fd_max ? cur_proxy_node->fd : fd_max;

			cur_proxy_node = cur_proxy_node->next;
			io->fd_count++;
		}

		/* Setup keepalive nop timers. */
		if(config->nop){
			tmp_ulong = rand();
			timeout.tv_sec = config->retry_start + (tmp_ulong % (config->retry_stop - config->retry_start));
			timeout.tv_usec = 0;
		}

		if(((retval = select(fd_max + 1, &read_fds, &write_fds, NULL, timeout_ptr)) == -1) \
				&& !sig_found){
			report_error("broker(): select(%d, %lx, %lx, NULL, %lx): %s", \
					fd_max + 1, (unsigned long) &read_fds, (unsigned long) &write_fds, (unsigned long) timeout_ptr, strerror(errno));
			goto RETURN;
		}

		// First check if we timed out, in which case send a keepalive nop.
		if(!retval){
			if((retval = handle_send_dt_nop()) == -1){
				report_error("broker(): handle_send_dt_nop(): %s", strerror(errno));
				goto RETURN;
			}
		}

		// Handle signals. (We've handled multiple in the past. Right now, we only watch for sigwinch.)
		if(sig_found){

			current_sig = sig_found;
			sig_found = 0;

			if(io->interactive && !io->target){

				switch(current_sig){

					/* Gather and send the new window size. */
					case SIGWINCH:
						if((retval = handle_signal_sigwinch()) == -1){
							report_error("broker(): handle_signal_sigwinch(): %s", strerror(errno));
							goto RETURN;
						}
						break;
				}
			}

			continue;
		}

		// Local tty / shell fd will have priority over all the other connections.
		if(FD_ISSET(io->local_out_fd, &write_fds)){

			if((retval = handle_local_write()) == -1){
				goto RETURN;
			}
			continue;
		}

		if(FD_ISSET(io->local_in_fd, &read_fds)){
			retval = handle_local_read();
			if(retval < 0){
				if(retval == -1){
					report_error("broker(): handle_local_read(): %s", strerror(errno));
				}else{
					retval = 0;
				}
				goto RETURN;
			}
			if(io->eof){
				retval = 0;
				goto RETURN;
			}
			continue;
		}

		// Next in priority comes the message bus.
		if(FD_ISSET(io->remote_fd, &read_fds)){

			if((retval = message_pull()) == -1){
				if(io->eof){
					retval = 0;
				}else{
					report_error("broker(): message_pull(): %s", strerror(errno));
				}
				goto RETURN;
			}

			// What type of message did we just get?
			switch(message->data_type){

				case DT_TTY:

					if((retval = handle_message_dt_tty()) == -1){
						report_error("broker(): handle_message_dt_tty(): %s", strerror(errno));
						goto RETURN;
					}

					break;

				case DT_WINRESIZE:

					if(io->target){
						if((retval = handle_message_dt_winresize()) == -1){
							report_error("broker(): handle_message_dt_winresize(): %s", strerror(errno));
							goto RETURN;
						}
					}

					break;

				case DT_PROXY:

					if(message->header_type == DT_PROXY_HT_DESTROY){

						if((retval = handle_message_dt_proxy_ht_destroy()) == -1){
							report_error("broker(): handle_message_dt_proxy_ht_destroy(): %s", strerror(errno));
							goto RETURN;
						}

					}else if(message->header_type == DT_PROXY_HT_CREATE){

						if((retval = handle_message_dt_proxy_ht_create()) == -1){
							report_error("broker(): handle_message_dt_proxy_ht_create(): %s", strerror(errno));
							goto RETURN;
						}

					}else if(message->header_type == DT_PROXY_HT_REPORT){

						if((retval = handle_message_dt_proxy_ht_report()) == -1){
							report_error("broker(): handle_message_dt_proxy_ht_report(): %s", strerror(errno));
							goto RETURN;
						}

					}else{
						report_error("broker(): Unknown Proxy Header Type: %d: Ignoring.", message->header_type);
					}
					break;

				case DT_CONNECTION:

					if(message->header_type == DT_CONNECTION_HT_DESTROY){

						if((retval = handle_message_dt_connection_ht_destroy()) == -1){
							report_error("broker(): handle_message_dt_connection_ht_destroy(): %s", strerror(errno));
							goto RETURN;
						}

					}else if(message->header_type == DT_CONNECTION_HT_CREATE){

						if((retval = handle_message_dt_connection_ht_create()) == -1){
							report_error("broker(): handle_message_dt_connection_ht_create(): %s", strerror(errno));
							goto RETURN;
						}

					}else if(message->header_type == DT_CONNECTION_HT_DATA){

						if((retval = handle_message_dt_connection_ht_data()) == -1){
							report_error("broker(): handle_message_dt_connection_ht_data(): %s", strerror(errno));
							goto RETURN;
						}

					}else if(message->header_type == DT_CONNECTION_HT_ACTIVE || message->header_type == DT_CONNECTION_HT_DORMANT){

						if((retval = handle_message_dt_connection_ht_active_dormant()) == -1){
							report_error("broker(): handle_message_dt_connection_ht_active_dormant(): %s", strerror(errno));
							goto RETURN;
						}

					}else{
						// Unknown connection type. Report but soldier on.
						report_error("broker(): Unknown Connection Header Type: %d: Ignoring.", message->header_type);
					}
					break;

				case DT_NOP:
					// Cool story, bro.
					break;

				case DT_ERROR:
					if(!io->target){
						if((retval = report_log("Target Error: %s", message->data)) == -1){
							goto RETURN;
						}
					}
					break;

				default:
					// Unknown message type. Report but soldier on.
					report_error("broker(): Unknown message data type: %d: Ignoring.", message->header_type);
					break;
			}

			continue;
		}

		/* Check the proxy listeners for new connections. Handle if appropriate. */
		found = 0;
		cur_proxy_node = io->proxy_head;
		while(cur_proxy_node && (cur_proxy_node->origin == io->target)){

			if(FD_ISSET(cur_proxy_node->fd, &read_fds)){
				if((retval = handle_proxy_read(cur_proxy_node)) == -1){
					report_error("broker(): handle_proxy_read(%lx): %s", (unsigned long) cur_proxy_node, strerror(errno));
					goto RETURN;
				}

				found = 1;
				break;
			}

			cur_proxy_node = cur_proxy_node->next;
		}

		if(found){
			continue;
		}

		/* Check current connections for data / events. Handle if appropriate. */
		cur_connection_node = io->connection_head;
		while(cur_connection_node){

			if(FD_ISSET(cur_connection_node->fd, &write_fds)){

				if(cur_connection_node->state == CON_EINPROGRESS){
					if((retval = handle_connection_activate(cur_connection_node)) == -1){
						report_error("broker(): handle_connection_activate(%lx): %s", (unsigned long) cur_connection_node, strerror(errno));
						goto RETURN;
					}
				} else {
					if((retval = handle_connection_write(cur_connection_node)) == -1){
						report_error("broker(): handle_connection_write(%lx): %s", (unsigned long) cur_connection_node, strerror(errno));
						goto RETURN;
					}
				}

				break;
			}

			if(FD_ISSET(cur_connection_node->fd, &read_fds)){
				if(cur_connection_node->state == CON_ACTIVE){
					if((retval = handle_connection_read(cur_connection_node)) == -1){
						report_error("broker(): handle_connection_read(%lx): %s", (unsigned long) cur_connection_node, strerror(errno));
						goto RETURN;
					}
				}else if(cur_connection_node->state == CON_SOCKS_INIT || cur_connection_node->state == CON_SOCKS_V5_AUTH){
					if((retval = handle_connection_socks_init(cur_connection_node)) == -1){
						report_error("broker(): handle_connection_socks_init(%lx): %s", (unsigned long) cur_connection_node, strerror(errno));
						goto RETURN;
					}
				}

				if(retval == 0){
					connection_node_queue(cur_connection_node);
				}

				break;
			}

			cur_connection_node = cur_connection_node->next;
		}

	}

	report_error("broker(): while(1): Should not be here!");
	retval = -1;

RETURN:
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
 *          and return. This allows the broker() select() call to manage signal generating events.
 * 
 **********************************************************************************************************************/
void signal_handler(int signal){
	sig_found = signal;
}
