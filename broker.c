
#include "common.h"

volatile sig_atomic_t sig_found = 0;


/*******************************************************************************
 *
 * broker()
 *
 * Input: A pointer to our io_helper object.
 * Output: 0 for EOF, -1 for errors.
 *
 * Purpose: Broker data between the terminal and the network socket. Do the 
 *	right thing when encountering a window resize event.
 *
 ******************************************************************************/
int broker(struct io_helper *io, struct config_helper *config){

	int retval = -1;
	fd_set fd_select;
	int io_bytes, fd_max;

	struct sigaction act;
	int current_sig;

	struct winsize *tty_winsize = NULL;
	pid_t sig_pid = 0;

	char *tmp_ptr;
	int count;

	struct message_helper *message;

	message = &io->message;

	/*  Prepare our signal handler. */
	if(config->interactive){

		if(io->controller){
			memset(&act, 0, sizeof(act));
			act.sa_handler = signal_handler;

			if((retval = sigaction(SIGWINCH, &act, NULL)) == -1){
				return(-1);
			}
		}

		/*  Also prepare one buffer specifically for dealing with serialization */
		/*  and transmission / receipt of a struct winsize. */
		if((tty_winsize = (struct winsize *) calloc(1, sizeof(struct winsize))) == NULL){
			return(-1);
		}
	}


	/*  Start the broker() loop. */
	while(1){

		FD_ZERO(&fd_select);
		FD_SET(io->local_in_fd, &fd_select);
		FD_SET(io->remote_fd, &fd_select);

		fd_max = (io->local_in_fd > io->remote_fd) ? io->local_in_fd : io->remote_fd;

		if(((retval = select(fd_max + 1, &fd_select, NULL, NULL, NULL)) == -1) \
				&& !sig_found){
			goto CLEAN_UP;
		}

		/*  Case 1: select() was interrupted by a signal that we handle. */
		if(sig_found){
			//			fprintf(stderr, "DEBUG: Case 1\r\n");

			current_sig = sig_found;
			sig_found = 0;

			if(config->interactive && io->controller){

				/*  I am leaving this as a switch() statement in case I decide to */
				/*  handle more signals later on. */
				switch(current_sig){

					case SIGWINCH:
						if((retval = ioctl(io->local_out_fd, TIOCGWINSZ, tty_winsize)) == -1){
							goto CLEAN_UP;
						}

						message->data_type = DT_WINRESIZE;

						*((unsigned short *) message->data) = htons(tty_winsize->ws_row);
						message->data_len = sizeof(tty_winsize->ws_row);
						*((unsigned short *) (message->data + message->data_len)) = htons(tty_winsize->ws_col);
						message->data_len += sizeof(tty_winsize->ws_col);

						if((retval = message_push(io)) == -1){
							goto CLEAN_UP;
						}

						break;
				}
			}

			/*  Case 2: Data is ready on the local fd. */
		}else if(FD_ISSET(io->local_in_fd, &fd_select)){
			//			fprintf(stderr, "DEBUG: Case 2\r\n");

			message->data_type = DT_TTY;

			if((retval = read(io->local_in_fd, message->data, message->data_size)) == -1){

				if(errno != EINTR){
					if(errno == EIO){
						retval = 0;
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
						goto CLEAN_UP;
					}

				}
			}

			/*  Case 3: Data is ready on the remote fd. */
		}else if(FD_ISSET(io->remote_fd, &fd_select)){
			//			fprintf(stderr, "DEBUG: Case 3\r\n");

			if((retval = message_pull(io)) == -1){
				goto CLEAN_UP;
			}

			switch(message->data_type){

				/* Will handle the DT_ERR case the same as the DT_TTY case, but return an error. */
				case DT_TTY:

					io_bytes = 0;
					tmp_ptr = message->data;
					count = message->data_len;

					while(count){
						retval = write(io->local_out_fd, tmp_ptr, count);

						if(retval == -1){
							if(errno != EINTR){
								goto CLEAN_UP;
							}

						}else{

							count -= retval;
							io_bytes += retval;
							tmp_ptr += retval;

						}
					}

					break;


				case DT_WINRESIZE:

					if(!io->controller){

						if(message->data_len != sizeof(tty_winsize->ws_row) + sizeof(tty_winsize->ws_col)){
							fprintf(stderr, "%s: %d: DT_WINRESIZE termios: not enough data!\r\n", \
									program_invocation_short_name, io->controller);
							return(-1);
						}

						tty_winsize->ws_row = ntohs(*((unsigned short *) message->data));
						tty_winsize->ws_col = ntohs(*((unsigned short *) (message->data + sizeof(unsigned short))));

						if((retval = ioctl(io->local_out_fd, TIOCSWINSZ, tty_winsize)) == -1){
							goto CLEAN_UP;
						}

						if((sig_pid = tcgetsid(io->local_out_fd)) == -1){
							retval = -1;
							goto CLEAN_UP;
						}

						if((retval = kill(-sig_pid, SIGWINCH)) == -1){
							goto CLEAN_UP;
						}
					}

					break;

				default:
					print_error(io, "%s: %d: broker: Undefined data type found: %d\r\n", \
							program_invocation_short_name, io->controller, message->data_type);
					retval = -1;
					goto CLEAN_UP;

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



/*******************************************************************************
 * 
 * signal_handler()
 *
 * Input: The signal being handled.
 * Output: None. 
 * 
 * Purpose: To handle signals! For best effort at avoiding race conditions,
 *  we simply mark that the signal was found and return. This allows the
 *  broker() select() call to manage signal generating events.
 * 
 ******************************************************************************/
void signal_handler(int signal){
	sig_found = signal;
}
