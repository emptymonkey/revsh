
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
	int count;

	struct message_helper *message;


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

						if((sig_pid = tcgetsid(io->local_out_fd)) == -1){
							print_error(io, "%s: %d: tcgetsid(%d): %s\n", \
									program_invocation_short_name, io->controller, \
									io->local_out_fd, \
									strerror(errno));
							retval = -1;
							goto CLEAN_UP;
						}

						if((retval = kill(-sig_pid, SIGWINCH)) == -1){
							print_error(io, "%s: %d: kill(%d, SIGWINCH): %s\n", \
									program_invocation_short_name, io->controller, \
									-sig_pid, \
									strerror(errno));
							goto CLEAN_UP;
						}
					}

					break;

					/* Ignore anything malformed. */
				default:
					break;

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
