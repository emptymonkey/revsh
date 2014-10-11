
#include "common.h"

volatile sig_atomic_t sig_found = 0;


/*******************************************************************************
 *
 * broker()
 *
 * Input: A pointer to our remote_io_helper object.
 * Output: 0 for EOF, -1 for errors.
 *
 * Purpose: Broker data between the terminal and the network socket. Do the 
 *	right thing when encountering a window resize event.
 *
 ******************************************************************************/
int broker(struct remote_io_helper *io){

	int retval = -1;
	fd_set fd_select;
	int io_bytes, fd_max;

	int buff_len;

	/* A buffer to hold what comes in from the terminal. */
	char *local_buff_head = NULL;
	char *local_buff_ptr = NULL;
	char *local_buff_tail = NULL;

	/*  A buffer to hold what comes in from the socket. */
	char *remote_buff_head = NULL;
	char *remote_buff_ptr = NULL;
	char *remote_buff_tail = NULL;


	/*  APC (0x9f) and ST (0x9c) are 8 bit control characters. */
	/*  We will be using APC here as the start of an in-band signalling event, */
	/*  and ST to mark it's end. We will do this in a UTF-8 friendly way. As such, */
	/*  The opening sequence will be '0xc2 0x9f'. The closing sequence will be */
	/*  '0xc2 0x9c'.  */
	/*   */
	/*  Note: We don't bother with the UTF8_HIGH character for the signalling done */
	/*  before entering the broker() function because there is no user generated */
	/*  data until now. */
	char *event_ptr = NULL;

	struct sigaction act;
	int current_sig;

	struct winsize tty_winsize;
	int winsize_buff_len;
	char *winsize_buff_head = NULL, *winsize_buff_tail;
	char **winsize_vec;
	int sig_pid;

	char tmp_char;

	int state_counter;

	int fcntl_flags;

	int ssl_bytes_pending = 0;


	/*  Prepare our signal handler. */
	if(io->controller){
		memset(&act, 0, sizeof(act));
		act.sa_handler = signal_handler;

		if((retval = sigaction(SIGWINCH, &act, NULL)) == -1){
			print_error(io, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
					program_invocation_short_name, io->controller, \
					SIGWINCH, (unsigned long) &act, NULL, strerror(errno));
			goto CLEAN_UP;
		}
	}


	/*  Prepare our buffers. */
	buff_len = getpagesize();

	if((local_buff_head = (char *) calloc(buff_len, sizeof(char))) == NULL){
		print_error(io, "%s: %d: calloc(%d, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				buff_len, (int) sizeof(char));
		retval = -1;
		goto CLEAN_UP;
	}

	if((remote_buff_head = (char *) calloc(buff_len, sizeof(char))) == NULL){
		print_error(io, "%s: %d: calloc(%d, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				buff_len, (int) sizeof(char));
		retval = -1;
		goto CLEAN_UP;
	}


	/*  Also prepare one buffer specifically for dealing with serialization */
	/*  and transmission / receipt of a struct winsize. */
	winsize_buff_len = WINSIZE_BUFF_LEN;
	if((winsize_buff_head = (char *) calloc(winsize_buff_len, sizeof(char))) == NULL){
		print_error(io, "%s: %d: calloc(%d, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				winsize_buff_len, (int) sizeof(char));
		retval = -1;
		goto CLEAN_UP;
	}


	/*  Time to set our socket non-blocking. */
	if((fcntl_flags = fcntl(io->remote_fd, F_GETFL, 0)) == -1){
		print_error(io, "%s: %d: fcntl(%d, FGETFL, 0): %s\r\n", \
				program_invocation_short_name, io->controller, \
				io->remote_fd, strerror(errno));
		retval = -1;
		goto CLEAN_UP;
	}

	fcntl_flags |= O_NONBLOCK;
	if((retval = fcntl(io->remote_fd, F_SETFL, fcntl_flags)) == -1){
		print_error(io, "%s: %d: fcntl(%d, FGETFL, %d): %s\r\n", \
				program_invocation_short_name, io->controller, \
				io->remote_fd, fcntl_flags, strerror(errno));
		retval = -1;
		goto CLEAN_UP;
	}


	/*  Set the proper initial state of our buffer pointers. */
	local_buff_tail = local_buff_head;
	local_buff_ptr = local_buff_head;
	remote_buff_tail = remote_buff_head;
	remote_buff_ptr = remote_buff_head;


	/*  Start the broker() loop. */
	while(1){

		/*  Attempt to empty the local buffer into the socket. We don't need */
		/*  to empty the remote buffer. It isn't a concern because it will be */
		/*  emptied when it is filled. (Keep in min that the remote buffer is */
		/*  being emptied into a blocking fd, and is a much simpler case.) */
		if(local_buff_ptr != local_buff_tail){

			FD_ZERO(&fd_select);
			FD_SET(io->remote_fd, &fd_select);

			if(((retval = select(io->remote_fd + 1, NULL, &fd_select, NULL, NULL)) == -1) \
					&& !sig_found){
				print_error(io, \
						"%s: %d: broker(): select(%d, NULL, %lx, NULL, NULL): %s\r\n", \
						program_invocation_short_name, io->controller, io->remote_fd + 1, \
						(unsigned long) &fd_select, strerror(errno));
				goto CLEAN_UP;
			}

			if(FD_ISSET(io->remote_fd, &fd_select)){
				if((retval = io->remote_write(io, local_buff_ptr, (local_buff_tail - local_buff_ptr))) == -1){
					print_error(io, "%s: %d: broker(): io->remote_write(%lx, %lx, %d): %s\r\n", \
							program_invocation_short_name, io->controller, \
							(unsigned long) io, (unsigned long) local_buff_ptr, (local_buff_tail - local_buff_ptr), strerror(errno));
					goto CLEAN_UP;
				}
				local_buff_ptr += retval;
			}

			/*  If the local buffer is empty, then we should try to fill the buffers. */
		}else{

			if(io->encryption){
				ssl_bytes_pending = SSL_pending(io->ssl);
			}

			if(!ssl_bytes_pending){
				FD_ZERO(&fd_select);
				FD_SET(io->local_fd, &fd_select);
				FD_SET(io->remote_fd, &fd_select);

				fd_max = (io->local_fd > io->remote_fd) ? io->local_fd : io->remote_fd;

				if(((retval = select(fd_max + 1, &fd_select, NULL, NULL, NULL)) == -1) \
						&& !sig_found){
					print_error(io, \
							"%s: %d: broker(): select(%d, %lx, NULL, NULL, NULL): %s\r\n", \
							program_invocation_short_name, io->controller, fd_max + 1, \
							(unsigned long) &fd_select, strerror(errno));
					goto CLEAN_UP;
				}
			}

			/*  Case 1: select() was interrupted by a signal that we handle. */
			if(sig_found){

				local_buff_tail = local_buff_head;
				local_buff_ptr = local_buff_head;

				current_sig = sig_found;
				sig_found = 0;

				/*  I am leaving this as a switch() statement in case I decide to */
				/*  handle more signals later on. */
				switch(current_sig){

					case SIGWINCH:
						if((retval = ioctl(io->local_fd, TIOCGWINSZ, &tty_winsize)) == -1){
							print_error(io, "%s: %d: ioctl(%d, TIOCGWINSZ, %lx): %s\r\n", \
									program_invocation_short_name, io->controller, \
									io->local_fd, (unsigned long) &tty_winsize, strerror(errno));
							goto CLEAN_UP;
						}

						if((io_bytes = snprintf(local_buff_head, buff_len, \
										"%c%c%hd %hd%c%c", (char) UTF8_HIGH, (char) APC, tty_winsize.ws_row, \
										tty_winsize.ws_col, (char) UTF8_HIGH, (char) ST)) < 0){
							print_error(io, \
									"%s: %d: snprintf(%lx, %d, \"%%c%%hd %%hd%%c\", APC, %hd, %hd, ST): %s\r\n", \
									program_invocation_short_name, io->controller, \
									(unsigned long) local_buff_head, buff_len, \
									tty_winsize.ws_row, tty_winsize.ws_col, strerror(errno));
							retval = -1;
							goto CLEAN_UP;
						}

						local_buff_tail = local_buff_head + io_bytes;
						break;

					default:
						print_error(io, "%s: %d: broker(): Undefined signal found: %d\r\n", \
								program_invocation_short_name, io->controller, current_sig);
						retval = -1;
						goto CLEAN_UP;
				}
				current_sig = 0;


				/*  Case 2: Data is ready on the local fd. */
			}else if(FD_ISSET(io->local_fd, &fd_select)){
				local_buff_tail = local_buff_head;
				local_buff_ptr = local_buff_head;

				if((io_bytes = read(io->local_fd, local_buff_head, buff_len)) == -1){
					if(!io->controller && errno == EIO){
						goto CLEAN_UP;
					}
					print_error(io, "%s: %d: broker(): read(%d, %lx, %d): %s\r\n", \
							program_invocation_short_name, io->controller, \
							io->local_fd, (unsigned long) local_buff_head, buff_len, strerror(errno));
					retval = -1;
					goto CLEAN_UP;
				}

				if(!io_bytes){
					retval = 0;
					goto CLEAN_UP;
				}
				local_buff_tail = local_buff_head + io_bytes;


				/*  Case 3: Data is ready on the remote fd. */
			}else if(FD_ISSET(io->remote_fd, &fd_select) || ssl_bytes_pending){

				ssl_bytes_pending = 0;

				remote_buff_tail = remote_buff_head;
				remote_buff_ptr = remote_buff_head;

				if((io_bytes = io->remote_read(io, remote_buff_head, buff_len)) == -1){
					print_error(io, "%s: %d: broker(): io->remote_read(%lx, %lx, %d): %s\r\n", \
							program_invocation_short_name, io->controller, \
							(unsigned long) io, (unsigned long) remote_buff_head, buff_len, strerror(errno));
					retval = -1;
					goto CLEAN_UP;
				}

				if(!io_bytes){
					retval = 0;
					goto CLEAN_UP;
				}
				remote_buff_tail = remote_buff_head + io_bytes;

				if(!io->controller){
					event_ptr = NULL;
					while(remote_buff_ptr != remote_buff_tail){
						if(*remote_buff_ptr == (char) UTF8_HIGH){
							event_ptr = remote_buff_ptr;
							break;
						}
						remote_buff_ptr++;
					}
					remote_buff_ptr = remote_buff_head;
				}

				/*  We may have found the begining of a signalling event. */
				if(!io->controller && event_ptr){

					/*  First, clear out any data that preceeds the possible event. */
					while(remote_buff_ptr != event_ptr){
						if((retval = write(io->local_fd, remote_buff_ptr, (event_ptr - remote_buff_ptr))) == -1){
							print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
									program_invocation_short_name, io->controller, \
									io->local_fd, (unsigned long) remote_buff_ptr, (event_ptr - remote_buff_ptr), strerror(errno));
							goto CLEAN_UP;
						}
						remote_buff_ptr += retval;
					}

					/*  At this point, either buff_head is pointing to unused space or it matches event_ptr and is already UTF8_HIGH. */
					/*  Either way, lets put UTF8_HIGH in at buff_head[0] so we can reference it later. */
					*remote_buff_head = (char) UTF8_HIGH;

					/*  Setup the state counter. */
					state_counter = APC_HIGH_FOUND;

					/*  Get the winsize data structures ready. */
					memset(winsize_buff_head, 0, winsize_buff_len);
					winsize_buff_tail = winsize_buff_head;

					/*  Now we will enter an event handler loop. It's a state machine that */
					/*  keeps track of our progress throught the event. */
					event_ptr++;
					while(state_counter || (event_ptr != remote_buff_tail)){


						/*  Grab the next character by whatever means are appropriate. */
						if(event_ptr != remote_buff_tail){
							tmp_char = *(event_ptr++);
						}else{

							/*  Our buffer is empty, so read() the next char. */
							FD_ZERO(&fd_select);
							FD_SET(io->remote_fd, &fd_select);

							if(((retval = select(io->remote_fd + 1, &fd_select, NULL, NULL, NULL)) == -1)){
								print_error(io, \
										"%s: %d: broker(): select(%d, %lx, NULL, NULL, NULL): %s\r\n", \
										program_invocation_short_name, io->controller, io->remote_fd + 1, \
										(unsigned long) &fd_select, strerror(errno));
								goto CLEAN_UP;
							}

							if(!FD_ISSET(io->remote_fd, &fd_select)){
								print_error(io, \
										"%s: %d: broker(): FD_ISSET(%d, %lx): select() returned, but no data found.\r\n", \
										program_invocation_short_name, io->controller, io->remote_fd, \
										(unsigned long) &fd_select);
								goto CLEAN_UP;
							}

							if((retval = io->remote_read(io, &tmp_char, 1)) == -1){
								print_error(io, "%s: %d: io->remote_read(%lx, %lx, %d): %s\r\n", \
										program_invocation_short_name, io->controller, \
										(unsigned long) io, (unsigned long) &tmp_char, 1, strerror(errno));
								retval = -1;
								goto CLEAN_UP;
							}

							if(!retval){
								continue;
							}
						}

						/*  Examine the new char and change state as appropriate. */
						switch(state_counter){


							/*  In this case we have found the opening APC_HIGH, but it wasn't related to an event. */
							/*  Further, the buffer isn't empty. Consume the data, one char at a time, and make sure */
							/*  we don't find another event. */
							case NO_EVENT:

								if(tmp_char == (char) UTF8_HIGH){
									state_counter = APC_HIGH_FOUND;
								}else{

									while((retval = write(io->local_fd, &tmp_char, 1)) < 1){
										if(retval == -1){
											print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
													program_invocation_short_name, io->controller, \
													io->local_fd, (unsigned long) &tmp_char, 1, strerror(errno));
											goto CLEAN_UP;
										}
									}
								}

								break;


								/*  In this case we are checking to ensure that this actually is in an event. */
							case APC_HIGH_FOUND:

								if(tmp_char == (char) APC){
									state_counter = DATA_FOUND;
								}else{

									/*  Damn you unicode!!! This isn't really an event. */
									state_counter = NO_EVENT;

									/*  Remember that UTF8_HIGH we stored at buff_head[0] earlier? */
									/*  This is where we'll use it. */
									while((retval = write(io->local_fd, &tmp_char, 1)) < 1){
										if(retval == -1){
											print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
													program_invocation_short_name, io->controller, \
													io->local_fd, (unsigned long) UTF8_HIGH, 1, strerror(errno));
											goto CLEAN_UP;
										}
									}

									/*  Flush the buffer before returning to the normal loop. */
									while((retval = write(io->local_fd, &tmp_char, 1)) < 1){
										if(retval == -1){
											print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
													program_invocation_short_name, io->controller, \
													io->local_fd, (unsigned long) &tmp_char, 1, strerror(errno));
											goto CLEAN_UP;
										}
									}
								}

								break;

							/*  In this case, we will process the event data, adding it to the winsize  */
							/*  data structure. */
							case DATA_FOUND:

								if(tmp_char == (char) UTF8_HIGH){
									state_counter = ST_HIGH_FOUND;
								}else{
									*(winsize_buff_tail++) = tmp_char;

									if((winsize_buff_tail - winsize_buff_head) > winsize_buff_len){

										print_error(io, \
												"%s: %d: broker(): switch(%d): winsize_buff overflow.\r\n", \
												program_invocation_short_name, io->controller, state_counter);
										retval = -1;
										goto CLEAN_UP;
									}
								}

								break;


								/*  In this case we will close out the event and send the signal to the local  */
								/*  terminal. */
							case ST_HIGH_FOUND:

								if(tmp_char == (char) ST){

									state_counter = NO_EVENT;

									/*  Should have the winsize data by this point, so consume it and  */
									/*  signal the foreground process group. */
									if((winsize_vec = string_to_vector(winsize_buff_head)) == NULL){
										print_error(io, "%s: %d: broker(): string_to_vector(%s): %s\r\n", \
												program_invocation_short_name, io->controller, \
												winsize_buff_head, strerror(errno));
										retval = -1;
										goto CLEAN_UP;
									}

									if(winsize_vec[0] == NULL){
										print_error(io, \
												"%s: %d: invalid initialization: tty_winsize.ws_row\r\n", \
												program_invocation_short_name, io->controller);
										retval = -1;
										goto CLEAN_UP;
									}

									errno = 0;
									tty_winsize.ws_row = (short) strtol(winsize_vec[0], NULL, 10);
									if(errno){
										print_error(io, "%s: %d: strtol(%s): %s\r\n", \
												program_invocation_short_name, io->controller, \
												winsize_vec[0], strerror(errno));
										retval = -1;
										goto CLEAN_UP;
									}

									if(winsize_vec[1] == NULL){
										print_error(io, \
												"%s: %d: invalid initialization: tty_winsize.ws_col\r\n", \
												program_invocation_short_name, io->controller);
										retval = -1;
										goto CLEAN_UP;
									}

									errno = 0;
									tty_winsize.ws_col = (short) strtol(winsize_vec[1], NULL, 10);
									if(errno){
										print_error(io, "%s: %d: strtol(%s): %s\r\n", \
												program_invocation_short_name, io->controller, \
												winsize_vec[1], strerror(errno));
										retval = -1;
										goto CLEAN_UP;
									}

									if((retval = ioctl(io->local_fd, TIOCSWINSZ, &tty_winsize)) == -1){
										print_error(io, "%s: %d: ioctl(%d, %d, %lx): %s\r\n", \
												program_invocation_short_name, io->controller, \
												io->local_fd, TIOCGWINSZ, (unsigned long) &tty_winsize, \
												strerror(errno));
										goto CLEAN_UP;
									}

									if((sig_pid = tcgetsid(io->local_fd)) == -1){
										print_error(io, "%s: %d: tcgetsid(%d): %s\r\n", \
												program_invocation_short_name, io->controller, \
												io->local_fd, strerror(errno));
										retval = -1;
										goto CLEAN_UP;
									}

									if((retval = kill(-sig_pid, SIGWINCH)) == -1){
										print_error(io, "%s: %d: kill(%d, %d): %s\r\n", \
												program_invocation_short_name, io->controller, \
												-sig_pid, SIGWINCH, strerror(errno));
										goto CLEAN_UP;
									}

								}else{

									/*  The winsize data is encoded as ascii. It should never come across as UTF8_HIGH. */
									/*  As such, this case will always be an error. */
									print_error(io, \
											"%s: %d: broker(): switch(%d): high closing byte found w/out low closing byte. Should not be here!\r\n", \
											program_invocation_short_name, io->controller, state_counter);
									retval = -1;
									goto CLEAN_UP;
								}

								break;


							/*  The case of no case. This should be unreachable. */
							default:

								print_error(io, \
										"%s: %d: broker(): switch(%d): unknown state. Should not be here!\r\n", \
										program_invocation_short_name, io->controller, state_counter);
								retval = -1;
								goto CLEAN_UP;
						}

					}

				}else{

					/*  Flush the remote buffer to the terminal. */
					while(remote_buff_ptr != remote_buff_tail){
						if((retval = write(io->local_fd, remote_buff_head, (remote_buff_tail - remote_buff_ptr))) == -1){
							print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
									program_invocation_short_name, io->controller, \
									io->local_fd, (unsigned long) remote_buff_head, (remote_buff_tail - remote_buff_ptr), strerror(errno));
							goto CLEAN_UP;
						}
						remote_buff_ptr += retval;
					}
				}
			}
		}
	}

	print_error(io, "%s: %d: broker(): while(1): Should not be here!\r\n", \
			program_invocation_short_name, io->controller);
	retval = -1;

CLEAN_UP:
	free(local_buff_head);
	free(remote_buff_head);
	free(winsize_buff_head);
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

