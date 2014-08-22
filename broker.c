
#include "common.h"

volatile sig_atomic_t sig_found = 0;


/*******************************************************************************
 *
 * broker()
 *
 * Input: Two file descriptors. Also, an indication of whether or not we are a
 *  listener.
 * Output: 0 for EOF, -1 for errors.
 *
 * Purpose: Broker data between the two file descriptors. Also, handle some 
 *  signal events (e.g. SIGWINCH) with in-band signalling.
 *
 ******************************************************************************/
int broker(struct remote_io_helper *io){

	int retval = -1;
	fd_set fd_select;
	int io_bytes, fd_max;

	int buff_len;

	char *local_buff_head = NULL;
	char *local_buff_ptr = NULL;
	char *local_buff_tail = NULL;

	char *remote_buff_head = NULL;
	char *remote_buff_ptr = NULL;
	char *remote_buff_tail = NULL;


	// APC (0x9f) and ST (0x9c) are 8 bit control characters. These pointers will
	// point to their location in a string, if found.
	// Using APC here as start of an in-band signalling event, and ST to mark
	// the end.
	// 
	// EDIT: Added UTF8_HIGH to the APC and ST characters to ensure the in-band signalling can coexist with utf8 data.
	//	We don't bother with the UTF8_HIGH parts before the broker() because they don't intermingle with user 
	//	generated data until now.
	char *event_ptr = NULL;

	struct sigaction act;
	int current_sig;

	struct winsize tty_winsize;
	int winsize_buff_len;
	char *winsize_buff_head, *winsize_buff_tail;
	char **winsize_vec;
	int sig_pid;

	char tmp_char;

	int state_counter;

	int fcntl_flags;

	int ssl_bytes_pending = 0;


	if(io->listener){
		memset(&act, 0, sizeof(act));
		act.sa_handler = signal_handler;

		if((retval = sigaction(SIGWINCH, &act, NULL)) == -1){
			print_error(io, "%s: %d: sigaction(%d, %lx, %p): %s\r\n", \
					program_invocation_short_name, io->listener, \
					SIGWINCH, (unsigned long) &act, NULL, strerror(errno));
			goto CLEAN_UP;
		}
	}

	buff_len = getpagesize();

	// One buffer for reading from local_fd
	if((local_buff_head = (char *) calloc(buff_len, sizeof(char))) == NULL){
		print_error(io, "%s: %d: calloc(%d, %d): %s\r\n", \
				program_invocation_short_name, io->listener, \
				buff_len, (int) sizeof(char));
		retval = -1;
		goto CLEAN_UP;
	}

	// One buffer for reading from remote_fd
	if((remote_buff_head = (char *) calloc(buff_len, sizeof(char))) == NULL){
		print_error(io, "%s: %d: calloc(%d, %d): %s\r\n", \
				program_invocation_short_name, io->listener, \
				buff_len, (int) sizeof(char));
		retval = -1;
		goto CLEAN_UP;
	}


	// And one buffer for dealing with serialization and transmission / receipt
	// of a struct winsize. This probably only needs to be 14 chars long.
	// 2 control chars + 1 space + (2 * string length of winsize members).
	// winsize members are unsigned shorts on my dev platform.
	// There are four members total, but the second two are ignored.
	winsize_buff_len = WINSIZE_BUFF_LEN;
	if((winsize_buff_head = (char *) calloc(winsize_buff_len, sizeof(char))) == NULL){
		print_error(io, "%s: %d: calloc(%d, %d): %s\r\n", \
				program_invocation_short_name, io->listener, \
				winsize_buff_len, (int) sizeof(char));
		retval = -1;
		goto CLEAN_UP;
	}


	if((fcntl_flags = fcntl(io->remote_fd, F_GETFL, 0)) == -1){
		print_error(io, "%s: %d: fcntl(%d, FGETFL, 0): %s\r\n", \
				program_invocation_short_name, io->listener, \
				io->remote_fd, strerror(errno));
		retval = -1;
		goto CLEAN_UP;
	}

	fcntl_flags |= O_NONBLOCK;
	if((retval = fcntl(io->remote_fd, F_SETFL, fcntl_flags)) == -1){
		print_error(io, "%s: %d: fcntl(%d, FGETFL, %d): %s\r\n", \
				program_invocation_short_name, io->listener, \
				io->remote_fd, fcntl_flags, strerror(errno));
		retval = -1;
		goto CLEAN_UP;
	}


	local_buff_tail = local_buff_head;
	local_buff_ptr = local_buff_head;
	remote_buff_tail = remote_buff_head;
	remote_buff_ptr = remote_buff_head;

	while(1){

		// Empty the local buffer.
		// The remote buffer isn't a concern. It will be emptied at the time its filled,
		// in a short loop, because it is a blocking fd.
		if(local_buff_ptr != local_buff_tail){

			FD_ZERO(&fd_select);
			FD_SET(io->remote_fd, &fd_select);

			if(((retval = select(io->remote_fd + 1, NULL, &fd_select, NULL, NULL)) == -1) \
					&& !sig_found){
				print_error(io, \
						"%s: %d: broker(): select(%d, NULL, %lx, NULL, NULL): %s\r\n", \
						program_invocation_short_name, io->listener, io->remote_fd + 1, \
						(unsigned long) &fd_select, strerror(errno));
				goto CLEAN_UP;
			}

			if(FD_ISSET(io->remote_fd, &fd_select)){
				if((retval = io->remote_write(io, local_buff_ptr, (local_buff_tail - local_buff_ptr))) == -1){
					print_error(io, "%s: %d: broker(): io->remote_write(%lx, %lx, %d): %s\r\n", \
							program_invocation_short_name, io->listener, \
							(unsigned long) io, (unsigned long) local_buff_ptr, (local_buff_tail - local_buff_ptr), strerror(errno));
					goto CLEAN_UP;
				}
				local_buff_ptr += retval;
			}

			// fill the buffers
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
							program_invocation_short_name, io->listener, fd_max + 1, \
							(unsigned long) &fd_select, strerror(errno));
					goto CLEAN_UP;
				}
			}

			// Case 1: select() was interrupted by a signal that we handle.
			if(sig_found){

				local_buff_tail = local_buff_head;
				local_buff_ptr = local_buff_head;

				current_sig = sig_found;
				sig_found = 0;

				// leaving this as a switch() statement in case I decide to
				// handle more signals later on.
				switch(current_sig){

					case SIGWINCH:
						if((retval = ioctl(io->local_fd, TIOCGWINSZ, &tty_winsize)) == -1){
							print_error(io, "%s: %d: ioctl(%d, TIOCGWINSZ, %lx): %s\r\n", \
									program_invocation_short_name, io->listener, \
									io->local_fd, (unsigned long) &tty_winsize, strerror(errno));
							goto CLEAN_UP;
						}

						if((io_bytes = snprintf(local_buff_head, buff_len, \
										"%c%c%hd %hd%c%c", (char) UTF8_HIGH, (char) APC, tty_winsize.ws_row, \
										tty_winsize.ws_col, (char) UTF8_HIGH, (char) ST)) < 0){
							print_error(io, \
									"%s: %d: snprintf(winsize_buff_head, winsize_buff_len, \"%%c%%hd %%hd%%c\", APC, %hd, %hd, ST): %s\r\n", \
									program_invocation_short_name, io->listener, \
									tty_winsize.ws_row, tty_winsize.ws_col, strerror(errno));
							retval = -1;
							goto CLEAN_UP;
						}

						local_buff_tail = local_buff_head + io_bytes;


						break;

					default:
						print_error(io, "%s: %d: broker(): Undefined signal found: %d\r\n", \
								program_invocation_short_name, io->listener, current_sig);
						retval = -1;
						goto CLEAN_UP;
				}
				current_sig = 0;

				// Case 2: Data is ready on the local fd.
			}else if(FD_ISSET(io->local_fd, &fd_select)){
				local_buff_tail = local_buff_head;
				local_buff_ptr = local_buff_head;

				if((io_bytes = read(io->local_fd, local_buff_head, buff_len)) == -1){
					if(!io->listener && errno == EIO){
						goto CLEAN_UP;
					}
					print_error(io, "%s: %d: broker(): read(%d, %lx, %d): %s\r\n", \
							program_invocation_short_name, io->listener, \
							io->local_fd, (unsigned long) local_buff_head, buff_len, strerror(errno));
					retval = -1;
					goto CLEAN_UP;
				}

				if(!io_bytes){
					retval = 0;
					goto CLEAN_UP;
				}
				local_buff_tail = local_buff_head + io_bytes;

				// Case 3: Data is ready on the remote fd.
			}else if(FD_ISSET(io->remote_fd, &fd_select) || ssl_bytes_pending){

				ssl_bytes_pending = 0;

				remote_buff_tail = remote_buff_head;
				remote_buff_ptr = remote_buff_head;

				if((io_bytes = io->remote_read(io, remote_buff_head, buff_len)) == -1){
					print_error(io, "%s: %d: broker(): io->remote_read(%lx, %lx, %d): %s\r\n", \
							program_invocation_short_name, io->listener, \
							(unsigned long) io, (unsigned long) remote_buff_head, buff_len, strerror(errno));
					retval = -1;
					goto CLEAN_UP;
				}

				if(!io_bytes){
					retval = 0;
					goto CLEAN_UP;
				}
				remote_buff_tail = remote_buff_head + io_bytes;

				if(!io->listener){
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

				if(!io->listener && event_ptr){

					// First, clear out any data not part of the in-band signalling
					// that may be at the front of our buffer.
					while(remote_buff_ptr != event_ptr){
						if((retval = write(io->local_fd, remote_buff_ptr, (event_ptr - remote_buff_ptr))) == -1){
							print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
									program_invocation_short_name, io->listener, \
									io->local_fd, (unsigned long) remote_buff_ptr, (event_ptr - remote_buff_ptr), strerror(errno));
							goto CLEAN_UP;
						}
						remote_buff_ptr += retval;
					}

					// At this point, either buff_head is pointing to unused space or it matches event_ptr and is already UTF8_HIGH.
					// Either way, lets put UTF8_HIGH in at buff_head[0] so we can reference it later.
					*remote_buff_head = (char) UTF8_HIGH;

					// setup a state counter. Then retrieve next char from the appropriate place.
					state_counter = APC_HIGH_FOUND;

					// Get winsize data structures ready
					memset(winsize_buff_head, 0, winsize_buff_len);
					winsize_buff_tail = winsize_buff_head;

					event_ptr++;
					while(state_counter || (event_ptr != remote_buff_tail)){

						if(event_ptr != remote_buff_tail){
							tmp_char = *(event_ptr++);
						}else{

							// read() a char, remember to select() first to ensure there's data there!

							FD_ZERO(&fd_select);
							FD_SET(io->remote_fd, &fd_select);

							if(((retval = select(io->remote_fd + 1, &fd_select, NULL, NULL, NULL)) == -1)){
								print_error(io, \
										"%s: %d: broker(): select(%d, %lx, NULL, NULL, NULL): %s\r\n", \
										program_invocation_short_name, io->listener, io->remote_fd + 1, \
										(unsigned long) &fd_select, strerror(errno));
								goto CLEAN_UP;
							}

							if(!FD_ISSET(io->remote_fd, &fd_select)){
								print_error(io, \
										"%s: %d: broker(): FD_ISSET(%d, %lx): select() returned, but no data found.\r\n", \
										program_invocation_short_name, io->listener, io->remote_fd, \
										(unsigned long) &fd_select);
								goto CLEAN_UP;
							}

							if((retval = io->remote_read(io, &tmp_char, 1)) == -1){
								print_error(io, "%s: %d: io->remote_read(%lx, %lx, %d): %s\r\n", \
										program_invocation_short_name, io->listener, \
										(unsigned long) io, (unsigned long) &tmp_char, 1, strerror(errno));
								retval = -1;
								goto CLEAN_UP;
							}

							if(!retval){
								continue;
							}
						}

						// now we have a char, go into the state handler
						switch(state_counter){

							// Here, we found the opening APC_HIGH, but it wasn't related to an event. Further, the buffer isn't empty.
							// Consume the data, one char at a time, and make sure we don't find another event start.     
							case NO_EVENT:

								if(tmp_char == (char) UTF8_HIGH){
									state_counter = APC_HIGH_FOUND;
								}else{

									while((retval = write(io->local_fd, &tmp_char, 1)) < 1){
										if(retval == -1){
											print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
													program_invocation_short_name, io->listener, \
													io->local_fd, (unsigned long) &tmp_char, 1, strerror(errno));
											goto CLEAN_UP;
										}
									}
								}

								break;

								// check that we are actually in an event.
							case APC_HIGH_FOUND:

								if(tmp_char == (char) APC){
									state_counter = DATA_FOUND;

								}else{
									// damn you unicode!!!
									state_counter = NO_EVENT;

									// remember that UTF8_HIGH we stored at buff_head[0] earlier?  Yeah. :)
									while((retval = write(io->local_fd, &tmp_char, 1)) < 1){
										if(retval == -1){
											print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
													program_invocation_short_name, io->listener, \
													io->local_fd, (unsigned long) UTF8_HIGH, 1, strerror(errno));
											goto CLEAN_UP;
										}
									}

									while((retval = write(io->local_fd, &tmp_char, 1)) < 1){
										if(retval == -1){
											print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
													program_invocation_short_name, io->listener, \
													io->local_fd, (unsigned long) &tmp_char, 1, strerror(errno));
											goto CLEAN_UP;
										}
									}
								}

								break;

							case DATA_FOUND:

								if(tmp_char == (char) UTF8_HIGH){
									state_counter = ST_HIGH_FOUND;
								}else{
									*(winsize_buff_tail++) = tmp_char;

									if((winsize_buff_tail - winsize_buff_head) > winsize_buff_len){

										print_error(io, \
												"%s: %d: broker(): switch(%d): winsize_buff overflow.\r\n", \
												program_invocation_short_name, io->listener, state_counter);
										retval = -1;
										goto CLEAN_UP;
									}
								}
								break;

							case ST_HIGH_FOUND:

								if(tmp_char == (char) ST){

									state_counter = NO_EVENT;

									// Should have the winsize data by this point, so consume it and 
									// signal the foreground process group.
									if((winsize_vec = string_to_vector(winsize_buff_head)) == NULL){
										print_error(io, "%s: %d: broker(): string_to_vector(%s): %s\r\n", \
												program_invocation_short_name, io->listener, \
												winsize_buff_head, strerror(errno));
										retval = -1;
										goto CLEAN_UP;
									}

									if(winsize_vec[0] == NULL){
										print_error(io, \
												"%s: %d: invalid initialization: tty_winsize.ws_row\r\n", \
												program_invocation_short_name, io->listener);
										retval = -1;
										goto CLEAN_UP;
									}

									errno = 0;
									tty_winsize.ws_row = (short) strtol(winsize_vec[0], NULL, 10);
									if(errno){
										print_error(io, "%s: %d: strtol(%s): %s\r\n", \
												program_invocation_short_name, io->listener, \
												winsize_vec[0], strerror(errno));
										retval = -1;
										goto CLEAN_UP;
									}

									if(winsize_vec[1] == NULL){
										print_error(io, \
												"%s: %d: invalid initialization: tty_winsize.ws_col\r\n", \
												program_invocation_short_name, io->listener);
										retval = -1;
										goto CLEAN_UP;
									}

									errno = 0;
									tty_winsize.ws_col = (short) strtol(winsize_vec[1], NULL, 10);
									if(errno){
										print_error(io, "%s: %d: strtol(%s): %s\r\n", \
												program_invocation_short_name, io->listener, \
												winsize_vec[1], strerror(errno));
										retval = -1;
										goto CLEAN_UP;
									}

									if((retval = ioctl(io->local_fd, TIOCSWINSZ, &tty_winsize)) == -1){
										print_error(io, "%s: %d: ioctl(%d, %d, %lx): %s\r\n", \
												program_invocation_short_name, io->listener, \
												io->local_fd, TIOCGWINSZ, (unsigned long) &tty_winsize, \
												strerror(errno));
										goto CLEAN_UP;
									}

									if((sig_pid = tcgetsid(io->local_fd)) == -1){
										print_error(io, "%s: %d: tcgetsid(%d): %s\r\n", \
												program_invocation_short_name, io->listener, \
												io->local_fd, strerror(errno));
										retval = -1;
										goto CLEAN_UP;
									}

									if((retval = kill(-sig_pid, SIGWINCH)) == -1){
										print_error(io, "%s: %d: kill(%d, %d): %s\r\n", \
												program_invocation_short_name, io->listener, \
												-sig_pid, SIGWINCH, strerror(errno));
										goto CLEAN_UP;
									}

								}else{
									// The winsize data is encoded as ascii. It should never come across at UTF8_HIGH.
									// So this case will always be an error. Handle as such.
									print_error(io, \
											"%s: %d: broker(): switch(%d): high closing byte found w/out low closing byte. Should not be here!\r\n", \
											program_invocation_short_name, io->listener, state_counter);
									retval = -1;
									goto CLEAN_UP;
								}

								break;

							default:

								// Handle error case.
								print_error(io, \
										"%s: %d: broker(): switch(%d): unknown state. Should not be here!\r\n", \
										program_invocation_short_name, io->listener, state_counter);
								retval = -1;
								goto CLEAN_UP;
						}

					}

				}else{
					while(remote_buff_ptr != remote_buff_tail){
						if((retval = write(io->local_fd, remote_buff_head, (remote_buff_tail - remote_buff_ptr))) == -1){
							print_error(io, "%s: %d: broker(): write(%d, %lx, %d): %s\r\n", \
									program_invocation_short_name, io->listener, \
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
			program_invocation_short_name, io->listener);
	retval = -1;

CLEAN_UP:
	free(local_buff_head);
	free(remote_buff_head);
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

