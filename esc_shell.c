#include "common.h"

#ifdef LINENOISE
# include "esc_shell.h"
#endif 


int esc_shell_start(){

#ifndef LINENOISE
	fprintf(stderr, "\r\n\nThis build of revsh does not include linenoise support. No command shell available.\r\n");
	fprintf(stderr, "\r\n\nhttps://github.com/antirez/linenoise\r\n");
#else

	int child_pid;
  int fcntl_flags;


  if(tcsetattr(io->local_in_fd, TCSANOW, io->saved_termios_attrs) == -1){
    report_error("do_control(): tcsetattr(%d, TCSANOW, %lx): %s", io->local_in_fd, (unsigned long) io->saved_termios_attrs, strerror(errno));
    return(-1);
  }

  /* Set the socket to blocking for the duration of the escape command shell. */
  if((fcntl_flags = fcntl(io->local_in_fd, F_GETFL, 0)) == -1){
    report_error("negotiate_protocol(): fcntl(%d, F_GETFL, 0): %s", io->local_in_fd, strerror(errno));
    return(-1);
  }

  fcntl_flags &= ~O_NONBLOCK;
  if(fcntl(io->local_in_fd, F_SETFL, fcntl_flags) == -1){
    report_error("esc_command_start(): fcntl(%d, F_SETFL, %d): %s", io->local_in_fd, fcntl_flags, strerror(errno));
    return(-1);
  }

  if((fcntl_flags = fcntl(io->local_out_fd, F_GETFL, 0)) == -1){
    report_error("negotiate_protocol(): fcntl(%d, F_GETFL, 0): %s", io->local_out_fd, strerror(errno));
    return(-1);
  }

  fcntl_flags &= ~O_NONBLOCK;
  if(fcntl(io->local_out_fd, F_SETFL, fcntl_flags) == -1){
    report_error("esc_command_start(): fcntl(%d, F_SETFL, %d): %s", io->local_out_fd, fcntl_flags, strerror(errno));
    return(-1);
  }

  if((io->command_buff = (char *) calloc(ESC_COMMAND_MAX, sizeof(char))) == NULL){
    report_error("esc_command_start(): calloc(%d, %d): %s", ESC_COMMAND_MAX, (int) sizeof(char), strerror(errno));
    return(-1);
  }

  // Check if there is message->data still left unprocessed. Shouldn't happen.
  // The esc_shell is a char by char human interaction. If you've somehow stuffed more data in here, it's going to get dropped.
  if(message->data_len){
    message->data_len = 0;
  }
	

	if(pipe(io->command_fd) == -1){
		report_error("esc_shell_start(): pipe(%lx): %s", (unsigned long) io->command_fd, strerror(errno));
		return(-1);
	}
	
	child_pid = fork();

	if(child_pid == -1){
		report_error("esc_shell_start(): fork(): %s", strerror(errno));
		return(-1);
	}	

	if(!child_pid){

		close(io->command_fd[0]);

		if(esc_shell_loop() == -1){
			fprintf(stderr, "\r\nesc_shell_start(): %s", strerror(errno));
			exit(-1);
		}

		exit(0);
	}

	close(io->command_fd[1]);

#endif 

	return(0);
}



int esc_shell_stop(){

#ifdef LINENOISE

  int fcntl_flags;


  if(tcsetattr(io->local_in_fd, TCSANOW, io->revsh_termios_attrs) == -1){
    report_error("do_control(): tcsetattr(%d, TCSANOW, %lx): %s", io->local_in_fd, (unsigned long) io->revsh_termios_attrs, strerror(errno));
    return(-1);
  }

  /* Set the socket to blocking for the duration of the escape command shell. */
  if((fcntl_flags = fcntl(io->local_in_fd, F_GETFL, 0)) == -1){
    report_error("negotiate_protocol(): fcntl(%d, F_GETFL, 0): %s", io->local_in_fd, strerror(errno));
    return(-1);
  }

  fcntl_flags |= O_NONBLOCK;
  if(fcntl(io->local_in_fd, F_SETFL, fcntl_flags) == -1){
    report_error("esc_command_start(): fcntl(%d, F_SETFL, %d): %s", io->local_in_fd, fcntl_flags, strerror(errno));
    return(-1);
  }

  if((fcntl_flags = fcntl(io->local_out_fd, F_GETFL, 0)) == -1){
    report_error("negotiate_protocol(): fcntl(%d, F_GETFL, 0): %s", io->local_out_fd, strerror(errno));
    return(-1);
  }

  fcntl_flags |= O_NONBLOCK;
  if(fcntl(io->local_out_fd, F_SETFL, fcntl_flags) == -1){
    report_error("esc_command_start(): fcntl(%d, F_SETFL, %d): %s", io->local_out_fd, fcntl_flags, strerror(errno));
    return(-1);
  }

	close(io->command_fd[0]);
	free(io->command_buff);
	io->command_buff = NULL;
	io->command_len = 0;

#endif

	return(0);
}

#ifdef LINENOISE
int esc_shell_loop(){

	char *input;
	int i;
	int retval;
	unsigned short count;
	char **command_vec;
	char *packed_command = NULL;


	linenoiseSetCompletionCallback(expand_tab);

	printf("\n\nEntering revsh command shell. Grabbing TTY input.\n");
	printf("\nThe revsh command shell uses the linenoise library:\nCopyright (c) 2010-2014, Salvatore Sanfilippo <antirez at gmail dot com>\nCopyright (c) 2010-2013, Pieter Noordhuis <pcnoordhuis at gmail dot com>\nhttps://github.com/antirez/linenoise\n\n");

	while((input = linenoise("revsh> "))){

//		fprintf(stderr, "\r\nDEBUG: input: |%s|\r\n", input);
		if((command_vec = cli_to_vector(input)) == NULL){
			fprintf(stderr, "\r\nesc_shell_loop(): cli_to_vector(%lx): %s\n", (unsigned long) input, strerror(errno));
			return(-1);
		}

//		fprintf(stderr, "\rDEBUG: command_vec[0]: |%s|\r\n", command_vec[0]);

		if(command_vec[0]){

			if(!(strcmp(command_vec[0], "exit") && strcmp(command_vec[0], ":q!") && strcmp(command_vec[0], ":q") && strcmp(command_vec[0], ":wq"))){
				goto EXIT;
			}else if(!(strcmp(command_vec[0], "help") && strcmp(command_vec[0], "?"))){
				esc_shell_help(command_vec);

			// command_validate() just looks at simple things.
			// Will it fit in the buffer? Do we recognize it as a supported command / subcommand?
			// Does it have the correct number of arguments?
			// No actual validation of files existing or having permission to access occurs here.
			}else if((retval = command_validate(command_vec)) > 0){

				// Send packed_command back to the main process.

/*
				i = 0;
				count = 0;
				while(command_vec[i]){
					if(i){
						memcpy(command_string + count, " ", 1);
						count++;
					}

					tmp_len = strlen(command_vec[i]);
					memcpy(command_string + count, command_vec[i], tmp_len);
					count += tmp_len;
					
					i++;
				}
				*(command_string + count++) = '\0';
			
//				printf("DEBUG: esc_shell_loop(): command_string: %s\n", command_string);	
*/
				if((packed_command = pack_vector(command_vec)) == NULL){
					fprintf(stderr, "\r\nesc_shell_loop(): pack_vector(%lx): %s\n", (unsigned long) command_vec, strerror(errno));
					return(-1);
				}
				memcpy(&count, packed_command, sizeof(unsigned short));
				count = ntohs(count);
//				fprintf(stderr, "\r\nDEBUG: esc_shell_loop(): count: %d\n", count);

				retval = write(io->command_fd[1], packed_command, count);
//				fprintf(stderr, "\r\nDEBUG: esc_shell_loop(): write() retval: %d\n", retval);
				

			}else{
				if(!retval){
					printf("\n");
					printf("Unknown command:");
					i = 0;
					while(command_vec[i]){
						printf(" %s", command_vec[i]);
						i++;
					}
					printf(": Try \"help\".\n");
					printf("\n");
				}
			}
		}

		if(packed_command){
			free(packed_command);
			packed_command = NULL;
		}
		linenoiseHistoryAdd(input);
		linenoiseHistorySetMaxLen(50);
		linenoiseFree(input);

		free_vector(command_vec);
	}

EXIT:
	printf("\r\nExiting revsh command shell. Releasing TTY input.\n(You may need to hit 'Enter' for a prompt.)\n");
	return(0);
}


void esc_shell_help(char **command_vec){

	const struct esc_shell_command *command_ptr;
	int i, j;


	if(!command_vec[1]){
		printf("\n");
		printf("Usage:\n\tCOMMAND SUBCOMAND ARGS\n");
		printf("\n");
		printf("Commands:\n");

		i = 0;
		while(menu[i].completion_string){
			printf("\t%s\n", menu[i].completion_string);
			j = 0;
			while(menu[i].sub_commands[j].completion_string){
				printf("\t%s\n", menu[i].sub_commands[j].completion_string);
				j++;
			}
			i++;
		}

		printf("\n");
		printf("For more info:\n");
		printf("\thelp COMMAND [SUBCOMMAND]\n");
		printf("\n");

		return;
	}

	if((command_ptr = find_in_menu(command_vec + 1)) == NULL){
		printf("\n");
		printf("Unknown command:");
		i = 1;
		while(command_vec[i]){
			printf(" %s", command_vec[i]);
			i++;
		}
		printf(": No help available.\n");
		printf("\n");
		return;
	}

	printf("\n");
	printf("%s", command_ptr->help_message);
	printf("\n");

}


const struct esc_shell_command *find_in_menu(char **command_vec){

	int i, j;


	i = 0;
	while(menu[i].command){
		if(command_vec[0] && !strcmp(command_vec[0], menu[i].command)){
			if(menu[i].sub_commands[0].command && command_vec[1]){
				j = 0;
				while(menu[i].sub_commands[j].command){
					if(!strcmp(command_vec[1], menu[i].sub_commands[j].command)){
						return(&menu[i].sub_commands[j]);
					}
					j++;
				}
			}else{
				return(&menu[i]);
			}
		}
		i++;
	}

	return(NULL);	
}


void expand_tab(const char *buf, linenoiseCompletions *lc){

	int i, j, k;
	char **buf_vec;
	char **suggestion_vec;
	char *string_ptr;
	int buf_count;
	int tmp_int;
	int buf_len;
	char scratch[ESC_COMMAND_MAX];

	int space_flag;

	if(!buf){
		return;
	}


	space_flag = 1;
	buf_len = strlen(buf);
	for(i = 0; i < buf_len; i++){
		if(buf[i] != ' '){
			space_flag = 0;
			break;
		}
	}
	
	if((buf_vec = cli_to_vector((char *) buf)) == NULL){
		fprintf(stderr, "\r\nexpand_tab(): cli_to_vector(%lx): %s\n", (unsigned long) buf, strerror(errno));
		return;
	}

	buf_count = 0;
	while(buf_vec[buf_count]){
		buf_count++;
	}
//	fprintf(stderr, "\r\nDEBUG: expand_tab(): buf_count: %d\n", buf_count);
//	fprintf(stderr, "\r\nDEBUG: expand_tab(): space_flag: %d\n", space_flag);

	// Nothing is really there. (Might have been whitespace which we stripped.)
	// Offer up the main menu commands.
	if(!buf_count){
		if(space_flag){
			i = 0;
			while(menu[i].command){
				linenoiseAddCompletion(lc, menu[i].command);
				i++;
			}
		}
		return;
	}

	if(buf_len && buf[buf_len - 1] == ' '){
		space_flag = 1;
	}	

	// loop once through the main menu. If we find a match, loop through submenu and do the needful...
	// Return if we find something. Don't forget to free_vector() the buf_vec.
	i = 0;
	while(menu[i].command){

		if(!strcmp(buf_vec[0], menu[i].command)){

			if(buf_count > 1){
				// same tactic here. Loop through sub commands looking for exact matches.
				if(menu[i].sub_commands){
					j = 0;
					while(menu[i].sub_commands[j].command){
						if(!strcmp(buf_vec[1], menu[i].sub_commands[j].command)){

							// Tried to keep this all as modular as possible.
							// Unfortuantely, there are *some* special cases we have to just deal with.

							// Handle tab expansion of "file upload / download" files.
							if(!strcmp(buf_vec[0], "file")){
								if(!strcmp(buf_vec[1], "upload") && (buf_count == 2 || buf_count == 3)){

									string_ptr = "./";
									if(buf_count == 3){
										string_ptr = buf_vec[2];
									}
									if((suggestion_vec = suggest_files(string_ptr)) == NULL){
										return;
									}

									// loop through suggestion_vec.
									k = 0;
									while(suggestion_vec[k]){
										snprintf(scratch, ESC_COMMAND_MAX, "%s %s %s", buf_vec[0], buf_vec[1], suggestion_vec[k]);
										linenoiseAddCompletion(lc, scratch);
										k++;
									}
								}else if(!strcmp(buf_vec[1], "download") && (buf_count == 3 || buf_count == 4)){

									string_ptr = "./";
									if(buf_count == 4){
										string_ptr = buf_vec[3];
									}
									if((suggestion_vec = suggest_files(string_ptr)) == NULL){
										return;
									}

									// loop through suggestion_vec.
									k = 0;
									while(suggestion_vec[k]){
										snprintf(scratch, ESC_COMMAND_MAX, "%s %s %s %s", buf_vec[0], buf_vec[1], buf_vec[2], suggestion_vec[k]);
										linenoiseAddCompletion(lc, scratch);
										k++;
									}
								}
							}

							free_vector(buf_vec);
							return;
						}
						j++;
					}
				}

				// Another special case.
				if(!strcmp(buf_vec[0], "lars") && (buf_count == 2 || buf_count == 3)){

					string_ptr = buf_vec[buf_count - 1];
					if(buf_count == 2 && space_flag){
						string_ptr = "./";					
					}

					if((suggestion_vec = suggest_files(string_ptr)) == NULL){
						return;
					}

					k = 0;
					while(suggestion_vec[k]){
						if(buf_count == 2 && !space_flag){
							snprintf(scratch, ESC_COMMAND_MAX, "%s %s", buf_vec[0], suggestion_vec[k]);
						}else{
							snprintf(scratch, ESC_COMMAND_MAX, "%s %s %s", buf_vec[0], buf_vec[1], suggestion_vec[k]);
						}
						linenoiseAddCompletion(lc, scratch);
						k++;
					}
				}	

			}else{
				// case where the first command matches, but no additional commands have been entered yet. suggest all submenu items.
				// maybe add a flag, then fall through to the next case and add everything if the flag is set?	

				j = 0;
				while(menu[i].sub_commands[j].command){
					// case where we match menu and sub menu. If there are files to suggest or otherwise, do that here.
					linenoiseAddCompletion(lc, menu[i].sub_commands[j].completion_string);
					j++;
				}

				if(!strcmp(buf_vec[0], "lars")){

					string_ptr = "./";
					if((suggestion_vec = suggest_files(string_ptr)) == NULL){
						return;
					}

					k = 0;
					while(suggestion_vec[k]){
						snprintf(scratch, ESC_COMMAND_MAX, "%s %s", buf_vec[0], suggestion_vec[k]);
						linenoiseAddCompletion(lc, scratch);
						k++;
					}
				}
				free_vector(buf_vec);
				return;
			}

			// If we're here, no exact subcommand matches. Loop through again and linenoiseAddCompletion() on the partials.
			tmp_int = strlen(buf_vec[1]);
			j = 0;
			while(menu[i].sub_commands[j].command){
				// case where we match menu and sub menu. If there are files to suggest or otherwise, do that here.
				if(!strncmp(buf_vec[1], menu[i].sub_commands[j].command, tmp_int)){
					linenoiseAddCompletion(lc, menu[i].sub_commands[j].completion_string);
				}
				j++;
			}

			free_vector(buf_vec);
			return;
		}

		i++;
	}

	// If we're here, there was no command match off the main menu. Loop through again and make recommendations on partial matches.
	tmp_int = strlen(buf_vec[0]);
	i = 0;
	while(menu[i].command){
		if(!strncmp(buf_vec[0], menu[i].command, tmp_int)){
			linenoiseAddCompletion(lc, menu[i].completion_string);
		}
		i++;
	}

	free_vector(buf_vec);
}


int command_validate(char **command_vec){

	int tmp_string_len = 0;
	const struct esc_shell_command *command_ptr = NULL;
	int arg_count;


	arg_count = 0;
	while(command_vec[arg_count]){
		tmp_string_len += strlen(command_vec[arg_count]);
		arg_count++;
	}
	tmp_string_len += arg_count;

	if((tmp_string_len + 1) > ESC_COMMAND_MAX){
		fprintf(stderr, "\r\nCommand too long! Ignoring.\n");
		return(-1);
	}

	if((command_ptr = find_in_menu(command_vec))){
		if((arg_count >= command_ptr->min_args) && (arg_count <= command_ptr->max_args)){
			return(tmp_string_len);
		}
	}

	return(0);
}


char **suggest_files(char *string){

	char scratch[ESC_COMMAND_MAX];

	unsigned int i;
	char **temp_vec = NULL;
	char *tmp_ptr;
	char *fragment_ptr;
	int tmp_len;
	int retval;

	wordexp_t file_exp;
	char **file_exp_matches;
	struct stat file_stat;
	DIR *query_dir;
	struct dirent *query_dirent;


	if((retval = wordexp(string, &file_exp, 0))){

		switch(retval){

			case WRDE_BADCHAR:
				fprintf(stderr, "\r\nIllegal occurrence of newline or one of |, &, ;, <, >, (, ), {, }.\n");
				break;

			case WRDE_BADVAL:
				fprintf(stderr, "\r\nAn undefined shell variable was referenced, and the WRDE_UNDEF flag told us to consider this an error.\n");
				break;

			case WRDE_CMDSUB:
				fprintf(stderr, "\r\nCommand substitution occurred, and the WRDE_NOCMD flag told us to consider this an error.\n");
				break;

			case WRDE_NOSPACE:
				fprintf(stderr, "\r\nOut of memory.\n");
				fprintf(stderr, "\rsuggest_files(): wordexp(%lx, %lx, 0): WRDE_NOSPACE\n", (unsigned long) string, (unsigned long) &file_exp);
				return(NULL);

			case WRDE_SYNTAX:
				fprintf(stderr, "\r\nShell syntax error, such as unbalanced parentheses or unmatched quotes.\n");
				break;
		}

		return(temp_vec);
	}

	file_exp_matches = file_exp.we_wordv;
	for(i = 0; i < file_exp.we_wordc; i++){

		if(!stat(file_exp_matches[i], &file_stat)){

			// Case 1: file. Offer it as a solution.
			if(!S_ISDIR(file_stat.st_mode)){
				if((temp_vec = vector_push(temp_vec, file_exp_matches[i])) == NULL){
					fprintf(stderr, "\r\nsuggest_files(): vector_push(%lx, %lx): %s\n", (unsigned long) temp_vec, (unsigned long) file_exp_matches[i], strerror(errno));
					return(NULL);
				}

				// Case 2: directory.  Recurse through it. and offer files as solutions.
			}else{

				if((query_dir = opendir(file_exp_matches[i]))){
					while((query_dirent = readdir(query_dir))){ 

						if(strcmp(query_dirent->d_name, ".") && strcmp(query_dirent->d_name, "..")){
							tmp_len = strlen(file_exp_matches[i]);
							tmp_len += strlen(query_dirent->d_name) + 1;

							if(!((tmp_len + 1) > ESC_COMMAND_MAX)){
								tmp_len = sprintf(scratch, "%s", file_exp_matches[i]);
								if(tmp_len && *(scratch + tmp_len - 1) != '/')
									sprintf(scratch + tmp_len++, "%s", "/");
							}
							sprintf(scratch + tmp_len, "%s", query_dirent->d_name);
							temp_vec = vector_push(temp_vec, scratch);
						}
					}
				}
			}

			// Case 3: partial name. 
			//					a: find the fragment at the end.
			//					b: decide upon a directory at the begining.
			//					c: loop through the directory looking for a partial string match. offer it as a solution.
		}else{

			tmp_len = strlen(file_exp_matches[i]);
			tmp_ptr = strrchr(file_exp_matches[i], '/');
			fragment_ptr = file_exp_matches[i];

			if(!tmp_ptr){
				tmp_len = sprintf(scratch, "%s", ".");
				tmp_ptr = scratch + tmp_len;	

			}else if(!((tmp_len + 1) > ESC_COMMAND_MAX)){
				fragment_ptr = tmp_ptr + 1;
				sprintf(scratch, "%s", file_exp_matches[i]);
				tmp_ptr = strrchr(scratch, '/');
				*tmp_ptr = '\0';
			}

			if((query_dir = opendir(scratch))){
				while((query_dirent = readdir(query_dir))){ 

					tmp_len = strlen(fragment_ptr);
					if(tmp_len && !strncmp(fragment_ptr, query_dirent->d_name, tmp_len)){
						tmp_len = strlen(scratch);
						tmp_len += strlen(query_dirent->d_name) + 1;

						if(!((tmp_len + 1) > ESC_COMMAND_MAX)){
							sprintf(tmp_ptr, "/%s", query_dirent->d_name);
							temp_vec = vector_push(temp_vec, scratch);
						}
					}
				}
			}
		}
	}

	wordfree(&file_exp);
	return(temp_vec);
}
#endif
