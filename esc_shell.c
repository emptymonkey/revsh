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

//    fprintf(stderr, "\rDEBUG: esc_command_start()\n");

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

	
	child_pid = fork();

	if(child_pid == -1){
		report_error("esc_shell_start(): fork(): %s", strerror(errno));
		return(-1);
	}	

	if(!child_pid){

		if(esc_shell_loop() == -1){
			fprintf(stderr, "\r\nesc_shell_start(): %s", strerror(errno));
			exit(-1);
		}

		exit(0);
	}


#endif 

	return(0);
}



int esc_shell_stop(){

#ifdef LINENOISE

  int fcntl_flags;

//	fprintf(stderr, "\r\nDEBUG: esc_shell_stop(): start.\n");

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
	int tmp_len;
	int count;
//	int command_count;
	char **command_vec;
	char *command_string = NULL;


	linenoiseSetCompletionCallback(expand_tab);

	printf("\n\nEntering revsh command shell. Grabbing TTY input.\n");
	printf("\nThe revsh command shell uses the linenoise library:\nCopyright (c) 2010-2014, Salvatore Sanfilippo <antirez at gmail dot com>\nCopyright (c) 2010-2013, Pieter Noordhuis <pcnoordhuis at gmail dot com>\nhttps://github.com/antirez/linenoise\n\n");

	while((input = linenoise("revsh> "))){
//		printf("DEBUG: *input: %s\n", input);

		if((command_vec = string_to_vector(input)) == NULL){
			fprintf(stderr, "\r\nesc_shell_loop(): string_to_vector(%lx): %s\n", (unsigned long) input, strerror(errno));
			return(-1);
		}

//		command_count = 0;
//		while(command_vec[command_count]){
//			printf("DEBUG: command_vec[%d]: %s\n", command_count, command_vec[command_count]);
//			command_count++;
//		}
//		printf("DEBUG: command_count: %d\n", command_count);

		if(command_vec[0]){

			if(!(strcmp(command_vec[0], "exit") && strcmp(command_vec[0], ":q!") && strcmp(command_vec[0], ":q") && strcmp(command_vec[0], ":wq"))){
				goto EXIT;
			}else if(!(strcmp(command_vec[0], "help") && strcmp(command_vec[0], "?"))){
				esc_shell_help(command_vec);
			}else if((count = command_validate(command_vec)) > 0){

				// Send command_string back to the main process.
				if((command_string = (char *) calloc(count + 1, sizeof(char))) == NULL){
					fprintf(stderr, "\r\nesc_shell_loop(): calloc(%d, %d): %s\n", count + 1, (int) sizeof(char), strerror(errno));
					goto EXIT;
				}

				i = 0;
				tmp_len = 0;
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
			
				printf("DEBUG: command_string: %s\n", command_string);	

			}else{
				if(!count){
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


		linenoiseHistoryAdd(input);
		linenoiseHistorySetMaxLen(50);
		linenoiseFree(input);

		if(command_string){
			free(command_string);
			command_string = NULL;
		}
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
		if(!strcmp(command_vec[0], menu[i].command)){
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

	char scratch[ESC_COMMAND_MAX];


	if((buf_vec = string_to_vector((char *) buf)) == NULL){
		fprintf(stderr, "\r\nexpand_tab(): string_to_vector(%lx): %s\n", (unsigned long) buf, strerror(errno));
		return;
	}	

	buf_count = 0;
	while(buf_vec[buf_count]){
		//		printf("\rDEBUG: buf_vec[%d]: %s\n", buf_count, buf_vec[buf_count]);
		buf_count++;
	}

	//	printf("\rDEBUG: buf_count: %d\n", buf_count);

	// loop once through the main menu. If we find a match, loop through submenu and do the needful...
	// Return if we find something. Don't forget to free_vector() the buf_vec.
	i = 0;
	while(menu[i].command){

		if(!strcmp(buf_vec[0], menu[i].command)){
			//			printf("\rDEBUG: menu exact match: %s\n", menu[i].command);

			if(buf_count > 1){
				// same tactic here. Loop through sub commands looking for exact matches.
				if(menu[i].sub_commands){
					j = 0;
					while(menu[i].sub_commands[j].command){
						if(!strcmp(buf_vec[1], menu[i].sub_commands[j].command)){
							//							printf("\rDEBUG: submenu exact match: %s\n", menu[i].sub_commands[j].command);

							// Handle tab expansion of "file upload / download" files.
							//							printf("\r\nDEBUG: buf_count: %d\n", buf_count);
							//							printf("\r\nDEBUG: buf_vec[0]: %s\n", buf_vec[0]);
							//							printf("\r\nDEBUG: buf_vec[1]: %s\n", buf_vec[1]);
							if(!strcmp(buf_vec[0], "file")){
								if(!strcmp(buf_vec[1], "upload") && (buf_count == 2 || buf_count == 3)){

									string_ptr = "./";
									if(buf_count == 3){
										string_ptr = buf_vec[2];
									}
									if((suggestion_vec = suggest_files(string_ptr)) == NULL){
										fprintf(stderr, "\r\nexpand_tab(): suggest_files(%lx): %s\n", (unsigned long) string_ptr, strerror(errno));
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
										fprintf(stderr, "\r\nexpand_tab(): suggest_files(%lx): %s\n", (unsigned long) string_ptr, strerror(errno));
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

				if(!strcmp(buf_vec[0], "ttyscript") && buf_count == 2){

					string_ptr = buf_vec[1];
					if((suggestion_vec = suggest_files(string_ptr)) == NULL){
						fprintf(stderr, "\r\nexpand_tab(): suggest_files(%lx): %s\n", (unsigned long) string_ptr, strerror(errno));
						return;
					}

					k = 0;
					while(suggestion_vec[k]){
						snprintf(scratch, ESC_COMMAND_MAX, "%s %s", buf_vec[0], suggestion_vec[k]);
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
					//					printf("\rDEBUG: submenu suggestion: %s\n", menu[i].sub_commands[j].command);
					linenoiseAddCompletion(lc, menu[i].sub_commands[j].completion_string);
					j++;
				}

				if(!strcmp(buf_vec[0], "ttyscript")){

					string_ptr = config->ttyscripts_dir;
					if((suggestion_vec = suggest_files(string_ptr)) == NULL){
						fprintf(stderr, "\r\nexpand_tab(): suggest_files(%lx): %s\n", (unsigned long) string_ptr, strerror(errno));
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
					//					printf("\rDEBUG: submenu suggestion: %s\n", menu[i].sub_commands[j].command);
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
			//			printf("\rDEBUG: menu suggestion: %s\n", menu[i].command);
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
	arg_count--;
	tmp_string_len += arg_count;

	if((tmp_string_len + 1) > ESC_COMMAND_MAX){
		fprintf(stderr, "\r\nCommand too long! Ignoring.\n");
		return(-1);
	}

//	printf("\r\nDEBUG: arg_count: %d\n", arg_count);
	if((command_ptr = find_in_menu(command_vec))){
//		printf("\r\nDEBUG: command_ptr->min_args: %d\n", command_ptr->min_args);
//		printf("\r\nDEBUG: command_ptr->max_args: %d\n", command_ptr->max_args);

		if((arg_count >= command_ptr->min_args) && (arg_count <= command_ptr->max_args)){
			return(tmp_string_len);
		}
	}

	return(0);
}

// original vector is destroyed. NULL on error.
char **vector_push(char **vector, char *string){

	char **tmp_vector = NULL;
	int count;
	int i;

	//	printf("DEBUG: vector_push(): start\n");

	count = 0;
	if(vector){
		while(vector[count]){
			count++;
		}
	}
	count++;

	if((tmp_vector = (char **) calloc(count + 1, sizeof(char *))) == NULL){
		fprintf(stderr, "\r\nvector_push(): calloc(%d, %d): %s\n", count + 1, (int) sizeof(char *), strerror(errno));
		return(NULL);
	}

	i = 0;
	if(vector){	
		while(vector[i]){

			count = strlen(vector[i]);
			if((tmp_vector[i] = (char *) calloc(count + 1, sizeof(char))) == NULL){
				fprintf(stderr, "\r\nvector_push(): calloc(%d, %d): %s\n", count + 1, (int) sizeof(char), strerror(errno));
				return(NULL);
			}
			memcpy(tmp_vector[i], vector[i], count);

			i++;
		}
	}

	count = strlen(string);
	if((tmp_vector[i] = (char *) calloc(count + 1, sizeof(char))) == NULL){
		fprintf(stderr, "\r\nvector_push(): calloc(%d, %d): %s\n", count + 1, (int) sizeof(char), strerror(errno));
		return(NULL);
	}
	memcpy(tmp_vector[i], string, count);

	if(vector){
		free_vector(vector);	
	}

	return(tmp_vector);
}


// NULL on errors. Pointer to vec with only the NULL element on success with no matches.
char **suggest_files(char *string){

	char scratch[ESC_COMMAND_MAX];

	unsigned int i;
	char **temp_vec = NULL;
	char *tmp_ptr;
	char *fragment_ptr;
	int fragment_len;
	int tmp_len;
	int retval;

	wordexp_t file_exp;
	char **file_exp_matches;
	struct stat file_stat;
	DIR *query_dir;
	struct dirent *query_dirent;

//	printf("\r\nDEBUG: string: %s\n", string);

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
//		printf("\r\nDEBUG: file_exp_matches[%d]: %s\n", i, file_exp_matches[i]);

		// for each match, go through and examine it. If a stat() shows it exists, offer it up as a suggestion.
		if(!stat(file_exp_matches[i], &file_stat) && !S_ISDIR(file_stat.st_mode)){
			//			printf("DEBUG: stat successful\n");
			if((temp_vec = vector_push(temp_vec, file_exp_matches[i])) == NULL){
				fprintf(stderr, "\r\nsuggest_files(): vector_push(%lx, %lx): %s\n", (unsigned long) temp_vec, (unsigned long) file_exp_matches[i], strerror(errno));
				return(NULL);
			}
		}else{
			// if it doesn't exist, try to figure out if some part of it is a dir, then opendir() readdir() and suggest files that match.


			tmp_len = strlen(file_exp_matches[i]);
			if(!(tmp_len > ESC_COMMAND_MAX)){
				strcpy(scratch, file_exp_matches[i]);

				fragment_ptr = NULL;
				fragment_len = 0;

				tmp_ptr = strrchr(scratch, '/');
				if(tmp_ptr && *(tmp_ptr + 1)){
					*tmp_ptr = '\0';
					fragment_ptr = tmp_ptr + 1;
					fragment_len = strlen(fragment_ptr);
				}else{
					tmp_ptr = scratch + tmp_len;
				}


				if(!stat(scratch, &file_stat) && S_ISDIR(file_stat.st_mode) && (query_dir = opendir(scratch))){

					while((query_dirent = readdir(query_dir))){ 
//						printf("\r\nDEBUG: query_dirent->d_name: %s\n", query_dirent->d_name);
						if(strcmp(query_dirent->d_name, ".") && strcmp(query_dirent->d_name, "..")){

							if(!fragment_ptr || !strncmp(fragment_ptr, query_dirent->d_name, fragment_len)){

								tmp_len += strlen(query_dirent->d_name) + 1;
								if(!((tmp_len + 1) > ESC_COMMAND_MAX)){
									sprintf(tmp_ptr, "%s", query_dirent->d_name);
									temp_vec = vector_push(temp_vec, scratch);
								}
							}
						}
					}
					closedir(query_dir);
				}
			}
		}
	}

	wordfree(&file_exp);
	return(temp_vec);
}
#endif
