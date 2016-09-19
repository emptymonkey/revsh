#include "common.h"

#ifdef LINENOISE
# include "linenoise.h"
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
//	int command_count;
	char **command_vec;
	char **completion_strings;	

	if((completion_strings = completion_strings_initialize()) == NULL){
		fprintf(stderr, "esc_shell_loop(): completion_strings_initialize(): %s\n", strerror(errno));
		return(-1);
	}


	printf("\n\nEntering revsh command shell. Grabbing TTY I/O.\n");
	printf("\nThe revsh command shell uses linenoise:\nCopyright (c) 2010-2014, Salvatore Sanfilippo <antirez at gmail dot com>\nCopyright (c) 2010-2013, Pieter Noordhuis <pcnoordhuis at gmail dot com>\nhttps://github.com/antirez/linenoise\n\n");

	while((input = linenoise("revsh> "))){
//		printf("DEBUG: *input: %s\n", input);

		if((command_vec = string_to_vector(input)) == NULL){
			fprintf(stderr, "esc_shell_loop(): string_to_vector(%lx): %s\n", (unsigned long) input, strerror(errno));
			return(-1);
		}

//		command_count = 0;
//		while(command_vec[command_count]){
//			printf("DEBUG: command_vec[%d]: %s\n", command_count, command_vec[command_count]);
//			command_count++;
//		}
//		printf("DEBUG: command_count: %d\n", command_count);

		if(command_vec[0]){

			if(!strcmp(command_vec[0], "exit")){
				goto EXIT;
			}

			if(!(strcmp(command_vec[0], "help") && strcmp(command_vec[0], "?"))){
				esc_shell_help(command_vec);
			}

			// XXX This is where we'll send it back to the main process.
			printf("DEBUG: command_vec:");
			i = 0;
			while(command_vec[i]){
				printf(" %s", command_vec[i++]);
			}
			printf("\n");
		}

		linenoiseHistoryAdd(input);
		linenoiseHistorySetMaxLen(50);
		linenoiseFree(input);

		free_vector(command_vec);
	}

EXIT:
	printf("\r\nExiting revsh command shell. Releasing TTY I/O.\n(You may need to hit 'Enter' for a prompt.)\n");
	return(0);
}


void esc_shell_help(char **command_vec){

	//	printf("\n\n");
	printf("DEBUG: help(): ");

	if(command_vec[1]){
		printf("command: %s", command_vec[1]);
	}
	printf("\n");

}

char **completion_strings_initialize(){

	char **strings_vec = NULL;
	int i;	
	
	i = 0;

	return(strings_vec);
}

#endif
