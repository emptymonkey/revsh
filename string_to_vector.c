
#include "common.h"


/**********************************************************************************************************************
 *
 * string_to_vector()
 *
 * Input: A string of tokens, whitespace delimited, null terminated.
 * Output: An array of strings containing the tokens. The array itself is also null terminated. NULL will be returned
 *	on error.
 *
 * Purpose: Tokenize a string for later consumption. 
 *
 **********************************************************************************************************************/
char **string_to_vector(char *command_string){

	int was_space = 1;
	int count = 0;
	int i, len;

	char *index;
	char *token_start = NULL;

	char **argv;

	index = command_string;
	while(*index){

		/*  Lets step through the string and look for tokens. We aren't grabbing them yet, just counting them. */
		/*  Note, we are looking at the transition boundaries from space->!space and !space->space to define the */
		/*  token. "count" will denote these transitions. An odd count implies that we are in a token. An even */
		/*  count implies we are between tokens. */
		if(isspace(*index)){
			if(!was_space){
				/*  end of a token. */
				count++;
			}
			was_space = 1;
		}else{
			if(was_space){
				/*  start of a token. */
				count++;
			}
			was_space = 0;
		}
		index++;
	}

	/*  Don't forget to account for the case where the last token is up against the '\0' terminator with no space */
	/*  between. */
	if(count % 2){
		count++;
	}

	/*  Now, (count / 2) will be the number of tokens. Since we know the number of tokens, lets setup argv. */
	// free() called in free_vector().
	if((argv = (char **) malloc((sizeof(char *) * ((count / 2) + 1)))) == NULL){
		report_error("string_to_vector(): malloc(%d): %s", (int) ((sizeof(char *) * ((count / 2) + 1))), strerror(errno));
		return(NULL);
	}
	memset(argv, 0, (sizeof(char *) * ((count / 2) + 1)));

	/*  Now, let's do that loop again, this time saving the tokens. */
	i = 0;
	len = 0;
	count = 0;
	was_space = 1;
	index = command_string;
	while(*index){
		if(isspace(*index)){
			if(!was_space){
				/*  end of a token. */
				// free() called in free_vector().
				if((argv[i] = (char *) malloc(sizeof(char) * (len + 1))) == NULL){
					report_error("string_to_vector(): malloc(%d): %s", (int) (sizeof(char) * (len + 1)), strerror(errno));
					goto CLEAN_UP;
				}
				memset(argv[i], 0, sizeof(char) * (len + 1));
				memcpy(argv[i], token_start, sizeof(char) * len);
				i++;
				len = 0;
				count++;
			}
			was_space = 1;
		}else{
			if(was_space){
				/*  start of a token. */
				count++;
				token_start = index;
			}
			len++;
			was_space = 0;
		}
		index++;
	}

	/*  Same final token termination case. */
	if(count % 2){
		// free() called in free_vector().
		if((argv[i] = malloc(sizeof(char) * (len + 1))) == NULL){
			report_error("string_to_vector(): malloc(%d): %s", (int) (sizeof(char) * (len + 1)), strerror(errno));
			goto CLEAN_UP;
		}
		memset(argv[i], 0, sizeof(char) * (len + 1));
		memcpy(argv[i], token_start, sizeof(char) * len);
	}

	return(argv);

CLEAN_UP:
	i = 0;
	while(argv[i]){
		free(argv[i]);
		i++;
	}

	free(argv);
	return(NULL);
}

void free_vector(char **vector){

	char **tmp_vector;
	char *tmp_string;


	tmp_vector = vector;
	tmp_string = *(tmp_vector++);

	while(tmp_string){
		free(tmp_string);
		tmp_string = *(tmp_vector++);
	}

	free(vector);
}


// Calls wordexp() first to handle commandline style tokenization,
// but returns it in a vector format.
char **cli_to_vector(char *command){

	int retval;
	wordexp_t word;

	unsigned int i;
	int tmp_len;
	char **tmp_ptr;

	tmp_len = 0;
	if(!(retval = wordexp(command, &word, 0))){
		tmp_len = word.we_wordc;
	}

	if((tmp_ptr = (char **) calloc(tmp_len + 1, sizeof(char *))) == NULL){
		report_error("cli_to_vector(): calloc(%d, %d): %s", tmp_len + 1, (int) sizeof(char *), strerror(errno));
		wordfree(&word);
		return(NULL);
	}

	if(!retval){
		for(i = 0; i < word.we_wordc; i++){
			tmp_len = strlen(word.we_wordv[i]);
			
			if((tmp_ptr[i] = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
				report_error("cli_to_vector(): calloc(%d, %d): %s", tmp_len + 1, (int) sizeof(char), strerror(errno));
			}
			memcpy(tmp_ptr[i], word.we_wordv[i], tmp_len);
		}
		wordfree(&word);
	}

	return(tmp_ptr);
}


// First two bytes are are an unsigned short in network order determining the size of the data to follow.
// The data are strings back to back with null termination as expected. 
char *pack_vector(char **command_vec){
	unsigned short count;
	int tmp_len;
	char *buff_ptr, *tmp_ptr;


	count = 0;
	tmp_len = 0;
	while(command_vec[tmp_len]){
		count += strlen(command_vec[tmp_len]) + 1;
		tmp_len++;
	}
	count += sizeof(unsigned short);

	if((buff_ptr = (char *) calloc(count, sizeof(char))) == NULL){
		report_error("pack_vector(): calloc(%d, %d): %s", count, (int) sizeof(char), strerror(errno));
	}

	tmp_ptr = buff_ptr;
	count = htons(count);
	memcpy(tmp_ptr, &count, sizeof(unsigned short));
	tmp_ptr += sizeof(unsigned short);

	count = 0;
	tmp_len = 0;
	while(command_vec[tmp_len]){
		count = strlen(command_vec[tmp_len]) + 1;
		memcpy(tmp_ptr, command_vec[tmp_len], count);
		tmp_ptr += count;
		tmp_len++;
	}

	return(buff_ptr);
}

char **unpack_vector(char *packed_command){
	unsigned short count;
	char **vec_ptr;
	char *tmp_ptr;
	int tmp_len;
	int i;


	tmp_ptr = packed_command;
	memcpy(&count, tmp_ptr, sizeof(unsigned short));
	count = ntohs(count);
	tmp_ptr += sizeof(unsigned short);

	tmp_len = 0;
	for(i = 0; i < (count - (int) sizeof(unsigned short)); i++){

		if(tmp_ptr[i] == '\0'){
			tmp_len++;
		}
	}

	if((vec_ptr = (char **) calloc(tmp_len + 1, sizeof(char *))) == NULL){
		report_error("unpack_vector(): calloc(%d, %d): %s", tmp_len + 1, (int) sizeof(char *), strerror(errno));
		return(NULL);
	}

	count = tmp_len;
	for(i = 0; i < count; i++){
		tmp_len = strlen(tmp_ptr);
		if((vec_ptr[i] = (char *) calloc(tmp_len + 1, sizeof(char))) == NULL){
			report_error("unpack_vector(): calloc(%d, %d): %s", tmp_len + 1, (int) sizeof(char), strerror(errno));
		}
		memcpy(vec_ptr[i], tmp_ptr, tmp_len);
		tmp_ptr += tmp_len + 1;
	}

	return(vec_ptr);
}


// original vector is destroyed. NULL on error.
char **vector_push(char **vector, char *string){

  char **tmp_vector = NULL;
  int count;
  int i;


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


