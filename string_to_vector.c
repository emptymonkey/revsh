
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
