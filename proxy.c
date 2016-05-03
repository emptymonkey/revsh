#include "common.h"


struct proxy_node *proxy_node_new(char *proxy_string, int proxy_type){

	struct proxy_node *new_node;

	char *first = NULL;
	char *second = NULL;
	char *third = NULL;
	char *fourth = NULL;

	unsigned int count;
	char *tmp;


	// First, quick syntax check.
	count = 0;
	tmp = proxy_string;
	while((tmp = strchr(tmp, ':')) != NULL){
		count++;
		tmp++;
	}

	if((proxy_type == PROXY_DYNAMIC && !(count == 0 || count == 1)) \
			|| (proxy_type == PROXY_LOCAL && !(count == 2 || count == 3))){
		if(verbose){
			fprintf(stderr, "%s: Improper port forward syntax for proxy type '%d': %s\r\n", \
				program_invocation_short_name, proxy_type, proxy_string);
		}
		return(NULL);
	} 

	// Now let's start setting up the nodes.
	if((new_node = (struct proxy_node *) calloc(1, sizeof(struct proxy_node))) == NULL){
		if(verbose){
			fprintf(stderr, "%s: calloc(1, sizeof(struct proxy_node)): %s\r\n", \
				program_invocation_short_name, strerror(errno));
		}
		return(NULL);
	}
	new_node->type = proxy_type;	

	if((first = (char *) calloc(strlen(proxy_string), sizeof(char))) == NULL){
		if(verbose){
			fprintf(stderr, "%s: calloc(%d, sizeof(char)): %s\r\n", \
				program_invocation_short_name, (int) strlen(proxy_string), strerror(errno));
		}
		free(new_node);
		return(NULL);
	}

	strcpy(first, proxy_string);
	
	if((second = strchr(first, ':')) != NULL){
		*(second++) = '\0';
	}

	if(proxy_type == PROXY_DYNAMIC){
		
		if(second){
			new_node->lhost = first;
			new_node->lport = second;
		}else{
			new_node->lhost = DEFAULT_PROXY_ADDR;
			new_node->lport = first;
		}

	} else if(proxy_type == PROXY_LOCAL) {

		if((third = strchr(second, ':')) == NULL){
			if(verbose){
				fprintf(stderr, "%s: Malformed proxy string: %s\r\n", \
						program_invocation_short_name, proxy_string);
			}
			goto CLEANUP;
		}

		if((fourth = strchr((third + 1) , ':')) != NULL){
			new_node->lhost = first;
			new_node->lport = second;
			new_node->rhost_rport = third + 1;
		}else{
			new_node->lhost = DEFAULT_PROXY_ADDR;
			new_node->lport = first;
			new_node->rhost_rport = second;
		}

	} else {
		goto CLEANUP;
	}

	if(proxy_listen(new_node) == -1){
		if(verbose){
			fprintf(stderr, "%s: proxy_listen() failed. Skipping this proxy.\r\n", \
					program_invocation_short_name);
		}
		goto CLEANUP;
	}

	return(new_node);

CLEANUP:
	free(new_node);	
	free(first);
	return(NULL);
}

/* setup a new proxy listener */
int proxy_listen(struct proxy_node *cur_proxy_node){

	int yes = 1;
	int rv, listener;
	struct addrinfo hints, *ai, *p;

	if(verbose){
		printf("DEBUG:\tcur_proxy_node->lhost: %s\r\n", cur_proxy_node->lhost);
		printf("DEBUG:\tcur_proxy_node->lport: %s\r\n", cur_proxy_node->lport);
		printf("DEBUG:\tcur_proxy_node->rhost_rport: %s\r\n", cur_proxy_node->rhost_rport);
		printf("DEBUG:\tcur_proxy_node->type: %d\r\n", cur_proxy_node->type);
	}

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if((rv = getaddrinfo(cur_proxy_node->lhost, cur_proxy_node->lport, &hints, &ai)) != 0) {
		if(verbose){
			fprintf(stderr, "%s: getaddrinfo(%s, %s, %lx, %lx): %s\r\n", \
					program_invocation_short_name, \
					cur_proxy_node->lhost, cur_proxy_node->lport, (unsigned long) &hints, (unsigned long) &ai, \
					gai_strerror(rv));
		}
		return(-1);
	}

	for(p = ai; p != NULL; p = p->ai_next) {
		listener = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (listener < 0) { 
			continue;
		}

		setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

		if(bind(listener, p->ai_addr, p->ai_addrlen) < 0){
			close(listener);
			continue;
		}

		break;
	}

	if(p == NULL){
		if(verbose){
			fprintf(stderr, "%s: Failed to bind() to %s:%s\r\n", \
					program_invocation_short_name, \
					cur_proxy_node->lhost, cur_proxy_node->lport);
		}
		return(-1);
	}
	freeaddrinfo(ai); 

	if(listen(listener, 10) == -1) {
		if(verbose){
			fprintf(stderr, "%s: listen(%d, 10): %s\r\n", \
					program_invocation_short_name, \
					listener, \
					strerror(errno));					
		}
		return(-1);
	}

	fcntl(listener, F_SETFL, O_NONBLOCK);
	cur_proxy_node->fd = listener;

	return(0);
}

int proxy_connect(char *rhost_rport){

	int count;
	int yes = 1;
	int rv, connector = -1;
	struct addrinfo hints, *ai, *p;
	char *rhost, *rport;

	count = strlen(rhost_rport);
	if((rhost = (char *) calloc(count + 1, sizeof(char))) == NULL){
	}
	memcpy(rhost, rhost_rport, count);
	if((rport = strchr(rhost, ':')) == NULL){
	}
	*(rport++) = '\0';

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if((rv = getaddrinfo(rhost, rport, &hints, &ai)) != 0) {
		if(verbose){
			fprintf(stderr, "%s: getaddrinfo(%s, %s, %lx, %lx): %s\r\n", \
					program_invocation_short_name, \
					rhost, rport, (unsigned long) &hints, (unsigned long) &ai, \
					gai_strerror(rv));
		}
		return(-1);
	}

	for(p = ai; p != NULL; p = p->ai_next) {
		connector = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (connector < 0) { 
			continue;
		}

		setsockopt(connector, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

		if(connect(connector, p->ai_addr, p->ai_addrlen) < 0){
			close(connector);
			continue;
		}
		break;
	}

	return(connector);
}

struct connection_node *connection_node_create(struct connection_node **head){

	struct connection_node *cur_connection_node, *tmp_connection_node;

	if((cur_connection_node = (struct connection_node *) calloc(1, sizeof(struct connection_node))) == NULL){
		if(verbose){
			fprintf(stderr, "%s: calloc(1, %d): %s\r\n", \
					program_invocation_short_name, \
					(int) sizeof(struct connection_node), \
					strerror(errno));
		}
		return(NULL);
	}

	tmp_connection_node = *(head);
	if(tmp_connection_node){
		while(tmp_connection_node->next){
			tmp_connection_node = tmp_connection_node->next;
		}

		tmp_connection_node->next = cur_connection_node;
		cur_connection_node->prev = tmp_connection_node;
	}else{
		*(head) = cur_connection_node;
	}
	return(cur_connection_node);
}

int connection_node_delete(unsigned short origin, unsigned short id, struct connection_node **head){

	struct connection_node *tmp_connection_node;

	if((tmp_connection_node = connection_node_find(origin, id, head)) == NULL){
		return(0);
	}

	if(tmp_connection_node == *(head)){
		*(head) = NULL;
	}
	if(tmp_connection_node->prev){
		tmp_connection_node->prev->next = tmp_connection_node->next;
	}
	if(tmp_connection_node->next){
		tmp_connection_node->next->prev = tmp_connection_node->prev;
	}

	if(tmp_connection_node->fd){
		close(tmp_connection_node->fd);
	}
	if(tmp_connection_node->rhost_rport){
		free(tmp_connection_node->rhost_rport);
	}
	if(tmp_connection_node){
		free(tmp_connection_node);
	}
	return(1);
}


struct connection_node *connection_node_find(unsigned short origin, unsigned short id, struct connection_node **head){
	struct connection_node *tmp_connection_node;

	tmp_connection_node = *(head);
	while(tmp_connection_node){
		if((tmp_connection_node->origin == origin) && (tmp_connection_node->id == id)){
			return(tmp_connection_node);
		}
		tmp_connection_node = tmp_connection_node->next;
	}
	return(NULL);
}
