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
		report_error("proxy_node_new(): Improper port forward syntax for proxy type '%d': %s", proxy_type, proxy_string);
		return(NULL);
	} 

	// Now let's start setting up the nodes.
	if((new_node = (struct proxy_node *) calloc(1, sizeof(struct proxy_node))) == NULL){
		report_error("proxy_node_new(): calloc(1, sizeof(struct proxy_node)): %s", strerror(errno));
		return(NULL);
	}
	new_node->type = proxy_type;	

	if((first = (char *) calloc(strlen(proxy_string) + 1, sizeof(char))) == NULL){
			report_error("proxy_node_new(): calloc(%d, sizeof(char)): %s", (int) strlen(proxy_string), strerror(errno));
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

		if(!second || (third = strchr(second, ':')) == NULL){
			report_error("proxy_node_new(): Malformed proxy string: %s", proxy_string);
			goto CLEANUP;
		}

		if((fourth = strchr((third + 1) , ':')) != NULL){
			new_node->lhost = first;
			new_node->lport = second;
			*(third++) = '\0';
			new_node->rhost_rport = third;
		}else{
			new_node->lhost = DEFAULT_PROXY_ADDR;
			new_node->lport = first;
			new_node->rhost_rport = second;
		}

	} else {
		goto CLEANUP;
	}

	if(proxy_listen(new_node) == -1){
		report_error("proxy_node_new(): proxy_listen() failed. Skipping this proxy.");
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
		report_error("proxy_listen(): getaddrinfo(%s, %s, %lx, %lx): %s", \
				cur_proxy_node->lhost, cur_proxy_node->lport, (unsigned long) &hints, (unsigned long) &ai, gai_strerror(rv));
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
		report_error("proxy_listen(): Failed to bind() to %s:%s", cur_proxy_node->lhost, cur_proxy_node->lport);
		return(-1);
	}
	freeaddrinfo(ai); 

	if(listen(listener, 10) == -1) {
		report_error("proxy_listen(): listen(%d, 10): %s", listener, strerror(errno));					
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
	char *rhost, *rport, *tmp_ptr;

	tmp_ptr = rhost_rport;
	if(*tmp_ptr == '['){
		tmp_ptr++;
	}

	count = strlen(tmp_ptr);

	if((rhost = (char *) calloc(count + 1, sizeof(char))) == NULL){
	}
	memcpy(rhost, tmp_ptr, count);

	if(tmp_ptr != rhost_rport){
		if((tmp_ptr = strchr(rhost, ']')) == NULL){
			free(rhost);
			return(connector);
		}
		*(tmp_ptr) = '\0';
	}
	if((rport = strrchr(rhost, ':')) == NULL){
		free(rhost);
		return(connector);
	}
	*(rport++) = '\0';

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	if((rv = getaddrinfo(rhost, rport, &hints, &ai)) != 0) {
		report_error("proxy_connect(): getaddrinfo(%s, %s, %lx, %lx): %s", rhost, rport, (unsigned long) &hints, (unsigned long) &ai, gai_strerror(rv));
		free(rhost);
		return(connector);
	}

	for(p = ai; p != NULL; p = p->ai_next) {
		connector = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (connector < 0) { 
			continue;
		}

		setsockopt(connector, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

		fcntl(connector, F_SETFL, O_NONBLOCK);
		errno = 0;
		if(connect(connector, p->ai_addr, p->ai_addrlen) < 0){
			if (errno != EINPROGRESS){
				close(connector);
				continue;
			}
		}
		break;
	}
	free(rhost);

	if(p == NULL){
		return(-1);
	}

	return(connector);
}

struct connection_node *connection_node_create(){

	struct connection_node *cur_connection_node, *tmp_connection_node;

	if((cur_connection_node = (struct connection_node *) calloc(1, sizeof(struct connection_node))) == NULL){
		report_error("connection_node_create(): calloc(1, %d): %s", (int) sizeof(struct connection_node), strerror(errno));
		return(NULL);
	}

	tmp_connection_node = io->connection_tail;
	if(!tmp_connection_node){
		io->connection_head = cur_connection_node;
		io->connection_tail = cur_connection_node;
	}else{
		tmp_connection_node->next = cur_connection_node;
		cur_connection_node->prev = tmp_connection_node;
		io->connection_tail = cur_connection_node;
	}

	io->fd_count++;
	return(cur_connection_node);
}

int connection_node_delete(unsigned short origin, unsigned short id){

	struct connection_node *tmp_connection_node;

	if((tmp_connection_node = connection_node_find(origin, id)) == NULL){
		return(-2);
	}

	if(tmp_connection_node == io->connection_head){
		io->connection_head = tmp_connection_node->next;
	}
	if(tmp_connection_node == io->connection_tail){
		io->connection_tail = tmp_connection_node->prev;
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
	if(tmp_connection_node->buffer_head){
		free(tmp_connection_node->buffer_head);
	}
	if(tmp_connection_node){
		free(tmp_connection_node);
	}

	io->fd_count--;
	return(0);
}


struct connection_node *connection_node_find(unsigned short origin, unsigned short id){
	struct connection_node *tmp_connection_node;

	tmp_connection_node = io->connection_head;
	while(tmp_connection_node){
		if((tmp_connection_node->origin == origin) && (tmp_connection_node->id == id)){
			return(tmp_connection_node);
		}
		tmp_connection_node = tmp_connection_node->next;
	}
	return(NULL);
}

void connection_node_queue(struct connection_node *cur_connection_node){

	if(cur_connection_node == io->connection_tail){
		return;
	}

	if(cur_connection_node == io->connection_head){
		io->connection_head = cur_connection_node->next;
	}
	if(cur_connection_node->prev){
		cur_connection_node->prev->next = cur_connection_node->next;
	}

	cur_connection_node->next->prev = cur_connection_node->prev;

	io->connection_tail->next = cur_connection_node;
	io->connection_tail = cur_connection_node;

}


int parse_socks_request(struct connection_node *cur_connection_node){

	int index, size;
	int nmethods, i;
	int len;
	char *head, *ptr;
	char *dst_port_ptr, *dst_addr_ptr, *domain_name;

	int atype = 0x01;


	head = cur_connection_node->buffer_head;
	ptr = cur_connection_node->buffer_tail;
	size = ptr - head;
	index = 0;

	if(!size){
		return(CON_SOCKS_NO_HANDSHAKE);
	}

	cur_connection_node->ver = *(head);
	if(head[index] == 4){

		/*
			 +----+----+----+----+----+----+----+----+----+----+....+----+
			 | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
			 +----+----+----+----+----+----+----+----+----+----+....+----+
			 1    1    2         4                   variable       1

			 1 + 1 + 2 + 4 + 1 
			 = 9  Minimum number of bytes to ensure we have at least 1 char of USERID.
		 */

		if(size < 9){
			return(CON_SOCKS_NO_HANDSHAKE);
		}

		index += 1;

		cur_connection_node->cmd = head[index];
		index += 1;

		dst_port_ptr = head + index;
		index += 2;

		dst_addr_ptr = head + index;
		index += 4;

		// Step through the "userid" we don't care about.
		while(head[index]){

			index++;
			if(index == size){
				return(CON_SOCKS_NO_HANDSHAKE);
			}
		}

		// Step through and grab the domain_name, if this is 4a.
		index++;
		if( \
				!dst_addr_ptr[0] && \
				!dst_addr_ptr[1] && \
				!dst_addr_ptr[2] && \
				dst_addr_ptr[3] \
			){

			if(!(index < size)){
				return(CON_SOCKS_NO_HANDSHAKE);
			}

			domain_name = head + index;
			while(head[index]){
				index++;
				if(index == size){
					return(CON_SOCKS_NO_HANDSHAKE);
				}
			}

			atype = 0x03;
			if((cur_connection_node->rhost_rport = addr_to_string(atype, domain_name, dst_port_ptr, strlen(domain_name))) == NULL){
				report_error("parse_socks_request(): addr_to_string(%d, %lx, %lx, %d): %s", \
						atype, (unsigned long) dst_addr_ptr, (unsigned long) dst_port_ptr, (int) strlen(domain_name), strerror(errno));
				return(-1);
			}

			return(CON_READY);
		}

		if((cur_connection_node->rhost_rport = addr_to_string(atype, dst_addr_ptr, dst_port_ptr, 0)) == NULL){
			report_error("parse_socks_request(): addr_to_string(%d, %lx, %lx, 0): %s", \
					atype, (unsigned long) dst_addr_ptr, (unsigned long) dst_port_ptr, strerror(errno));
			return(-1);
		}

		return(CON_READY);

	}else if(head[index] == 5){
		// SOCKS 5

		if(cur_connection_node->state == CON_SOCKS_NO_HANDSHAKE){
			index += 1;	
			if(!(index < size)){
				return(CON_SOCKS_NO_HANDSHAKE);
			}

			cur_connection_node->auth_method = 0xff;
			nmethods = head[index++];
			for(i = 0; i < nmethods; i++){

				if(!(index < size)){
					return(CON_SOCKS_NO_HANDSHAKE);
				}

				// Prefer uname/pass to no-auth. (uname/pass not yet implemented.)
				if(head[index] == 0x02){
				}else if(head[index] == 0x00){
					cur_connection_node->auth_method = 0x00;
				}

				index++;
			}

			return(CON_SOCKS_V5_AUTH);
		}else if(cur_connection_node->state == CON_SOCKS_V5_AUTH){


			/*

				 +----+-----+-------+------+----------+----------+
				 |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
				 +----+-----+-------+------+----------+----------+
				 | 1  |  1  | X'00' |  1   | Variable |    2     |
				 +----+-----+-------+------+----------+----------+
				 (First byte of "Variable" is the strlen of the string that follows in the DOMAINNAME case. No '\0' terminator.)

				 1 + 1 + 1 + 1 + 1
				 = 5  Minimum number of bytes before we can do anything interesting.
			 */

			if(size < 5){
				return(CON_SOCKS_NO_HANDSHAKE);
			}

			index += 1;

			cur_connection_node->cmd = head[index];
			index += 2;

			atype = head[index];
			index += 1;

			len = 4;
			dst_addr_ptr = head + index;
			dst_port_ptr = head + index + len;

			if(atype == 0x01){
				// From the diagram above. 4 + Variable + 2, where Variable is 4 in the ipv4 case.
				if(size < (4 + len  + 2)){
					return(CON_SOCKS_NO_HANDSHAKE);
				}
			}else if(atype == 0x03){
				len = head[index];

				// From the diagram above. 4 + Variable + 2, where Variable length is defined in the first octet.
				if(size < (4 + 1 + len + 2)){
					return(CON_SOCKS_NO_HANDSHAKE);
				}
				dst_addr_ptr = head + index + 1;
				dst_port_ptr = head + index + 1 + len;
			} else if(atype == 0x04){
				len = 16;

				// From the diagram above. 4 + Variable + 2, where Variable is 16 in the ipv6 case.
				if(size < (4 + len + 2)){
					return(CON_SOCKS_NO_HANDSHAKE);
				}
				dst_addr_ptr = head + index;
				dst_port_ptr = head + index + len;
			}


			if((cur_connection_node->rhost_rport = addr_to_string(atype, dst_addr_ptr, dst_port_ptr, len)) == NULL){
				report_error("parse_socks_request(): addr_to_string(%d, %lx, %lx, 0): %s", \
						atype, (unsigned long) dst_addr_ptr, (unsigned long) dst_port_ptr, strerror(errno));
				return(-1);
			}

			return(CON_READY);
		}
	}

	return(-1);
}


// If atype is 0x03, then len is the length of the addr string.
// If atype isn't 0x03, len is ignored.
char *addr_to_string(int atype, char *addr, char *port, int len){

	char *ptr;
	unsigned short int port_num = ntohs(*((unsigned short int *)(port)));

	// strlen("255.255.255.255:65535") -> 21
	int string_len = 21;

	if(atype == 0x03){
		string_len = len;
		// strlen(":65535") -> 6
		string_len += 6;

	}else if(atype == 0x04){
		// strlen("[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535") -> 47 
		string_len = 47;
	}

	if((ptr = (char *) calloc(string_len + 1, sizeof(char))) == NULL){
		report_error("addr_to_string(): calloc(%d, %d): %s", string_len + 1, (int) sizeof(char), strerror(errno));
		return(NULL);
	}

	string_len++;
	if(atype == 0x03){
		snprintf(ptr, string_len, "%s:%d", addr, port_num);
	}else if(atype == 0x04){
		snprintf(ptr, string_len, "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%d", \
				(unsigned char) addr[0], (unsigned char) addr[1], (unsigned char) addr[2], (unsigned char) addr[3], \
				(unsigned char) addr[4], (unsigned char) addr[5], (unsigned char) addr[6], (unsigned char) addr[7], \
				(unsigned char) addr[8], (unsigned char) addr[9], (unsigned char) addr[10], (unsigned char) addr[11], \
				(unsigned char) addr[12], (unsigned char) addr[13], (unsigned char) addr[14], (unsigned char) addr[15], \
				port_num);
	}else{
		snprintf(ptr, string_len, "%d.%d.%d.%d:%d", (unsigned char) addr[0], (unsigned char) addr[1], (unsigned char) addr[2], (unsigned char) addr[3], port_num);
	}

	return(ptr);
}

/*
Cases:
4 / 4A:
+----+----+-----+-----+
|VER |CMD |PORT |ADDR |
+----+----+-----+-----+
|1   |1   |2    |4    |
+----+----+-----+-----+

Connect:
VER -> 0x00
CMD -> 0x5A
PORT -> // ignored, pad w/zeros
ADDR -> // ignored, pad w/zeros

Bind:
VER -> 0x00
CMD -> 0x5A
PORT -> // port of the listenting socket
ADDR -> // address of the listening socket

5:
+----+----+-----+-----+--------+-----+
|VER |CMD |RSV  |ATYP |ADDR    |PORT |
+----+----+-----+-----+--------+-----+
|1   |1   |'\0' |1    |4 or 16 |2    |
+----+----+-----+-----+--------+-----+

Connect:
VN -> 0x05
CD -> 0x00
ATYP -> // address type
PORT -> // port of the connecting socket
ADDR -> // address of the connecting socket

Bind (first reply):
VN -> 0x05
CD -> 0x00
ATYP -> // address type
PORT -> // port of the listening socket
ADDR -> // address of the listening socket

Bind (second reply):
VN -> 0x05
CD -> 0x00
ATYP -> // address type
PORT -> // port of the connectin socket
ADDR -> // address of the connecting socket

Case with largest response size:
Socks 5, IPv6, bind (which requires *two* responses)
(1 + 1 + 1 + 1 + 16 + 2) * 2
= (22) * 2
= 44 bytes
 */
#define MAX_RESPONSE_SIZE 44

// Use the new DT_PROXY_HT_RESPONSE to send back port / addr info.
// - Actually, just have the response be the exact response to be sent back to the client!
// - And don't worry about a new buffer. Just stuff it into the message buffer and pass it through!
// - Use getsockname() to gather the data.
// - http://beej.us/guide/bgnet/output/html/multipage/sockaddr_inman.html
// - http://long.ccaba.upc.edu/long/045Guidelines/eva/ipv6.html

int proxy_response(int sock, char ver, char cmd, char *buffer, int buffer_size){

	int retval;
	char *buff_ptr;
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);


	// Response for a point-to-point proxy being requested. NOP out.
	if(ver == 0){
		return(0);
	}

	if(buffer_size < MAX_RESPONSE_SIZE){
		return(-1);
	}
	memset(buffer, 0x00, MAX_RESPONSE_SIZE);	

	buff_ptr = buffer;
	if(ver == 0x04){
		if(cmd == 0x01){

			// ver
			*(buff_ptr++) = 0x00;
			// cmd
			*((unsigned char *) buff_ptr++) = 0x5a;
			// port and addr are already 0x00 from the memset above.
			buff_ptr += 6;

			return(buff_ptr - buffer);

		}else if(cmd == 0x02){
			// XXX ignored until we implement bind.
		}
	}else if(ver == 0x05){
		if(cmd == 0x01){

			// ver
			*(buff_ptr++) = 0x05;
			// cmd
			*(buff_ptr++) = 0x00;
			// rsv 
			*(buff_ptr++) = 0x00;

			if((retval = getsockname(sock, (struct sockaddr *)&addr, &addrlen)) == -1){
				report_error("proxy_response(): getsockname(%d, %lx, %lx): %s", \
						sock, (unsigned long) &addr, (unsigned long) &addrlen, strerror(errno));
				return(-1);
			}

			if(addr.ss_family == AF_INET){

				// atyp
				*(buff_ptr++) = 0x01;
				// addr
				memcpy(buff_ptr, &(((struct sockaddr_in *) &addr)->sin_addr), 4);
				buff_ptr += 4;
				// port
				memcpy(buff_ptr, &(((struct sockaddr_in *) &addr)->sin_port), 2);
				buff_ptr += 2;

			}else if(addr.ss_family == AF_INET6){

				// atyp
				*(buff_ptr++) = 0x04;
				// addr
				memcpy(buff_ptr, &(((struct sockaddr_in6 *) &addr)->sin6_addr), 16);
				buff_ptr += 16;
				// port
				memcpy(buff_ptr, &(((struct sockaddr_in6 *) &addr)->sin6_port), 2);
				buff_ptr += 2;

			}

			return(buff_ptr - buffer);

		}else if(cmd == 0x02){
			// XXX ignored until we implement bind.
		}
	}

	return(-1);	
}
