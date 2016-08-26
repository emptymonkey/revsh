
/* An object to assist in sending and recieving messages. */
struct message_helper {
	unsigned char data_type;
	unsigned short data_len;

	// Additional header info:
	//	* header_type: subtype defining what is going on.
	//	* header_id: the id number of the proxy connection.
	//	* header_errno: The errno for the remote request that has failed.
	unsigned short header_type;
	unsigned short header_origin;
	unsigned short header_id;
	unsigned short header_proxy_type;

	char *data;

	struct message_helper *next;
};

/* This struct allows for tracking of proxies being requested on the command line. They may or may not become real proxies later on. */
struct proxy_request_node {
	char *request_string;
	int type;
	
	struct proxy_request_node *next;
};

/* An object representing how the different configuration options were set for this run. */
struct config_helper {

	unsigned char interactive;

	int bindshell;
	int tun;
	int tap;

	char *ip_addr;
	char *keys_dir;
	char *rc_file;
	char *shell;
	char *local_forward;
	char *log_file;

	int keepalive;
	int nop;

	unsigned int retry_start;
	unsigned int retry_stop;
	unsigned int timeout;

#ifdef OPENSSL
	int encryption;
	char *cipher_list;
#endif /* OPENSSL */

	struct proxy_request_node *proxy_request_head;

};

/* A node for a linked list of proxy listeners. */
struct proxy_node {
	char *lhost;
	char *lport;
	char *rhost_rport;

	int type;
	int fd;

	struct proxy_node *next;
};

/* A node for a linked list of tunneled data connections. */
struct connection_node {

	unsigned short origin;
	unsigned short id;
	unsigned short proxy_type;
	int fd;

	// A copy of the original rhost_rport string in the related proxy_node struct, to simplify retry requests.
	// Note, this has to be a copy, because in the remote connection state, the original proxy node does not exist.
	char *rhost_rport;

	// This buffer is used to cache socks request data during a proxy setup.
	char *buffer_head;
	char *buffer_ptr;
	char *buffer_tail;
	unsigned int buffer_size;

	// Current state of the connecction. (E.g. CON_EINPROGRESS, CON_ACTIVE, etc.)
	unsigned int state;
	
	unsigned char ver;
	unsigned char cmd;
	unsigned char auth_method;

	/* Use these when implementing rfc1929.
		 char ulen;
		 char *uname;
		 char plen;
		 char *passwd;
	 */

	// This will allow for write queues.
	//  Note, no write_tail element. Iterate through every time you want to add an element, thus calculating the message depth dynamically.
  //  If MAX_MESSAGE_DEPTH is hit, do the needful.
	struct message_helper *write_head;

	struct connection_node *next;
	struct connection_node *prev;
};

/* An object for organizing I/O structures and interfaces. */
struct io_helper {

	/* Denote whether this instance is on the control node or the target node. */
	int controller;
	int child_sid;

	/* We use pointers to functions here so we can invoke the appropriate function on the backend (crypto / no crypto). */
	int (*remote_read)(void *buf, size_t count);
	int (*remote_write)(void *buf, size_t count);

	int local_in_fd;
	int local_out_fd;
	int remote_fd;

	FILE *log_stream;

	// Fixed size of all message->data buffers. 
	unsigned short message_data_size;

	// this message_helper node is used internally by the io_helper for the processing of the message bus.
	struct message_helper message;
	int eof;

	// Flag representing that the initialization process has completed. Used in report_error() to determine
  // if it is ok to leverage the message bus for error reporting.
	int init_complete;

	// this message_helper node is used for the write buffer queue for the tty/shell.
	struct message_helper *tty_write_head;


#ifdef OPENSSL
	BIO *connect;
	SSL_CTX *ctx;
	SSL *ssl;
	DH *dh;

	const EVP_MD *fingerprint_type;
#endif /* OPENSSL */

	struct proxy_node *proxy_head;
	struct proxy_node *proxy_tail;

	struct connection_node *connection_head;
	struct connection_node *connection_tail;

	struct winsize *tty_winsize;

	int fd_count;

};
