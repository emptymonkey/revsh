
/******************************************************************************
 * struct message_helper
 *   Assists in sending and receiving messages. 
 ******************************************************************************/
struct message_helper {
	unsigned char data_type;
	unsigned short data_len;

	// Header types are defined in the protocol.h file.
	unsigned short header_type;

	// header_origin is the "io->target" value of the connection initializer.
	// header_id is the fd of the connection on the initializer's end.
	// (header_origin, header_id) as a tuple forms a unique identifier for the
	// connection recognized by both nodes.
	unsigned short header_origin;
	unsigned short header_id;

	// Proxy types are defined in the protocol.h file.
	unsigned short header_proxy_type;

	char *data;

	struct message_helper *next;
};


/******************************************************************************
 * struct proxy_request_node
 *   Assists in tracking proxies that are requested on the command line.
 *   These may or may not become real proxies later on.
 ******************************************************************************/
struct proxy_request_node {
	char *request_string;
	int type;
	int remote;

	struct proxy_request_node *next;
};


/******************************************************************************
 * struct config_helper
 *   Tracks the different configuration options that were set for this run.
 ******************************************************************************/
struct config_helper {

	unsigned char interactive;

	int bindshell;

	char *socks;
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

	// The proxy requests are setup as a linked list here. 
	// This was the solution I came up with for an arbitrary number of proxies
	// requested by the user on the command line, any number of which may or
	// may not actually successfully listen down the road.
	struct proxy_request_node *proxy_request_head;

};


/******************************************************************************
 * struct proxy_node
 *   Tracks the actual proxy listeners.
 ******************************************************************************/
struct proxy_node {

	unsigned short origin;
	unsigned short id;
	unsigned short proxy_type;

	// Remembers the original malloc() address. Depending on the case, this 
	// value will end up in one of the strings below. Adding this pointer will 
	// simplify the free() call later.
	char *mem_ptr;

	// The strings representing this proxy may be used later on for error reporting.
	char *lhost;
	char *lport;
	char *rhost_rport;

	int fd;

	// pointer to the original request string;
	char *orig_request;

	struct proxy_node *next;
	struct proxy_node *prev;
};


/******************************************************************************
 * struct connection_node
 *   Tracks established data connections. (Can be of any of the non-tty 
 *   varieties.)
 ******************************************************************************/
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

	unsigned long io_read;
	unsigned long io_written;

	// This will allow for write queues.
	//  Note, no write_tail element. Iterate through every time you want to add an element, thus calculating the message depth dynamically.
	//  If MAX_MESSAGE_DEPTH is hit, tell the remote node to stop listening its associated fd.
	struct message_helper *write_head;

	struct connection_node *next;
	struct connection_node *prev;
};


/******************************************************************************
 * struct io_helper
 *   Tracks the state of IO in the application.
 *   There should only ever be one of these, and it is a global.
 ******************************************************************************/
struct io_helper {

	unsigned short control_proto_major;
	unsigned short control_proto_minor;

	unsigned short target_proto_major;
	unsigned short target_proto_minor;

	/* Denote whether this node is a target node or the control node. */
	// Done as a "target" flag, so control is always 0. If we expand to allow node chaining in the future,
	// then each target node will have a non-zero target number. This is for future expansion.
	int target;
	int child_sid;

	/* We use pointers to functions here so we can invoke the appropriate function on the backend (crypto / no crypto). */
	int (*remote_read)(void *buf, size_t count);
	int (*remote_write)(void *buf, size_t count);

	int local_in_fd;
	int local_out_fd;
	int remote_fd;

	// This is the match for the config->interactive, but represents the actual state of interaction for this run. 
	// Useful in the keepalive case.
	int interactive;

	// Save the original tty settings here for inspection during runtime and later restoration.
	struct termios *saved_termios_attrs;
	struct termios *revsh_termios_attrs;

	// Stores transient tty state info.
	struct winsize *tty_winsize;

	// If no logging setup, this will remain NULL.
	FILE *log_stream;

	// Fixed size of all message->data buffers. 
	unsigned short message_data_size;

	// this message_helper node is used internally by the io_helper for the processing of the message bus.
	struct message_helper message;

	// flag for EOF condition.
	int eof;

	// Flag representing that the initialization process has completed. Used in report_error() to determine
	// if it is ok to leverage the message bus for error reporting.
	int init_complete;

	// this message_helper node is used for the write buffer queue for the tty/shell.
	struct message_helper *tty_write_head;

	unsigned long tty_io_read;
	unsigned long tty_io_written;

#ifdef OPENSSL
	BIO *connect;
	SSL_CTX *ctx;
	SSL *ssl;
	DH *dh;

	const EVP_MD *fingerprint_type;
#endif /* OPENSSL */

	// Linked list of proxy listeners.
	struct proxy_node *proxy_head;
	struct proxy_node *proxy_tail;

	// Linked list of established connections.
	struct connection_node *connection_head;
	struct connection_node *connection_tail;

	// Used to track number of open fds. Select can't handle more than 1024.
	unsigned int fd_count;

	// Used to handle escape character ('~') interactions.
	unsigned int escape_state;
	unsigned int escape_depth;

	char *local_in_buffer;
	int local_in_count;

};
