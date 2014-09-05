
// Basic object for organizing I/O structures and interfaces.

struct remote_io_helper {

	// Denote whether this instance is on the control node or the target node.
	int controller;
	int encryption;
	
	int local_fd;
	int remote_fd;

	char *ip_addr;

	BIO *connect;
	SSL_CTX *ctx;
	SSL *ssl;
	DH *dh;

	// We use pointers to functions here so we can invoke the appropriate function on the backend (crypto / no crypto).
	int (*remote_read)(struct remote_io_helper *io, void *buf, size_t count);
	int (*remote_write)(struct remote_io_helper *io, void *buf, size_t count);
	int (*remote_printf)(struct remote_io_helper *io, char *fmt, ...);

};
