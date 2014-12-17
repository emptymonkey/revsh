struct configuration_helper {

	int interactive;
	int bindshell;
	int verbose;

	char *env_string;
	char *ip_addr;
	char *keys_dir;
	char *rc_file;
	char *shell;

	int keepalive;

	unsigned int retry_start;
	unsigned int retry_stop;
	unsigned int timeout;

#ifdef OPENSSL
	int encryption;
	char *cipher_list;
#endif /* OPENSSL */

};


/* Basic object for organizing I/O structures and interfaces. */

struct io_helper {

	/* Denote whether this instance is on the control node or the target node. */
	int controller;

	/* We use pointers to functions here so we can invoke the appropriate function on the backend (crypto / no crypto). */
	int (*remote_read)(struct io_helper *io, void *buf, size_t count);
	int (*remote_write)(struct io_helper *io, void *buf, size_t count);

	int local_in_fd;
	int local_out_fd;
	int remote_fd;


#ifdef OPENSSL
	BIO *connect;
	SSL_CTX *ctx;
	SSL *ssl;
	DH *dh;

	const EVP_MD *fingerprint_type;
#endif /* OPENSSL */

};
