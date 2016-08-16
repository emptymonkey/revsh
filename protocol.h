
/**********************************************************************************************************************
 *
 * Message Bus Protocol Specification:
 *
 *	Header:
 *		- header_len		: unsigned short (network order)
 *			-- This is the size of the remaining header data.
 *		- data_type			:	unsigned char
 *		- data_len			:	unsigned short (network order)
 *		- Other data_type specific headers, as needed.
 *
 *	Other headers used with DT_PROXY and DT_CONNECTION:
 *		- header_type		: unsigned short (network order)
 *		- header_id			: unsigned long (network order)
 *
 *	Body:
 *		- data					:	void *
 *
 *
 *	The naming convetion below is DT for "Data Type" and HT for "Header Type".
 *	E.g. DT_PROXY_HT_CREATE denotes a message where the data type is that of a proxy, but the header will have
 *  additional information relating to the type of request, in this case "create" the proxy.
 *
 **********************************************************************************************************************/

/* This is the smallest message size we will respect when asked by the remote connection. */
#define MINIMUM_MESSAGE_SIZE	1024

/* Data Types */
/* DT_INIT: Initialization sequence data. */
#define DT_INIT				1

/* DT_TTY: TTY interaction data. */
/* This message type is always given priority because, despite added funcitionality, we are still a shell at heart. */
#define DT_TTY				2

/* DT_WINRESIZE: Window re-size event data. */
#define DT_WINRESIZE	3

/* DT_PROXY: Proxy meta-data. (e.g. setup, teardown, etc.) */
#define DT_PROXY			4
/*
	 In a DT_PROXY_HT_CREATE request, the first char will be ver, the second char will be cmd.
	 Null terminated rhost_rport string follows.
 */
#define DT_PROXY_HT_CREATE				1
#define DT_PROXY_HT_DESTROY				2
#define DT_PROXY_HT_RESPONSE			3

/* DT_CONNECTION: Information related to established proxy connections. */
#define DT_CONNECTION	5
/* Normal data to be brokered back and forth. */
#define DT_CONNECTION_HT_DATA			0
/*
	 DT_CONNECTION_HT_DORMANT is used when a fd would block for writting, and our message queue is getting deep.
	 Tells the other side to stop reading from the associated remote fd until otherwise notified. Reset to normal
	 with DT_CONNECTION_HT_ACTIVE once the message write queue for this connection is empty. 
 */
#define DT_CONNECTION_HT_DORMANT	1
#define DT_CONNECTION_HT_ACTIVE		2

/* DT_NOP: No Operation dummy message used for network keep-alive. */
#define DT_NOP				6

/* DT_ERROR: Used to send error reporting back to the controller for logging. */
#define DT_ERROR			7

/* DT_TAP and DT_TUN allow for forwarding raw ethernet frames and raw ip packets, respectfully, via a tun/tap device. */
#define DT_TAP				8
#define DT_TUN				9
