
// XXX Add information about the bootstrap phase.

/**********************************************************************************************************************
 *
 * Message Bus Protocol Specification:
 *
 *	Header:
 *		- header_len		: unsigned short (network order)	:	size of the remaining header data.
 *		- data_type			:	unsigned char
 *		- data_len			:	unsigned short (network order)
 *		- Other data_type specific headers, if applicable, as noted below.
 *
 *	Other headers used with DT_PROXY and DT_CONNECTION:
 *		- header_type				: unsigned short (network order)
 *		- header_origin			: unsigned long (network order)	:	Lists if controller or target is the owner.
 *		- header_id					: unsigned long (network order)	:	FD of the connection at it's origin.
 *		- header_proxy_type	: unsigned long (network order)	: Used during DT_PROXY_HT_CREATE to relay proxy type.
 * 
 *		Note: (header_origin, header_id) as a tuple forms a unique identifier for the connection recognized by both nodes.
 *
 *	Body:
 *		- data					:	void *
 *
 *
 *	The naming convetion below is DT for "Data Type" and HT for "Header Type".
 *	E.g. DT_PROXY_HT_CREATE denotes a message where the data type is that of a proxy, but the header will have
 *  additional information relating to the type of request, in this case "create" the proxy connection.
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
#define DT_PROXY_HT_CREATE				1
#define DT_PROXY_HT_DESTROY				2
#define DT_PROXY_HT_RESPONSE			3

/* DT_CONNECTION: Information related to established connections. */
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
#define DT_TUN				8
#define DT_TAP				9

/* 
	Other protocol constants used in messaging.
*/

/* Proxy types. Set in message->header_proxy_type for DT_PROXY_HT_CREATE messages. */
#define PROXY_STATIC	0
#define PROXY_DYNAMIC	1
#define PROXY_TUN			2
#define PROXY_TAP			3

