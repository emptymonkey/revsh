
/*
 * This file contains the constants defining the inner workings of the message bus. This also seems to be an
 * appropriate space to describe network communication, from the initialization routine through to the expected
 * form of bytes on the message bus. This probably wont ever be formal enough to be a proper API, but this should
 * get us most of the way there.
 *
 * Each of the stages of the process is detailed below.
 *
 */

// These are exchanged and used in reporting, but as it's the first protocol, everything is interoperable!!
#define PROTOCOL_MAJOR_VERSION	1
#define PROTOCOL_MINOR_VERSION	0

/**********************************************************************************************************************
 *
 * Network connection:
 *
 * 1) TCP connection: Normally, the target node connects back to the control node. In bindshell mode, this
 *    will be reversed.
 *
 * 2) SSL connection: Regardless of who initiated the TCP connection, the control host is authoritative over 
 *    the SSL connection. It will decide which forms of SSL are appropriate, and disconnect if the target doesn't
 *    agree.
 *
 * At this point the network is connected and the two nodes can communicate.
 *
 **********************************************************************************************************************/

/**********************************************************************************************************************
 *
 * Basic negotiation: 
 * 
 * 1) Message size: Both nodes send their desired message size. This is sent as an unsigned short in network order.
 *    If either side receives a desired message size from their peer that is less than the MINIMUM_MESSAGE_SIZE 
 *    defined below, then it will immediately close the connection and exit. If both nodes decide to proceed, then
 *		the max message size for all messages going forward will be the smaller of the two desired message sizes.
 *
 * At this point the messaging bus is active, and all future communication will be as messages (described in more
 * detail later in this document.
 *
 **********************************************************************************************************************/

/* This is the smallest message size we will respect when asked by the remote connection. */
#define MINIMUM_MESSAGE_SIZE	1024

/**********************************************************************************************************************
 *
 * Message bus initialization:
 *
 * Notes:
 *    - The specifics of the message bus are described in detail at the end of this document.
 *    - All messages in this section will use the DT_INIT data_type. Order is important. We aren't in a multiplexed
 *      situation yet, so the messages in this section must occur in the order described here.
 *
 * 1) Interactive mode: Normally, a connection will be in interactive mode (i.e with a human sitting at a keyboard.) 
 *    A non-interactive mode is also supported. This allows for file / data transfer instead of terminal access. In 
 *    this phase of initialization both sides will send a message detailing if they plan on an interactive session or
 *    not. This data is represented as a single unsigned char. 1 is interactive, 0 is non-interactive. If either end
 *    requests non-interactive, then the entire communication will be non-interactive. If a non-interactive connection
 *    is determined, no further initialization will take place, but rather the program will move straight into the 
 *    broker() loop. Once there it will pass its data along the message bus as data type DT_TTY. Behavior upon receipt
 *    of a data_type other than DT_TTY is undefined.
 *
 * 2) Shell: The control node will send a message to the target instructing it which shell it should launch, as a 
 *    string. (The string may or may not be null terminated. It should be read in by its data_len argument.) If the
 *    control node doesn't have a specification, then it will send an empty string (data_len = 0) at which point the
 *    target node may choose which shell to spawn.
 *
 * 3) Environment: Some environment variables (such as TERM and LANG) are so core to how the terminal will function
 *    that they are read from the operators environment on the control node and sent to the target node. As such, the
 *    control node will send a message to the target node with this data. The data will be formatted as a single 
 *    string, whitespace delimited, null terminated. (It should still be read in by its data_len argument.) 
 *    E.g. "TERM=xterm LANG=en_US.utf8"  It is expected that the target will then set these variables in the 
 *    environment appropriately.
 *    
 * 4) Window size: The control node will send a message with the window size information relating to the operators 
 *    current window, as read with the TIOCGWINSZ ioctl(). The data will be the ws_row and ws_col fields from the 
 *    winsize struct. ("man tty_ioctl" for more info.) The ws_row and ws_col data will be stored in network order, 
 *    back to back in the data field. (Extract using data_len as always.) It is expected the target will inform the 
 *    pseudoterminal of the associated window size with a TIOCSWINSZ ioctl().
 *
 * At this point, the system has been initialized and we are ready to enter the broker() loop for normal multiplexed
 * io handling. 
 *
 **********************************************************************************************************************/

/**********************************************************************************************************************
 *
 * Message Bus Protocol Specification
 *
 *  What follows is a description of the bytes expected to be set for the message bus to work. Every message is made
 *  up of a header and a body. header_len, data_type, data_len are mandatory for the header, and data is mandatory for
 *  the body. Depending on the data_type, there may be other headers as well. As always, the order listed here for
 *  header and body components is important.
 *
 *	Header:
 *		- header_len		: unsigned short (network order)	:	size of the remaining header data.
 *		- data_type			:	unsigned char
 *		- data_len			:	unsigned short (network order)
 *		- Other data_type specific headers, if applicable, as noted below.
 *
 *	Other headers used with DT_PROXY and DT_CONNECTION:
 *		- header_type				: unsigned short (network order)
 *		- header_origin			: unsigned short (network order)	:	Lists if control or target is the owner.
 *		- header_id					: unsigned short (network order)	:	FD of the connection at it's origin.
 *		- header_proxy_type	: unsigned short (network order)	: Used during DT_PROXY_HT_CREATE, DT_PROXY_HT_REPORT, 
 *                                                            and DT_CONNECTION_HT_CREATE to relay proxy type.
 * 
 *		Note: (header_origin, header_id) together form a tuple that acts as a unique identifier for the connection this
 *          message refers to.
 *
 *	Body:
 *		- data					:	void *
 *
 **********************************************************************************************************************/

// The naming convention below is DT for "Data Type" and HT for "Header Type".

// At some point in the future I may dive through the code and detail how each of these message should look. As I said
// above though, this isn't a real API specification yet. For now, go look at the specific handler code in handler.c 
// and examine the source for each of the message cases if you need more detail.

/* Data Types */
/* DT_INIT: Initialization sequence data. */
#define DT_INIT				0

/* DT_TTY: TTY interaction data. */
/* This message type is always given priority because, despite added functionality, we are still a shell at heart. */
/* This will also be the data type used for passing data in the non-interactive mode. */
#define DT_TTY				1

/* DT_WINRESIZE: Window re-size event data. */
#define DT_WINRESIZE	2

/* DT_PROXY: Proxy meta-data. (e.g. setup, teardown, etc.) */
#define DT_PROXY			3
#define DT_PROXY_HT_CREATE				0
#define DT_PROXY_HT_DESTROY				1

// Used for sending data about listening proxies to the control node for reporting.
#define DT_PROXY_HT_REPORT				2

/* DT_CONNECTION: Information related to established connections. */
#define DT_CONNECTION	4
#define DT_CONNECTION_HT_CREATE				0
#define DT_CONNECTION_HT_DESTROY			1
/* Normal data to be brokered back and forth. */
#define DT_CONNECTION_HT_DATA			2
/*
	 DT_CONNECTION_HT_DORMANT is used when a fd would block for writing, and our message queue is getting deep.
	 Tells the other side to stop reading from the associated remote fd until otherwise notified. Reset to normal
	 with DT_CONNECTION_HT_ACTIVE once the message write queue for this connection is empty. 
 */
#define DT_CONNECTION_HT_DORMANT	3
#define DT_CONNECTION_HT_ACTIVE		4

/* DT_NOP: No Operation dummy message used for network keep-alive. */
#define DT_NOP				5

/* DT_ERROR: Used to send error reporting back to the control node for logging. */
#define DT_ERROR			6

/* 
	 Other protocol constants used in messaging.
 */

/* Proxy types. Set in message->header_proxy_type for DT_PROXY_HT_CREATE messages. */
#define PROXY_STATIC	0
#define PROXY_DYNAMIC	1
#define PROXY_TUN			2
#define PROXY_TAP			3
#define PROXY_FILE_UP		4
#define PROXY_FILE_DOWN	5
#define PROXY_LARS		6

/* String representations of the proxy types above for reporting purposes. */
#define PROXY_STATIC_STRING "Static"
#define PROXY_DYNAMIC_STRING "Dynamic"
#define PROXY_TUN_STRING "Tun"
#define PROXY_TAP_STRING "Tap"
#define PROXY_FILE_UP_STRING "File Upload"
#define PROXY_FILE_DOWN_STRING "File Download"
#define PROXY_LARS_STRING "LARS"

