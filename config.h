
/*********************************************************************************************************************
 * This file consists of entries that the user may want to tweak.
 * Edit away to your heart's content.
 *********************************************************************************************************************/


// Default address of the command and control listener. Nice to have when
// Nice to have baked in when you can't hand args or switches to the target at launch.
#define CONTROL_ADDRESS "0.0.0.0"
#define CONTROL_PORT "2200"

// Default socks proxy listener port.
#define SOCKS_LISTENER "2280"

// Default point-to-point proxy listeners bound to localhost on both ends for bi-directional asynchronous in-band data
// transfers. This is useful for copying files.
/*
 * Example:
 *   On target:  nc -l 127.0.0.1 -p 2291 >rootkit.tar
 *   On control: cat rootkit.tar | nc 127.0.0.1 2290
 */
#define LOCAL_LISTENER "2290:127.0.0.1:2291"

// Default shell.
#define DEFAULT_SHELL "/bin/bash"

/*
 * These two environment variables seemed important enough for allowing the tool to provide a sane feeling terminal
 * that we go ahead and export them automatically. Feel free to bake more in here by adding them to this DEFAULT_ENV
 * string (space delimited). Otherwise, just set the environment on the fly using your rc file.
 */
#define DEFAULT_ENV "TERM LANG"

// Default retry range, in seconds.
//   E.g. "600,1200" sets recurrence of connect back retry to some random time between 5 and 20 min.
// This variable range is also used in sending nop keepalive packets across the connection.
#define RETRY "600,1200"

//  Time to wait on a new connection before dying, in seconds.
#define TIMEOUT 3600

// Default locations of important things.
#define REVSH_DIR "~/.revsh/"
#define RC_FILE REVSH_DIR "rc"
#define KEYS_DIR REVSH_DIR "keys/"

// Cipher definitions.
#define ADH_CIPHER "ADH-AES256-SHA"
#define EDH_CIPHER "DHE-RSA-AES256-SHA"
#define TARGET_CIPHER EDH_CIPHER ":" ADH_CIPHER
#define CONTROLLER_CIPHER "!" ADH_CIPHER ":" EDH_CIPHER

// Uncomment this to enable logging on the control node.
//#define LOG_FILE REVSH_DIR "log"

// If defined, use the RETRY values above to also time the sending a keep-alive NOP message.
// In some environments, this will ensure the networking gear doesn't kill the connection for lack of activity.
#define NOP

// CALLING_CARD is just a string that will be left sitting in the binary. I use it as advertising space.
#define CALLING_CARD "@emptymonkey - https://github.com/emptymonkey"

/*
 * CALLING_CARD may also be useful as a mechanism for:
 *  -  false attribution.
 *  -  embedding a counter-forensic exploit (CVE-2014-8485).

 *  /usr/bin/strings is *not* a cyber-attribution tool. 
 */
//#define CALLING_CARD "白人害怕中国文字！"
