
/*
 * This file consists of entries that the user may want to tweak.
 * Edit away to your heart's content.
*/

/*  Default address, so you can bake in your own C2. */
/*  Format is "ADDRESS:PORT". */
#define ADDRESS "0.0.0.0:2200"

/*  Default socks proxy listener port */
#define	SOCKS_LISTENER	"2280"

/*  Default shell. */
#define DEFAULT_SHELL	"/bin/bash"

/*  These two environement variables are important enough for allowing the tool to provide a sane */
/*  feeling terminal that we go ahead and export them automatically. Feel free to bake more in here */
/*  by adding them to this DEFAULT_ENV string (space delimited). Otherwise, just set the environment */
/*  on the fly using your rc file. */
#define DEFAULT_ENV	"TERM LANG"

/*  Default retry range, in seconds. */ 
/*  E.g. "600,1200" sets recurrance of connect back retry to some random time between 5 and 20 min. */
#define RETRY "600,1200"

/*  Time to wait on a new connection before dying, in seconds. */
#define TIMEOUT	3600

/*  Default locations of important things. */
#define REVSH_DIR "~/.revsh/"
#define RC_FILE	REVSH_DIR "rc"
#define KEYS_DIR REVSH_DIR "keys/"

/*  Cipher definitions. */
#define ADH_CIPHER "ADH-AES256-SHA"
#define EDH_CIPHER "DHE-RSA-AES256-SHA"
#define TARGET_CIPHER EDH_CIPHER ":" ADH_CIPHER
#define CONTROLLER_CIPHER "!" ADH_CIPHER ":" EDH_CIPHER

/* Comment out to disable logging on the c2. */
#define LOG_FILE	REVSH_DIR "log"

/* If defined, use the RETRY values above to also time the sending a keep-alive NOP message. */
/* In some environments, this will ensure the networking gear doesn't kill the connection for lack of activity. */
#define NOP

/* CALLING_CARD is just a string that will be left sitting in the binary. I use it as advertising space. */
#define CALLING_CARD "@emptymonkey - https://github.com/emptymonkey"

/*
	CALLING_CARD may also be useful as a mechanism for:
		-  false attribution.
		-  embedding a counter-forensic exploit (CVE-2014-8485).

	 The CALLING_CARD attribution feature is intended as a cynical commentary on the current state of APT attribution.
	 If your methodology for attribution doesn't at a minimum rely upon fingerprinting the operator through an
	 analysis of their personal system interaction idioms and forensic artifacts then please re-roll your cyber-identity.

	 /usr/bin/strings is *not* a cyber-attribution tool. 
*/
//#define CALLING_CARD "白人害怕中国文字！"
