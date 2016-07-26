
/*
 * This file consists of entries that the user may want to tweak.
 * Edit away to your heart's content.
*/

/*  Default retry range. (Recur sometime between 5 and 20 min). */
#define RETRY "600,1200"

/*  Time to wait on a new connection before dying. */
#define TIMEOUT	3600

/*  Default address, so you can bake in your own C2. */
#define ADDRESS "127.0.0.1:9999"

/*  Default shell. */
#define DEFAULT_SHELL	"/bin/bash"

/*  These two environement variables are important enough for allowing the tool to provide a sane */
/*  feeling terminal that we go ahead and export them automatically. Feel free to bake more in here */
/*  by adding them to this DEFAULT_ENV string (space delimited). Otherwise, just set the environment */
/*  on the fly using your rc file. */
#define DEFAULT_ENV	"TERM LANG"

/*  Default locations of important things. */
#define REVSH_DIR "~/.revsh/"
#define RC_FILE	REVSH_DIR "rc"
#define KEYS_DIR REVSH_DIR "keys/"

/*  Cipher definitions. */
#define ADH_CIPHER "ADH-AES256-SHA"
#define EDH_CIPHER "DHE-RSA-AES256-SHA"
#define TARGET_CIPHER EDH_CIPHER ":" ADH_CIPHER
#define CONTROLLER_CIPHER "!ADH" ":" EDH_CIPHER

/* Comment out to disable logging. */
#define LOG_FILE	REVSH_DIR "log"

/* If defined, use the RETRY values above to also time the sending a keep-alive NOP message. */
/* In some environments, this will ensure the networking gear doesn't kill the connection for lack of activity. */
#define NOP

/* CALLING_CARD is just a string that will be left sitting in the binary. I use it as advertising space. */
#define CALLING_CARD "@emptymonkey - https://github.com/emptymonkey"

/* CALLING_CARD may also be used as a mechanism for false attribution. Be creative. */

/* Chinese	"we are hongke" */
/* #define CALLING_CARD "我们是红客" */

/* Korean		"we are guardians of peace" */
/* #define CALLING_CARD "우리는 평화의 수호자" */

