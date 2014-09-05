
//#define DEBUG

#define TIMEOUT	3600
#define ADDRESS "127.0.0.1:9999"

// No good reason for 1024. Pick your favorite power of two.
#define BUFFER_SIZE 1024

// I had this as "/bin/sh". Hacker's don't care for that backward compatability shit.
// They just want it to work with as little fuss as possible.
#define DEFAULT_SHELL	"/bin/bash"

// These two environement variables are important enough in allowing the tool to provide a sane
// feeling terminal that we bake them into the binary. They will be passed automatically. Feel
// free to bake more in here by adding them to the DEFAULT_ENV string (space delimited). Otherwise,
// just set the environment on the fly using your rc file.
#define DEFAULT_ENV	"TERM LANG"

#define REVSH_DIR ".revsh"
#define RC_FILE "rc"
#define KEYS_DIR "keys"
#define TARGET_CERT_FILE "target_cert.pem"
#define CONTROLLER_CERT_FILE "controller_cert.pem"
#define CONTROLLER_KEY_FILE "controller_key.pem"

// Cipher definitions.
#define ADH_CIPHER "ADH-AES256-SHA"
#define EDH_CIPHER "DHE-RSA-AES256-SHA"
#define TARGET_CIPHER EDH_CIPHER ":" ADH_CIPHER
#define CONTROLLER_CIPHER "!ADH" ":" EDH_CIPHER
