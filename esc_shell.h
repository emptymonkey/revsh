
const char list_help[] = \
"List all active connections and listeners.\n" \
"\nUsage:\n\tlist\n";

const char kill_help[] = \
"Kill any active connection or listener by it's Connection ID (CID).\n" \
"CIDs are listed with the \"list\" command.\n" \
"\nUsage:\n\tkill CID\n";

const char proxy_help[] = \
"Setup a new listener.\n" \
"\nSubcommands:\n\tlocal\n\tdynamic\n\tremote\n\tbypass\n";

const char local_help[] = \
"Set up a local listener that will perform static point-to-point socket\n" \
"forwarding, with traffic exiting through the target node.\n" \
"\nUsage:\n\tproxy local [LHOST:]LPORT:RHOST:RPORT\n";

const char dynamic_help[] = \
"Set up a local listener that will perform dynamic SOCKS socket forwarding, with\n" \
"traffic exiting through the target node.\n" \
"\nUsage:\n\tproxy dynamic [LHOST:]LPORT\n";

const char remote_help[] = \
"Set up a remote listener that will perform static point-to-point socket\n" \
"forwarding, with traffic exiting through the control node.\n" \
"\nUsage:\n\t[RHOST:]RPORT:LHOST:LPORT\n";

const char bypass_help[] = \
"Set up a remote listener that will perform dynamic SOCKS socket forwarding, with\n" \
"traffic exiting through the control node.\n" \
"\nUsage:\n\tproxy bypass [RHOST:]RPORT\n";

const char device_help[] = \
"Setup a new device connection.\n" \
"\nSubcommands:\n\ttun\n\ttap\n";

const char tun_help[] = \
"Create a new TUN device on both nodes and forward their raw IP packets.\n" \
"\nUsage:\n\tdevice tun\n";

const char tap_help[] = \
"Create a new TAP device on both nodes and forward their raw Ethernet frames.\n" \
"\nUsage:\n\tdevice tap\n";

const char file_help[] = \
"Transfer a file between the control node and the target node.\n" \
"\nNOTE: File transfer commands only work on individual files.\n" \
"Use tar to pack multiple files / directories for transfer.\n" \
"\nSubcommands:\n\tupload\n\tdownload\n";

const char upload_help[] = \
"Upload a file to the target node.\n" \
"Default will be to use the current working directory on either end if not\n" \
"otherwise specified.\n" \
"\nNOTE: File transfer commands only work on individual files.\n" \
"Use tar to pack multiple files / directories for transfer.\n" \
"\nUsage:\n\tfile upload SOURCE [DEST]\n";

const char download_help[] = \
"Download a file from the target node.\n" \
"Default will be to use the current working directory on either end if not\n" \
"otherwise specified.\n" \
"\nNOTE: File transfer commands only work on individual files.\n" \
"Use tar to pack multiple files / directories for transfer.\n" \
"\nUsage:\n\tfile download SOURCE [DEST]\n";

/*
const char ttyscript_help[] = \
"Forward the contents of a ttyscript file to the remote tty as though they were\n" \
"commands you had typed at the keyboard.\n" \
"\nDefault will be to look for the script in the TTYSCRIPTS_DIR directory if not\n" \
"otherwise specified.\n" \
"\nUsage:\n\tttyscript FILE\n";
*/

const char help_help[] = \
"Explain any of the commands or subcommands further.\n" \
"\nUsage:\n\thelp COMMAND [SUBCOMMAND]\n";

const char exit_help[] = \
"Exit the revsh command shell.\n" \
"\nUsage:\n\texit\n";

const struct esc_shell_command null_sub_commands[] = {
	{NULL, NULL, 0, 0, NULL, NULL}
};

const struct esc_shell_command file_sub_commands[] = {
	{"upload", "file upload", 3, 4, upload_help, null_sub_commands},
	{"download", "file download", 3, 4, download_help, null_sub_commands},
	{NULL, NULL, 0, 0, NULL, null_sub_commands}
};

const struct esc_shell_command device_sub_commands[] = {
	{"tun", "device tun", 2, 2, tun_help, null_sub_commands},
	{"tap", "device tap", 2, 2, tap_help, null_sub_commands},
	{NULL, NULL, 0, 0, NULL, null_sub_commands}
};

const struct esc_shell_command proxy_sub_commands[] = {
	{"local", "proxy local", 3, 3, local_help, null_sub_commands},
	{"dynamic", "proxy dynamic", 3, 3, dynamic_help, null_sub_commands},
	{"remote", "proxy remote", 3, 3, remote_help, null_sub_commands},
	{"bypass", "proxy bypass", 3, 3, bypass_help, null_sub_commands},
	{NULL, NULL, 0, 0, NULL, null_sub_commands}
};

const struct esc_shell_command menu[] = {
	{"list", "list", 1, 1, list_help, null_sub_commands}, 
	{"kill", "kill", 2, 2, kill_help, null_sub_commands}, 
	{"proxy", "proxy", 0, 0, proxy_help, proxy_sub_commands}, 
	{"device", "device", 0, 0, device_help, device_sub_commands}, 
//	{"ttyscript", "ttyscript", 2, 2, NULL, ttyscript_help, null_sub_commands}, 
	{"file", "file", 0, 0, file_help, file_sub_commands}, 
	{"help", "help", 1, 3, help_help, null_sub_commands}, 
	{"exit", "exit", 1, 1, exit_help, null_sub_commands}, 
	{NULL, NULL, 0, 0, NULL, null_sub_commands}
};

