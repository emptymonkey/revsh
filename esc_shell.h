

struct esc_shell_command {
	char *command;
	char *completion_string;
	int min_args;
	int max_args;
	int (*payload)(char **command_vec);

	const struct esc_shell_command *sub_commands;
};

const struct esc_shell_command connect_sub_commands[] = {
	{"tun", "connect tun", 0, 0, NULL, NULL},
	{"tap", "connect tap", 0, 0, NULL, NULL},
	{NULL, NULL, 0, 0, NULL, NULL}
};

const struct esc_shell_command file_sub_commands[] = {
	{"upload", "file upload", 1, 2, NULL, NULL},
	{"download", "file download", 1, 2, NULL, NULL},
	{NULL, NULL, 0, 0, NULL, NULL}
};

const struct esc_shell_command list_sub_commands[] = {
	{"all", "list all", 0, 0, NULL, NULL},
	{"proxies", "list proxies", 0, 0, NULL, NULL},
	{"connections", "list connections", 0, 0, NULL, NULL},
	{NULL, NULL, 0, 0, NULL, NULL}
};

const struct esc_shell_command proxy_sub_commands[] = {
	{"local", "proxy local", 1, 1, NULL, NULL},
	{"dynamic", "proxy dynamic", 1, 1, NULL, NULL},
	{"remote", "proxy remote", 1, 1, NULL, NULL},
	{"bypass", "proxy bypaxx", 1, 1, NULL, NULL},
	{NULL, NULL, 0, 0, NULL, NULL}
};

const struct esc_shell_command menu[] = {
	{"connect", "connect", 1, 1, NULL, connect_sub_commands}, 
	{"file", "file", 2, 3, NULL, file_sub_commands}, 
	{"kill", "kill", 1, 1, NULL, NULL}, 
	{"list", "list", 1, 1, NULL, list_sub_commands}, 
	{"proxy", "proxy", 2, 2, NULL, proxy_sub_commands}, 
	{"ttyscript", "ttyscript", 1, 1, NULL, NULL}, 
	{"help", "help", 0, 2, NULL, NULL}, 
	{"exit", "exit", 0, 0, NULL, NULL}, 
	{NULL, NULL, 0, 0, NULL, NULL}
};

