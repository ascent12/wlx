/* SPDX-License-Identifier: GPL-2.0-only */

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>

#define WATCHDOG_DEFAULT 10000

struct status_set {
	/* Bitmask of 256 bits */
	uint8_t status[32];
	sigset_t signal;
	bool watchdog;
};

enum {
	OPT_HELP,
	OPT_VERSION,
	OPT_WATCHDOG,
	OPT_NO_RESTART,
	OPT_SUCCESS,
};

static const struct option options[] = {
	[OPT_HELP] = { "help", no_argument, NULL, 'h' },
	[OPT_VERSION] = { "version", no_argument, NULL, 'v' },
	[OPT_WATCHDOG] = { "watchdog", optional_argument, NULL, 0 },
	[OPT_NO_RESTART] = { "no-restart", required_argument, NULL, 0 },
	[OPT_SUCCESS] = { "success", required_argument, NULL, 0 },
};

static noreturn void
usage(const char *name, int status)
{
	static const char *str = 
	"wlx-launch: Launch wlx-based display server\n"
	"\n"
	"usage: %s [options]... [--] command [args]...\n"
	"  -h, --help           Display this help message and exit.\n"
	"  -v, --version        Display version information and exit.\n"
	"  --watchdog(=n)       Enables the watchdog timer, with an optional duration\n"
	"                         in milliseconds. The default is %d milliseconds.\n"
	"  --no-restart=...     Sets the exit conditions for which the command will not\n"
	"                         automatically be restarted on. It is important to set this\n"
	"                         correctly so the command isn't continuously restarted in\n"
	"                         situations such as bad arguments/config files, or otherwise\n"
	"                         \"normal\" failures.\n"
	"                         The default is \"0,SIGHUP,SIGINT,SIGTERM,SIGPIPE,SIGKILL\".\n"
	"  --success=...        Sets the exit conditions which is considered a successful\n"
	"                         execution. This only has an effect on the return code\n"
	"                         of this program. While not enforced, this should be a\n"
	"                         subset of --no-restart.\n"
	"                         The default is \"0,SIGHUP,SIGINT,SIGTERM,SIGPIPE\".\n"
	"\n"
	"[Exit conditions]\n"
	"An exit condition is a description of how the process exits.\n"
	"This is a comma-separated list.\n"
	"  n                    An integer exit code that the program terminated with.\n"
	"                         Must be in the range [0, 255].\n"
	"  SIGNAME              A signal name the process was terminated abnormally by.\n"
	"                         Must be in all caps, e.g. SIGTERM, not sigterm.\n"
	"  watchdog             A special value meaning the program was killed by the\n"
	"                         watchdog, by failing to send a notification in time.\n";

	fprintf(stderr, str, name, WATCHDOG_DEFAULT);
	exit(status);
}

static int
str_to_sig(const char *str)
{
	/* List in order found in 'man 0p signal.h' */
	struct { const char *str; int sig; } table[] = {
		{ "ABRT", SIGABRT },
		{ "ALRM", SIGALRM },
		{ "BUS", SIGBUS },
		{ "CHLD", SIGCHLD },
		{ "CONT", SIGCONT },
		{ "FPE", SIGFPE },
		{ "HUP", SIGHUP },
		{ "ILL", SIGILL },
		{ "INT", SIGINT },
		{ "KILL", SIGKILL },
		{ "PIPE", SIGPIPE },
		{ "QUIT", SIGQUIT },
		{ "SEGV", SIGSEGV },
		{ "STOP", SIGSTOP },
		{ "TERM", SIGTERM },
		{ "TSTP", SIGTSTP },
		{ "TTIN", SIGTTIN },
		{ "TTOU", SIGTTOU },
		{ "USR1", SIGUSR1 },
		{ "USR2", SIGUSR2 },
		{ "POLL", SIGPOLL },
		{ "PROF", SIGPROF },
		{ "SYS", SIGSYS },
		{ "TRAP", SIGTRAP },
		{ "URG", SIGURG },
		{ "VTALRM", SIGVTALRM },
		{ "XCPU", SIGXCPU },
		{ "XFZS", SIGXFSZ },
	};

	for (size_t i = 0; i < sizeof table / sizeof table[0]; ++i) {
		if (strcmp(str, table[i].str) == 0)
			return table[i].sig;
	}

	return 0;
}

static void
parse_status_set(struct status_set *set, char *str)
{
	bool last = false;

	memset(set, 0, sizeof *set);
	sigemptyset(&set->signal);

	do {
		char *comma = strchr(str, ',');
		if (comma)
			*comma++ = '\0';
		else
			last = true;

		if (isdigit(str[0])) {
			long n;
			char *endptr;

			errno = 0;
			n = strtol(str, &endptr, 10);
			if (errno || endptr == str || *endptr != '\0' || n < 0 || n >= 256)
				goto error;

			set->status[n / 8] |= 1 << n % 8;
		} else if (strncmp(str, "SIG", 3) == 0) {
			int sig = str_to_sig(str + 3);
			if (sig == 0)
				goto error;

			sigaddset(&set->signal, sig);
		} else if (strcmp(str, "watchdog") == 0) {
			set->watchdog = true;
		} else {
			goto error;
		}

		str = comma;
		continue;

error:
		fprintf(stderr, "Invalid status argument \"%s\"\n", str);
		exit(1);
	} while (!last);
}

static void
parse_args(int argc, char *argv[],
	   struct status_set *no_restart, struct status_set *success)
{
	bool watchdog_enabled = false;
	int watchdog_timeout = WATCHDOG_DEFAULT;
	int c;
	int long_index;

	while ((c = getopt_long(argc, argv, "+hv", options, &long_index)) != -1) {
		switch (c) {
		case 0:
		switch (long_index) {
		case OPT_WATCHDOG:
			watchdog_enabled = true;
			printf("watchdog: %s\n", optarg);
			break;
		case OPT_NO_RESTART:
			parse_status_set(no_restart, optarg);
			break;
		case OPT_SUCCESS:
			parse_status_set(success, optarg);
			break;
		}
		break;
		case 'h':
			usage(argv[0], 0);
		default:
			usage(argv[0], 1);
		}
	}

	printf("remaining args: ");
	for (int i = optind; i < argc; ++i) {
		printf("%s%s", i == optind ? "" : ", ", argv[i]); 
	}
	printf("\n");
}

int
main(int argc, char *argv[])
{
	struct status_set no_restart = {
		.status[0] = 0x1, /* Status code 0 */
	};
	struct status_set success = {
		.status[0] = 0x1, /* Status code 0 */
	};

	sigemptyset(&no_restart.signal);
	sigaddset(&no_restart.signal, SIGHUP);
	sigaddset(&no_restart.signal, SIGINT);
	sigaddset(&no_restart.signal, SIGTERM);
	sigaddset(&no_restart.signal, SIGPIPE);
	sigaddset(&no_restart.signal, SIGKILL);

	sigemptyset(&success.signal);
	sigaddset(&success.signal, SIGHUP);
	sigaddset(&success.signal, SIGINT);
	sigaddset(&success.signal, SIGTERM);
	sigaddset(&success.signal, SIGPIPE);

	parse_args(argc, argv, &no_restart, &success);
}
