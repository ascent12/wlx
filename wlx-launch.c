/* SPDX-License-Identifier: GPL-2.0-only */

#define _GNU_SOURCE /* dup3, ppoll */
#define _XOPEN_SOURCE 700 /* realpath */
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "util-string.h"

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

static bool
status_set_has_status(const struct status_set *set, uint8_t status)
{
	return set->status[status / 8] & (1 << (status % 8));
}

static bool
status_set_has_signal(const struct status_set *set, int signo)
{
	return sigismember(&set->signal, signo);
}

#ifdef __linux__
static void
make_sockaddr_un(struct sockaddr_un *addr, socklen_t *len)
{
	/*
	 * Use the kernel's auto-binding of an abstract socket.
	 * I'd prefer to avoid the filesystem if we can.
	 */
	*addr = (struct sockaddr_un) {
		.sun_family = AF_UNIX,
	};
	*len = sizeof addr->sun_family;
}
#else
static char sock_dir[
	sizeof ((struct sockaddr_un *)NULL)->sun_path - sizeof "/notify" - 1
];

static void
remove_sock_dir(void)
{
	int dirfd = open(sock_dir, O_DIRECTORY);
	if (dirfd != -1) {
		unlinkat(dirfd, "notify", 0);
		close(dirfd);
		rmdir(sock_dir);
	}
}

static void
make_sockaddr_un(struct sockaddr_un *addr, socklen_t *len)
{
	char *runtime_dir;
	int ret;

	runtime_dir = getenv("XDG_RUNTIME_DIR");
	if (!runtime_dir) {
		fprintf(stderr, "XDG_RUNTIME_DIR not set in environment\n");
		exit(1);
	}

	runtime_dir = realpath(runtime_dir, NULL);
	if (!runtime_dir) {
		perror("realpath");
		exit(1);
	}

	ret = snprintf(sock_dir, sizeof sock_dir, "%s/wlx-launch_XXXXXX", runtime_dir);
	free(runtime_dir);

	if (ret >= (int)sizeof sock_dir) {
		fprintf(stderr, "Socket path too long");
		exit(1);
	}

	if (!mkdtemp(sock_dir)) {
		perror("mkdtemp");
		exit(1);
	}

	atexit(remove_sock_dir);

	*addr = (struct sockaddr_un) {
		.sun_family = AF_UNIX,
	};
	*len = offsetof(struct sockaddr_un, sun_path);
	*len += snprintf(addr->sun_path, sizeof addr->sun_path,
			 "%s/notify", sock_dir) + 1; /* null terminator */
}
#endif

static int
make_notify_socket(void)
{
	struct sockaddr_un addr;
	socklen_t len;
	int sock;

	make_sockaddr_un(&addr, &len);

	sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sock == -1) {
		perror("socket");
		exit(1);
	}

	if (bind(sock, (struct sockaddr *)&addr, len) == -1) {
		perror("bind");
		exit(1);
	}

	return sock;
}

static void
set_notify_socket_env(int sock)
{
	struct sockaddr_un addr;
	socklen_t len = sizeof addr;
	int path_len;

	if (getsockname(sock, (struct sockaddr *)&addr, &len) == -1) {
		perror("getsockname");
		exit(1);
	}

	path_len = len - offsetof(struct sockaddr_un, sun_path);

#ifdef __linux__
	if (addr.sun_path[0] == '\0') {
		char buf[sizeof ((struct sockaddr_un *)NULL)->sun_path + 1];
		int ret;

		ret = snprintf(buf, sizeof buf,
			       "@%.*s", path_len - 1, addr.sun_path + 1);
		/*
		 * The kernel shouldn't do this, but we'll check anyway. The
		 * current format it uses is %05X with an incrementing value
		 * each time.
		 */
		if (ret != path_len) {
			fprintf(stderr, "Address contains embedded nulls\n");
			exit(1);
		}

		setenv("NOTIFY_SOCKET", buf, 1);
	} else
#endif
	{
		setenv("NOTIFY_SOCKET", addr.sun_path, 1);
	}
}

#ifdef __linux__
static void
cleanup_fds(void)
{
	DIR *d;
	struct dirent *dp;
	int max_fd = sysconf(_SC_OPEN_MAX);
	int d_fd;

	d = opendir("/proc/self/fd");
	if (!d) {
		perror("/proc/self/fd");
		return;
	}
	d_fd = dirfd(d);

	while ((dp = readdir(d)) != NULL) {
		int n;

		if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
			continue;

		n = atoi(dp->d_name);

		/* Want to keep stdin, stdout, and stderr */
		if (n < 3)
			continue;
		/* Still using this */
		if (n == d_fd)
			continue;
		/*
		 * Valgrind actually changes our ulimit by a little bit and
		 * uses that space for some of its own fds. It'll show up here,
		 * but we can't close them, nor do we want to; they won't
		 * interfere with the fd-store.
		 */
		if (n >= max_fd)
			continue;

		close(n);
	}

	closedir(d);
}
#else
static void
cleanup_fds(void)
{
	closefrom(3);
}
#endif

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
	"This is a comma-separated list. Optionally this can start with a '+', which\n"
	"specifies that this will be appended to the current set, rather than replace it.\n"
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

	if (str[0] == '+') {
		++str;
	} else {
		memset(set, 0, sizeof *set);
		sigemptyset(&set->signal);
	}

	do {
		char *comma = strchr(str, ',');
		if (comma)
			*comma++ = '\0';
		else
			last = true;

		if (isdigit(str[0])) {
			uint8_t n;
			if (wlxi_strtoi(str, &n) < 0)
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

static char **
parse_args(int argc, char *argv[], struct timespec *watchdog,
	   struct status_set *no_restart, struct status_set *success)
{
	int wd_ms = WATCHDOG_DEFAULT;
	int c;
	int long_index;

	while ((c = getopt_long(argc, argv, "+hv", options, &long_index)) != -1) {
		switch (c) {
		case 0:
		switch (long_index) {
		case OPT_WATCHDOG:
			if (optarg && wlxi_strtoi(optarg, &wd_ms) < 0) {
				fprintf(stderr, "Invalid argument");
				exit(1);
			}

			watchdog->tv_sec = wd_ms / 1000;
			watchdog->tv_nsec = wd_ms % 1000 * 1000000;
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

	if (!argv[optind])
		usage(argv[0], 1);

	return &argv[optind];
}

static void
init_defaults(struct status_set *no_restart, struct status_set *success)
{
	/* Return code 0 */
	no_restart->status[0] = 0x1;
	success->status[0] = 0x1;

	sigemptyset(&no_restart->signal);
	sigaddset(&no_restart->signal, SIGHUP);
	sigaddset(&no_restart->signal, SIGINT);
	sigaddset(&no_restart->signal, SIGTERM);
	sigaddset(&no_restart->signal, SIGPIPE);
	sigaddset(&no_restart->signal, SIGKILL);

	sigemptyset(&success->signal);
	sigaddset(&success->signal, SIGHUP);
	sigaddset(&success->signal, SIGINT);
	sigaddset(&success->signal, SIGTERM);
	sigaddset(&success->signal, SIGPIPE);
}

static volatile sig_atomic_t quit = 0;
static volatile sig_atomic_t check_child = 0;
static volatile sig_atomic_t watchdog_expired = 0;

static void
signal_handler(int signo, siginfo_t *si, void *cntxt)
{
	if (signo == SIGTERM || signo == SIGINT || signo == SIGHUP)
		quit = 1;
	else if (signo == SIGCHLD)
		check_child = 1;
	else if (signo == SIGALRM && si->si_code == SI_TIMER)
		watchdog_expired = 1;
}

static void
install_signals(sigset_t *orig_mask)
{
	static const int signals[] = {
		SIGTERM, SIGINT, SIGHUP,
		SIGCHLD,
		SIGALRM,
	};
	sigset_t block;
	struct sigaction sa = {
		.sa_flags = SA_SIGINFO | SA_NODEFER,
		.sa_sigaction = signal_handler,
	};

	/* Do a search for "select vs pselect" to see why we do this. */
	sigemptyset(&block);
	for (size_t i = 0; i < sizeof signals / sizeof signals[0]; ++i)
		sigaddset(&block, signals[i]);
	sigprocmask(SIG_BLOCK, &block, orig_mask);

	sigemptyset(&sa.sa_mask);
	for (size_t i = 0; i < sizeof signals / sizeof signals[0]; ++i)
		sigaction(signals[i], &sa, NULL);
}

extern char **environ;

int
main(int argc, char *argv[])
{
	sigset_t orig_mask;
	struct status_set no_restart = {0};
	struct status_set success = {0};
	struct itimerspec watchdog_its = {0};
	struct itimerspec watchdog_sav = {0};
	char **command;
	int notify_socket;
	timer_t watchdog;

	install_signals(&orig_mask);

	init_defaults(&no_restart, &success);
	command = parse_args(argc, argv, &watchdog_its.it_value, &no_restart, &success);

	if (timer_create(CLOCK_MONOTONIC, NULL, &watchdog) == -1) {
		perror("timer_create");
		exit(1);
	}

	/*
	 * Need a squeaky clean file descriptor set to make sure it doesn't
	 * mess with the fd-store. stdin/stdout/stderr survive this.
	 */
	cleanup_fds();

	notify_socket = make_notify_socket();
	set_notify_socket_env(notify_socket);

	/*
	 * The fd-store starts at '3', which isn't something we can modify, and
	 * this socket will be there. We move it to the highest possible
	 * number, to get it out of the way.
	 */
	int tmp = dup3(notify_socket, sysconf(_SC_OPEN_MAX) - 1, O_CLOEXEC);
	if (tmp == -1) {
		perror("dup3");
		return 1;
	}
	close(notify_socket);
	notify_socket = tmp;

	struct pollfd pfd = {
		.fd = notify_socket,
		.events = POLLIN,
	};
	posix_spawnattr_t attr;
	posix_spawnattr_init(&attr);
	posix_spawnattr_setsigmask(&attr, &orig_mask);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);

	pid_t child = 0;
	bool child_succeeded = false;
	bool killing_child = false;

	while (!quit || killing_child) {
		int ret;

		if (child == 0) {
			ret = posix_spawnp(&child, command[0], NULL,
					   &attr, command, environ);
			if (ret != 0) {
				perror("posix_spawnp");
				return 1;
			}

			timer_settime(watchdog, 0, &watchdog_its, NULL);
		}

		ret = ppoll(&pfd, 1, NULL, &orig_mask);
		if (ret == -1 && errno != EINTR) {
			perror("ppoll");
			return 1;
		}

		if (ret == 1) {
			/* TODO: Read stuff */
		}

		/*
		 * Just got SIGINT, etc.
		 * Reuse the watchdog killing logic.
		 */
		if (quit && !killing_child)
			watchdog_expired = 1;

		if (watchdog_expired) {
			watchdog_expired = 0;
			if (!killing_child) {
				struct itimerspec it = {
					.it_value.tv_sec = 5,
				};
				killing_child = true;
				if (kill(child, SIGTERM) == -1)
					perror("kill");

				timer_settime(watchdog, 0, &it, NULL);
			} else {
				/* It's taking too long */
				kill(child, SIGKILL);
			}
		}

		if (check_child) {
			siginfo_t info;
			struct itimerspec zero = {0};
			bool killed_by_watchdog = killing_child && !quit;
			int n;

			ret = waitid(P_PID, child, &info,
				     WEXITED | WCONTINUED | WSTOPPED);
			if (ret == -1) {
				perror("waitid");
				return 1;
			}

			psiginfo(&info, "wlx-launch");

			assert(info.si_pid == child);
			child = 0;
			check_child = 0;
			killing_child = false;

			if (killed_by_watchdog) {
				if (no_restart.watchdog) {
					quit = 1;
					child_succeeded = success.watchdog;
				}
				continue;
			}

			switch (info.si_code) {
			case CLD_EXITED:
				n = info.si_status;
				if (!status_set_has_status(&no_restart, n))
					break;

				child_succeeded = status_set_has_status(&success, n);
				quit = 1;
				break;
			case CLD_KILLED:
			case CLD_DUMPED:
				n = info.si_status;
				if (!status_set_has_signal(&no_restart, n))
					break;

				child_succeeded = status_set_has_signal(&success, n);
				quit = 1;
				break;
			case CLD_STOPPED:
				timer_settime(watchdog, 0, &zero, &watchdog_sav);
				break;
			case CLD_CONTINUED:
				timer_settime(watchdog, 0, &watchdog_sav, NULL);
				break;
			default:
				break;
			}
		}
	}

	close(notify_socket);
	timer_delete(watchdog);
	posix_spawnattr_destroy(&attr);

	/* '!' because 0 is success */
	return !child_succeeded;
}
