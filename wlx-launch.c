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
#include <stdalign.h>
#include <stdarg.h>
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
#include <stdatomic.h>

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
	OPT_NO_ABSTRACT_SOCKET,
	OPT_DISABLE_PID_CHECK,
};

/* Options from command-line arguments */
static struct {
	/* it_value being 0 means it's disabled */
	struct itimerspec watchdog;
	struct status_set no_restart;
	struct status_set success;
	bool no_abstract_socket;
	bool disable_pid_check;
	char **command;
} opt;

static noreturn void
usage(const char *name, int status)
{
	/* Break usual formatting here, to more easily see when we hit 80 chars */
	static const char *str =
"wlx-launch: Launch wlx-based display server\n"
"\n"
"usage: %s [options]... [--] command [args]...\n"
"  -h, --help           Display this help message and exit.\n"
"  -v, --version        Display version information and exit.\n"
"  --watchdog(=n)       Enables the watchdog timer, with an optional duration\n"
"                         in milliseconds. The default is %d milliseconds.\n"
"  --no-restart=...     Sets the exit conditions for which the command will\n"
"                         not automatically be restarted on. It is important\n"
"                         to set this correctly, so the command isn't\n"
"                         continuously restarted on failures like bad arguments.\n"
"                         The default is \"0,SIGHUP,SIGINT,SIGTERM,SIGPIPE,SIGKILL\".\n"
"  --success=...        Sets the exit conditions which is considered a successful\n"
"                         execution. This only has an effect on the return code\n"
"                         of this program. While not enforced, this should be a\n"
"                         subset of --no-restart.\n"
"                         The default is \"0,SIGHUP,SIGINT,SIGTERM,SIGPIPE\".\n"
"  --no-abstract-socket Forces the notify socket to not use an abstract unix socket,\n"
"                         and will instead use the file system. This only has\n"
"                         an affect on Linux, and is intended as a debugging tool.\n"
"  --disable-pid-check  Disable checking the PID of the sender of messages to the\n"
"                         notify socket. This is intended for debugging.\n"
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
"                         watchdog, by failing to send a notification in time.\n"
"\n"
"[Users]\n"
"This program is not intended to be used by \"end users\" directly. These\n"
"arguments are not configuration for them to change, instead they are immutable\n"
"properties of the command being run. It is highly recommended that you create a\n"
"wrapper script that will pass the correct arguments tailored for your program.\n";

	fprintf(stderr, str, name, WATCHDOG_DEFAULT);
	exit(status);
}

static noreturn void
__attribute__((format(printf, 1, 2)))
err(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	fprintf(stderr, "wlx-launch: ");
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");

	va_end(args);
	exit(1);
}

static noreturn void
__attribute__((format(printf, 1, 2)))
err_errno(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int saved_errno = errno;

	fprintf(stderr, "wlx-launch: ");
	vfprintf(stderr, fmt, args);
	fprintf(stderr, ": %s\n", strerror(saved_errno));

	va_end(args);
	exit(1);
}

static void
opt_init_defaults(void)
{
	/* Return code 0 */
	opt.no_restart.status[0] = 0x1;
	opt.success.status[0] = 0x1;

	sigemptyset(&opt.no_restart.signal);
	sigaddset(&opt.no_restart.signal, SIGHUP);
	sigaddset(&opt.no_restart.signal, SIGINT);
	sigaddset(&opt.no_restart.signal, SIGTERM);
	sigaddset(&opt.no_restart.signal, SIGPIPE);
	sigaddset(&opt.no_restart.signal, SIGKILL);

	sigemptyset(&opt.success.signal);
	sigaddset(&opt.success.signal, SIGHUP);
	sigaddset(&opt.success.signal, SIGINT);
	sigaddset(&opt.success.signal, SIGTERM);
	sigaddset(&opt.success.signal, SIGPIPE);

#ifndef __linux__
	opt.no_abstract_socket = true;
#endif
}

static int
opt_str_to_sig(const char *str)
{
	/*
	 * List in order found in 'man 0p signal.h'.
	 * It's pretty lame that there isn't a standard function to do this.
	 */
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
opt_parse_status_set(struct status_set *set, const char *str)
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
			int sig = opt_str_to_sig(str + 3);
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
		err("Invalid argument: \"%s\"", str);
	} while (!last);
}

static void
opt_parse_args(int argc, char *argv[])
{
	static const struct option options[] = {
		[OPT_HELP] = { "help", no_argument, NULL, 'h' },
		[OPT_VERSION] = { "version", no_argument, NULL, 'v' },
		[OPT_WATCHDOG] = { "watchdog", optional_argument, NULL, 0 },
		[OPT_NO_RESTART] = { "no-restart", required_argument, NULL, 0 },
		[OPT_SUCCESS] = { "success", required_argument, NULL, 0 },
		[OPT_NO_ABSTRACT_SOCKET] = { "no-abstract-socket", no_argument, NULL, 0 },
		[OPT_DISABLE_PID_CHECK] = { "disable-pid-check", no_argument, NULL, 0 },
	};
	int wd_ms = WATCHDOG_DEFAULT;
	int c;
	int long_index;

	while ((c = getopt_long(argc, argv, "+hv", options, &long_index)) != -1) {
		switch (c) {
		case 0:
			switch (long_index) {
			case OPT_WATCHDOG:
				if (optarg && wlxi_strtoi(optarg, &wd_ms) < 0)
					err("Invalid argument: \"%s\"", optarg);

				opt.watchdog.it_value.tv_sec = wd_ms / 1000;
				opt.watchdog.it_value.tv_nsec = wd_ms % 1000 * 1000000;
				break;
			case OPT_NO_RESTART:
				opt_parse_status_set(&opt.no_restart, optarg);
				break;
			case OPT_SUCCESS:
				opt_parse_status_set(&opt.success, optarg);
				break;
			case OPT_NO_ABSTRACT_SOCKET:
				opt.no_abstract_socket = true;
				break;
			case OPT_DISABLE_PID_CHECK:
				opt.disable_pid_check = true;
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

	opt.command = &argv[optind];
}

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
	if (!runtime_dir)
		err("Missing environment variable: XDG_RUNTIME_DIR");

	runtime_dir = realpath(runtime_dir, NULL);
	if (!runtime_dir)
		err_errno("%s", runtime_dir);

	ret = snprintf(sock_dir, sizeof sock_dir, "%s/wlx-launch_XXXXXX", runtime_dir);
	free(runtime_dir);

	if (ret >= (int)sizeof sock_dir)
		err("Socket path too long: %d > %zu", ret, sizeof sock_dir);

	if (!mkdtemp(sock_dir))
		err_errno("%s\n", sock_dir);

	atexit(remove_sock_dir);

	snprintf(addr->sun_path, sizeof addr->sun_path, "%s/notify", sock_dir);
	*len = sizeof *addr;
}

static int
make_notify_socket(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	socklen_t len = sizeof addr.sun_family;
	int sock, tmp;

	sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (sock == -1)
		err_errno("socket");
	assert(sock == 3); /* Because closefrom */

	/*
	 * The fd-store starts at '3', which isn't something we can modify, and
	 * this socket will be there. We move it to the highest possible
	 * number, to get it out of the way.
	 */
	tmp = dup3(sock, sysconf(_SC_OPEN_MAX) - 1, O_CLOEXEC);
	if (tmp == -1)
		err_errno("dup3");
	close(sock);
	sock = tmp;

#ifdef __linux__
	int one = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_PASSCRED, &one, sizeof one) == -1)
		err_errno("setsockopt(SO_PASSCRED)");
#endif

	/* no_abstract_socket is forced on for all non-Linux systems */
	if (opt.no_abstract_socket)
		make_sockaddr_un(&addr, &len);

	if (bind(sock, (struct sockaddr *)&addr, len) == -1)
		err_errno("bind");

	if (opt.no_abstract_socket) {
		setenv("NOTIFY_SOCKET", addr.sun_path, 1);
	} else {
		char buf[sizeof addr.sun_path + 1];
		int path_len;

		len = sizeof addr;
		if (getsockname(sock, (struct sockaddr *)&addr, &len) == -1)
			err_errno("getsockname");
		path_len = len - offsetof(struct sockaddr_un, sun_path);

		snprintf(buf, sizeof buf, "@%.*s", path_len - 1, addr.sun_path + 1);

		setenv("NOTIFY_SOCKET", buf, 1);
	}

	return sock;
}

static void
handle_packet(size_t buf_len, char buf[static buf_len],
	      size_t fds_len, int fds[static fds_len])
{
	char *ptr = buf;

	do {
		char *key = ptr;
		char *value = NULL;

		for (; *ptr != '\n' && *ptr != '\0'; ++ptr) {
			if (!value && *ptr == '=') {
				value = ptr + 1;
				*ptr = '\0';
			}
		}
		*ptr++ = '\0';

		if (!value) {
			fprintf(stderr, "wlx-launch: Message has no '='\n");
			continue;
		}

		printf("key=\"%s\", value=\"%s\"\n", key, value);
	} while (ptr < buf + buf_len);
}

/*
 * God damn I wish there was a standard way of doing this. You'd think if
 * everyone has their own (unfortunately incompatable) implementation, POSIX
 * would've done something by now.
 */
#ifdef __linux__
typedef struct ucred cmsg_creds_t;

static bool
cmsg_is_creds(const struct cmsghdr *cmsg)
{
	return cmsg->cmsg_level == SOL_SOCKET &&
	       cmsg->cmsg_type == SCM_CREDENTIALS &&
	       cmsg->cmsg_len == sizeof(struct ucred);
}

static bool
creds_is_pid(const cmsg_creds_t *creds, pid_t pid)
{
	return creds->pid == pid;
}
#elif defined(__FreeBSD__)
typedef struct cmsgcred cmsg_creds_t;

static bool
cmsg_is_creds(const struct cmsghdr *cmsg)
{
	return cmsg->cmsg_level == SOL_SOCKET &&
	       cmsg->cmsg_type == SCM_CREDS &&
	       cmsg->cmsg_len == sizeof(struct cmsgcred);
}

static bool
creds_is_pid(const cmsg_creds_t *creds, pid_t pid)
{
	return creds->cmsgcred_pid == pid;
}
#else
#error "Platform needs cmsg credentials implementation"
#endif

#define MAX_FDS 768

static void
recv_notify_socket(int sock, pid_t child)
{
	/*
	 * These are the sizes systemd uses.
	 *
	 * systemd uses PIPE_BUF here, which is 4096 on Linux, but POSIX's
	 * minimum is only 512. Lets just go with the Linux size explicitly.
	 */
	char buf[4096 + 1];
	alignas(struct cmsghdr) char cmsg_buf[
		CMSG_SPACE(sizeof(cmsg_creds_t)) +
		CMSG_SPACE(sizeof(int[MAX_FDS]))
	];
	struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof buf - 1,
	};
	struct msghdr msghdr = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cmsg_buf,
		.msg_controllen = sizeof cmsg_buf,
	};
	ssize_t nread;

	while ((nread = recvmsg(sock, &msghdr, 0)) != -1) {
		/*
		 * We can't assume the CMSG_DATA is correctly aligned, so it
		 * gets memcpy()'d to these instead of using a pointer.
		 */
		int fds[MAX_FDS];
		size_t fds_len = 0;
		cmsg_creds_t creds;
		bool have_creds = false;

		buf[nread] = '\0';

		for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msghdr); cmsg;
		     cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
			if (cmsg->cmsg_level == SOL_SOCKET &&
			    cmsg->cmsg_type == SCM_RIGHTS) {
				assert(fds_len == 0);
				fds_len = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
				memcpy(fds, CMSG_DATA(cmsg), fds_len * sizeof fds[0]);
			} else if (cmsg_is_creds(cmsg)) {
				assert(!have_creds);
				have_creds = true;
				memcpy(&creds, CMSG_DATA(cmsg), sizeof creds);
			}
		}

		if (!opt.disable_pid_check && (!have_creds || !creds_is_pid(&creds, child))) {
			fprintf(stderr, "wlx-launch: Incorrect credentials\n");
			goto error;
		}

		/* Not much we can do besides ignore it */
		if (msghdr.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "wlx-launch: Message truncated\n");
			goto error;
		}
		if (msghdr.msg_flags & MSG_CTRUNC) {
			fprintf(stderr, "wlx-launch: Control message truncated\n");
			goto error;
		}


		handle_packet(nread, buf, fds_len, fds);

error:
		for (size_t i = 0; i < fds_len; ++i)
			close(fds_len);
	}

	if (nread == -1 && errno != EAGAIN && errno != EWOULDBLOCK)
		err_errno("recvmsg");
}

#ifdef __linux__
static void
closefrom(int min_fd)
{
	DIR *d;
	struct dirent *dp;
	int max_fd = sysconf(_SC_OPEN_MAX);
	int d_fd;

	d = opendir("/proc/self/fd");
	if (!d)
		err_errno("/proc/self/fd");
	d_fd = dirfd(d);

	while ((dp = readdir(d)) != NULL) {
		int n;

		if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
			continue;

		n = atoi(dp->d_name);

		if (n < min_fd)
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
#endif

/* Flag being unset means we have a signal we need to handle. */
static atomic_flag sigexit_flag = ATOMIC_FLAG_INIT;
static atomic_flag sigchld_flag = ATOMIC_FLAG_INIT;
static atomic_flag sigalrm_flag = ATOMIC_FLAG_INIT;

static void
signal_handler(int signo, siginfo_t *si, void *cntxt)
{
	if (signo == SIGTERM || signo == SIGINT || signo == SIGHUP)
		atomic_flag_clear(&sigexit_flag);
	else if (signo == SIGCHLD)
		atomic_flag_clear(&sigchld_flag);
	else if (signo == SIGALRM && si->si_code == SI_TIMER)
		atomic_flag_clear(&sigalrm_flag);
}

static void
install_signals(sigset_t *orig_mask)
{
	static const int signals[] = {
		SIGTERM, SIGINT, SIGHUP, /* "SIGEXIT" */
		SIGCHLD,
		SIGALRM,
	};
	struct sigaction sa = {
		.sa_flags = SA_SIGINFO,
		.sa_sigaction = signal_handler,
	};
	sigset_t block;

	/* Do a search for "select vs pselect" to see why we do this. */
	sigemptyset(&block);
	for (size_t i = 0; i < sizeof signals / sizeof signals[0]; ++i)
		sigaddset(&block, signals[i]);
	sigprocmask(SIG_BLOCK, &block, orig_mask);

	sigemptyset(&sa.sa_mask);
	for (size_t i = 0; i < sizeof signals / sizeof signals[0]; ++i)
		sigaction(signals[i], &sa, NULL);

	/* set by default */
	atomic_flag_test_and_set(&sigexit_flag);
	atomic_flag_test_and_set(&sigchld_flag);
	atomic_flag_test_and_set(&sigalrm_flag);
}

int
main(int argc, char *argv[])
{
	sigset_t orig_mask, sigchld_set;
	struct itimerspec watchdog_sav = {0};
	struct pollfd notify = { .events = POLLIN };
	timer_t watchdog;
	posix_spawnattr_t attr;

	install_signals(&orig_mask);

	opt_init_defaults();
	opt_parse_args(argc, argv);

	if (timer_create(CLOCK_MONOTONIC, NULL, &watchdog) == -1)
		err_errno("timer_create");

	/*
	 * Need a squeaky clean file descriptor set to make sure it doesn't
	 * mess with the fd-store. stdin/stdout/stderr survive this.
	 */
	closefrom(3);
	notify.fd = make_notify_socket();

	sigemptyset(&sigchld_set);
	sigaddset(&sigchld_set, SIGCHLD);

	posix_spawnattr_init(&attr);
	posix_spawnattr_setsigmask(&attr, &orig_mask);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);

	pid_t child = 0;
	bool child_succeeded = false;

	bool quit = false;
	while (!quit) {
		int ret;
		bool should_waitid;
		bool watchdog_expired;

		if (child == 0) {
			extern char **environ;

			ret = posix_spawnp(&child, opt.command[0], NULL,
					   &attr, opt.command, environ);
			if (ret != 0)
				err_errno("%s", opt.command[0]);

			if (timer_settime(watchdog, 0, &opt.watchdog, NULL) != 0)
				err_errno("timer_settime");
		}

		ret = ppoll(&notify, 1, NULL, &orig_mask);
		if (ret == -1 && errno != EINTR)
			err_errno("ppoll");

		quit = !atomic_flag_test_and_set(&sigexit_flag);
		should_waitid = !atomic_flag_test_and_set(&sigchld_flag);
		watchdog_expired = !atomic_flag_test_and_set(&sigalrm_flag);

		if (ret == 1)
			recv_notify_socket(notify.fd, child);

		if (quit || watchdog_expired) {
			static const struct timespec ts = { .tv_sec = 2 };

			fprintf(stderr, "wlx-launch: Sending SIGTERM to child\n");
			kill(child, SIGTERM);

			ret = sigtimedwait(&sigchld_set, NULL, &ts);
			if (ret == -1 && errno == EAGAIN) {
				fprintf(stderr, "wlx-launch: Sending SIGKILL to child\n");
				kill(child, SIGKILL);
			}
			/*
			 * I couldn't see anything in the documentation about
			 * sigtimedwait messing with the signal mask, but it
			 * seems to. If we don't do this, then it seems to
			 * break the watchdog timer.
			 *
			 * Maybe I'm just doing all of this signal shit wrong.
			 */
			sigprocmask(SIG_SETMASK, &orig_mask, NULL);

			should_waitid = true;
		}

		if (should_waitid) {
			siginfo_t info;
			int n;

			/*
			 * Maybe they sent us another message in their
			 * dying breath? Do this now so we still have their
			 * pid unwaited and valid to check against.
			 */
			recv_notify_socket(notify.fd, child);

			ret = waitid(P_PID, child, &info,
				     WEXITED | WCONTINUED | WSTOPPED);
			if (ret == -1)
				err_errno("waitid");

			psiginfo(&info, "wlx-launch");

			assert(info.si_pid == child);
			child = 0;

			if (watchdog_expired) {
				if (opt.no_restart.watchdog) {
					quit = true;
					child_succeeded = opt.success.watchdog;
				}
				continue;
			}

			switch (info.si_code) {
			case CLD_EXITED:
				n = info.si_status;
				if (!status_set_has_status(&opt.no_restart, n))
					break;

				child_succeeded = status_set_has_status(&opt.success, n);
				quit = true;
				break;
			case CLD_KILLED:
			case CLD_DUMPED:
				n = info.si_status;
				if (!status_set_has_signal(&opt.no_restart, n))
					break;

				child_succeeded = status_set_has_signal(&opt.success, n);
				quit = true;
				break;
			case CLD_STOPPED:
				timer_settime(watchdog, 0,
					      &(struct itimerspec){ 0 },
					      &watchdog_sav);
				break;
			case CLD_CONTINUED:
				timer_settime(watchdog, 0, &watchdog_sav, NULL);
				break;
			default:
				break;
			}
		}
	}

	close(notify.fd);
	timer_delete(watchdog);
	posix_spawnattr_destroy(&attr);

	/* '!' because 0 is success */
	return !child_succeeded;
}
