/* SPDX-License-Identifier: GPL-2.0-only */

#include "context.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "util-string.h"

static void
wlxi_watchdog_event(void *userdata)
{
}

static void
wlxi_notify_event(void *userdata, int fd, int revents)
{
}

static int
wlxi_notify_init_watchdog(struct wlx *wlx)
{
	int res = WLX_RESULT_SUCCESS;
	const char *usec_env;
	const char *pid_env;
	uint64_t usec;

	usec_env = getenv("WATCHDOG_USEC");
	pid_env = getenv("WATCHDOG_PID");

	/* Watchdog not enabled */
	if (!usec_env) {
		wlxi_info(wlx, "WATCHDOG_SEC not set");
		goto out;
	}

	if (pid_env) {
		pid_t pid;

		res = wlxi_strtoi(pid_env, &pid);
		if (res < 0) {
			wlxi_err(wlx, "WATCHDOG_PID invalid value");
			goto out;
		}

		/* This was not intended for us */
		if (pid != getpid()) {
			wlxi_info(wlx, "WATCHDOG_PID does not match ours; ignoring");
			goto out;
		}
	}

	res = wlxi_strtoi(usec_env, &usec);
	if (res < 0) {
		wlxi_err(wlx, "WATCHDOG_SET invalid value");
		goto out;
	}

	wlx->notify.watchdog_ms = usec / 1000000;
	/*
	 * We could easily change the event loop API to have nanosecond
	 * precision, but many common event loop libraries only have
	 * millisecond resolution in their APIs. Not to mention that this
	 * would be stupidly quick for a watchdog timer. It should be in
	 * the order of seconds.
	 *
	 * We set the timer for half of the required interval, so 1ms doesn't
	 * work either.
	 */
	if (wlx->notify.watchdog_ms < 2) {
		wlxi_err(wlx, "Do not have the required resolution for WATCHDOG_USEC");
		res = WLX_RESULT_FAILURE;
		goto out;
	}

	res = wlxi_ev_source_init_timer(wlx, &wlx->notify.watchdog,
					wlxi_watchdog_event, wlx,
					wlx->notify.watchdog_ms / 2);
	if (res < 0) {
		wlxi_err(wlx, "Could not start watchdog timer");
	}

out:
	unsetenv("WATCHDOG_USEC");
	unsetenv("WATCHDOG_PID");
	return res;
}

static int
wlxi_notify_init_socket(struct wlx *wlx)
{
	int res = WLX_RESULT_SUCCESS;
	const char *path;
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};
	socklen_t addr_len;
	size_t path_len;

	path = getenv("NOTIFY_SOCKET");
	if (!path) {
		wlxi_warn(wlx, "NOFIFY_SOCKET not set");
		return WLX_RESULT_NO_REMOTE;
	}

	path_len = strlen(path);

#ifdef __linux__
	if (path[0] == '@') {
		/*
		 * Abstract sockets can in theory contain null bytes embedded
		 * in them but since this is going through an environment
		 * variable (which is a C string), these embedded nulls can't
		 * be represented. The Linux kernel pretty prints them as '@',
		 * but there is no way to distingush that from an actual '@',
		 * and there is no other standard escaping method I've seen in
		 * use.
		 * 
		 * Basically, we accept that we can't handle embedded nulls,
		 * and this will fail at connect(). It's whoever set up the
		 * socket's fault for doing that.
		 */

		if (path_len > sizeof addr.sun_path) {
			wlxi_err(wlx, "NOTIFY_SOCKET too long");
			res = WLX_RESULT_INVALID;
			goto out;
		}

		/* Note that this is NOT null-terminated */
		addr.sun_path[0] = '\0';
		memcpy(&addr.sun_path[1], path + 1, path_len - 1);
	} else
#endif
	if (path[0] == '/') {
		if (path_len >= sizeof addr.sun_path) {
			wlxi_err(wlx, "NOTIFY_SOCKET too long");
			res = WLX_RESULT_INVALID;
			goto out;
		}

		strcpy(addr.sun_path, path);
		/* Need to include null terminator for addr_len later */
		++path_len;
	} else {
		/*
		 * Unix sockets can use relative paths, but they're a terrible
		 * idea in this situation, so we just reject them.
		 */
		wlxi_err(wlx, "NOTIFY_SOCKET invalid value");
		res = WLX_RESULT_INVALID;
		goto out;
	}

	/*
	 * SOCK_CLOEXEC is non-standard, but supported by everyone we care
	 * about, and too useful to leave out.
	 */
	wlx->notify.socket = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (wlx->notify.socket == -1) {
		wlxi_err(wlx, "Failed to create socket: %s", strerror(errno));
		res = WLX_RESULT_FAILURE; /* TODO: use errno */
		goto out;
	}

	/* We connect to the socket so we can monitor if the peer is still there. */
	addr_len = offsetof(struct sockaddr_un, sun_path) + path_len;
	if (connect(wlx->notify.socket, (struct sockaddr *)&addr, addr_len) == -1) {
		wlxi_err(wlx, "Failed to connect: %s", strerror(errno));
		res = WLX_RESULT_FAILURE; /* TODO: use errno */
		goto out;
	}

	/* Interested in POLLHUP, which is implied by default. */
	res = wlxi_ev_source_init_fd(wlx, &wlx->notify.socket_event,
				     wlxi_notify_event, wlx, wlx->notify.socket, 0);
	if (res < 0) {
		wlxi_err(wlx, "Could not create event source");
	}

out:
	if (res < 0 && wlx->notify.socket != -1) {
		close(wlx->notify.socket);
		wlx->notify.socket = -1;
	}

	unsetenv("NOTIFY_SOCKET");
	return res;
}

int
wlx_notify_init(struct wlx *wlx)
{
	int res;

	res = wlxi_notify_init_socket(wlx);
	if (res < 0)
		return res;

	res = wlxi_notify_init_watchdog(wlx);
	if (res < 0)
		return res;

	return WLX_RESULT_SUCCESS;
}
