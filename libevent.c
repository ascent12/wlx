/* SPDX-License-Identifier: GPL-2.0-only */

#include <wlx/libevent.h>

#include <sys/poll.h>

#include "context.h"

static void
wlxi_libevent_exit(void *userdata)
{
	struct event_base *ev_base = userdata;
	event_base_loopexit(ev_base, NULL);
}

static void
wlxi_libevent_fd_event(int fd, short flags, void *userdata)
{
	struct wlx_ev_source *src = userdata;
	/*
	 * For some weird-ass reason, instead of having a status
	 * for POLLHUP or POLLERR, they just send EV_READ | EV_WRITE,
	 * and I guess just expect you to use the return codes from
	 * the functions that would've used the fd.
	 *
	 * EV_CLOSED is "almost" what we want, but actually only handles
	 * POLLRDHUP. We just hope that it doesn't screw with anything.
	 * POLLERR still doesn't work properly.
	 *
	 * XXX: Consider using poll(pfd, 1, 0) to work around this.
	 */
	int revents = 0;
	if (flags & EV_READ)
		revents |= POLLIN;
	if (flags & EV_WRITE)
		revents |= POLLOUT;
	if (flags & EV_CLOSED)
		revents |= POLLHUP; /* POLLRDHUP; see comment above */

	wlx_ev_source_fd_dispatch(src, fd, revents);
}

static int
wlxi_libevent_fd_add(void *userdata, struct wlx_ev_source *src, int fd, int events)
{
	struct event_base *ev_base = userdata;
	struct event *event;
	short flags = EV_PERSIST | EV_CLOSED;

	if (events & POLLIN)
		flags |= EV_READ;
	if (events & POLLOUT)
		flags |= EV_WRITE;

	event = event_new(ev_base, fd, flags, wlxi_libevent_fd_event, src);
	if (!event)
		return WLX_RESULT_FAILURE;

	if (event_add(event, NULL) == -1) {
		event_free(event);
		return WLX_RESULT_FAILURE;
	}

	wlx_ev_source_set_userdata(src, event);
	return WLX_RESULT_SUCCESS;
}

static int
wlxi_libevent_fd_update(void *userdata, struct wlx_ev_source *src, int events)
{
	int res;
	struct event_base *ev_base = userdata;
	struct event *event = wlx_ev_source_get_userdata(src);
	int fd;

	/*
	 * libevent doesn't support updating flags in-place, so we need to
	 * dance around it by making a new event. We also don't want to mess
	 * with the old event if the new one fails for some reason.
	 */

	event_get_assignment(event, NULL, &fd, NULL, NULL, NULL);

	res = wlxi_libevent_fd_add(ev_base, src, fd, events);
	if (res < 0)
		return res;

	event_free(event);
	return WLX_RESULT_SUCCESS;
}

static void
wlxi_libevent_timer_event(int unused1, short unused2, void *userdata)
{
	struct wlx_ev_source *src = userdata;
	wlx_ev_source_timer_dispatch(src);
}

static int
wlxi_libevent_timer_update(void *userdata, struct wlx_ev_source *src, int timeout_ms)
{
	int res;
	struct event *event = wlx_ev_source_get_userdata(src);
	struct timeval tv = {
		.tv_sec = timeout_ms / 1000,
		.tv_usec = timeout_ms % 1000 * 1000,
	};

	if (timeout_ms == 0)
		res = event_del(event);
	else
		res = event_add(event, &tv);

	return res == 0 ? WLX_RESULT_SUCCESS : WLX_RESULT_FAILURE;
}

static int
wlxi_libevent_timer_add(void *userdata, struct wlx_ev_source *src, int timeout_ms)
{
	int res;
	struct event_base *ev_base = userdata;
	struct event *event;

	event = event_new(ev_base, -1, EV_TIMEOUT, wlxi_libevent_timer_event, src);
	if (!event)
		return WLX_RESULT_FAILURE;

	wlx_ev_source_set_userdata(src, event);

	res = wlxi_libevent_timer_update(ev_base, src, timeout_ms);
	if (res < 0)
		event_free(event);
	return res;
}

static void
wlxi_libevent_event_remove(void *userdata, struct wlx_ev_source *src)
{
	struct event *event = wlx_ev_source_get_userdata(src);
	event_free(event);
}

static void
wlxi_libevent_idle_event(int sig, short events, void *userdata)
{
	struct wlx_ev_source *src = userdata;
	wlx_ev_source_idle_dispatch(src);
}

static int
wlxi_libevent_idle_add(void *userdata, struct wlx_ev_source *src)
{
	/*
	 * libevent doesn't have a dedicated idle type, but it can be
	 * accomplished with a timeout of 0 (or NULL here).
	 */
	int res;
	struct event_base *ev_base = userdata;
	res = event_base_once(ev_base, -1, EV_TIMEOUT,
			      wlxi_libevent_idle_event, src, NULL);
	return res == 0 ? WLX_RESULT_SUCCESS : WLX_RESULT_FAILURE;
}

static const struct wlx_ev_funcs wlxi_libevent_funcs = {
	.exit = wlxi_libevent_exit,
	.fd_add = wlxi_libevent_fd_add,
	.fd_update = wlxi_libevent_fd_update,
	.fd_remove = wlxi_libevent_event_remove,
	.timer_add = wlxi_libevent_timer_add,
	.timer_update = wlxi_libevent_timer_update,
	.timer_remove = wlxi_libevent_event_remove,
	.idle_add = wlxi_libevent_idle_add,
};

int
wlx_context_set_libevent(struct wlx *wlx, struct event_base *ev_base)
{
	int req = EV_FEATURE_EARLY_CLOSE;

	if ((event_base_get_features(ev_base) & req) != req) {
		wlxi_err(wlx, "libevent base does not have the required features");
		return WLX_RESULT_INVALID;
	}

	wlx_context_set_ev(wlx, &wlxi_libevent_funcs, ev_base);
	return WLX_RESULT_SUCCESS;
}
