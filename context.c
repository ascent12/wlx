/* SPDX-License-Identifier: GPL-2.0-only */

#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "context.h"

struct wlx *
wlx_context_create(void)
{
	struct wlx *wlx;

	wlx = calloc(1, sizeof *wlx);

	wlx->notify.socket = -1;

	return wlx;
}

void
wlx_context_destroy(struct wlx *wlx)
{
	free(wlx);
}

void
wlx_context_set_log_fn(struct wlx *wlx, wlx_log_fn log, void *userdata)
{
	wlx->log = log;
	wlx->log_userdata = userdata;
}

void
wlxi_log(struct wlx *wlx, enum wlx_log_level lvl,
	 const char *func, int line, const char *fmt, ...)
{
	/*
	 * Many uses of this function are like
	 * ```
	 *   wlxi_err(wlx, "Error: %s", strerror(errno));
	 *   do_something_else(errno);
	 * ```
	 * but this callback may change errno, breaking the 2nd line. We make
	 * sure to save/restore it to allow for the above code to work.
	 */
	va_list args;
	int saved_errno = errno;

	va_start(args, fmt);
	wlx->log(wlx->log_userdata, lvl, func, line, fmt, args);
	va_end(args);

	errno = saved_errno;
}

void
wlx_context_set_ev(struct wlx *wlx, const struct wlx_ev_funcs *funcs, void *userdata)
{
	assert(!wlx->ev_funcs);

	wlx->ev_funcs = funcs;
	wlx->ev_userdata = userdata;
}

void
wlxi_ev_exit(struct wlx *wlx)
{
	wlx->ev_funcs->exit(wlx->ev_userdata);
}

void
wlx_ev_source_fd_dispatch(struct wlx_ev_source *ev, int fd, int revents)
{
	ev->fd_cb(ev->cb_userdata, fd, revents);
}

void
wlx_ev_source_timer_dispatch(struct wlx_ev_source *ev)
{
	ev->timer_cb(ev->cb_userdata);
}

void
wlx_ev_source_idle_dispatch(struct wlx_ev_source *ev)
{
	ev->idle_cb(ev->cb_userdata);
	memset(ev, 0, sizeof *ev);
}

void *
wlx_ev_source_get_userdata(struct wlx_ev_source *ev)
{
	return ev->ev_userdata;
}

void
wlx_ev_source_set_userdata(struct wlx_ev_source *ev, void *userdata)
{
	ev->ev_userdata = userdata;
}

int
wlxi_ev_source_init_fd(struct wlx *wlx, struct wlx_ev_source *ev,
		       wlxi_ev_fd_callback_fn cb,
		       void *userdata, int fd, int events)
{
	int ret;

	assert(!ev->fd_cb);
	assert(!ev->cb_userdata);

	ev->fd_cb = cb;
	ev->fd_events = events;
	ev->cb_userdata = userdata;

	ret = wlx->ev_funcs->fd_add(wlx->ev_userdata, ev, fd, events);
	if (ret < 0)
		memset(ev, 0, sizeof *ev);
	return ret;
}

int
wlxi_ev_source_init_timer(struct wlx *wlx, struct wlx_ev_source *ev,
			  wlxi_ev_timer_callback_fn cb,
			  void *userdata, int timeout_ms)
{
	int ret;

	assert(!ev->timer_cb);
	assert(!ev->cb_userdata);

	ev->timer_cb = cb;
	ev->cb_userdata = userdata;

	ret = wlx->ev_funcs->timer_add(wlx->ev_userdata, ev, timeout_ms);
	if (ret < 0)
		memset(ev, 0, sizeof *ev);
	return ret;
}

int
wlxi_ev_source_init_idle(struct wlx *wlx, struct wlx_ev_source *ev,
			 wlxi_ev_idle_callback_fn cb,
			 void *userdata)
{
	int ret;

	assert(!ev->idle_cb);
	assert(!ev->cb_userdata);

	ev->idle_cb = cb;
	ev->cb_userdata = userdata;

	ret = wlx->ev_funcs->idle_add(wlx->ev_userdata, ev);
	if (ret < 0)
		memset(ev, 0, sizeof *ev);
	return ret;
}

int
wlxi_ev_source_fd_update(struct wlx *wlx, struct wlx_ev_source *ev,
			 int events)
{
	int ret;

	/*
	 * Updating this isn't necessarily free (e.g. it may call a syscall
	 * like epoll_ctl), so we bother to check if it's actually necessary.
	 */
	if (ev->fd_events == events)
		return 0;

	ret = wlx->ev_funcs->fd_update(wlx->ev_userdata, ev, events);
	if (ret == 0)
		ev->fd_events = events;

	return ret;
}

int
wlxi_ev_source_timer_update(struct wlx *wlx, struct wlx_ev_source *ev,
			    int timeout_ms)
{
	return wlx->ev_funcs->timer_update(wlx->ev_userdata, ev, timeout_ms);
}

void
wlxi_ev_source_fd_remove(struct wlx *wlx, struct wlx_ev_source *ev)
{
	wlx->ev_funcs->fd_remove(wlx->ev_userdata, ev);
	memset(ev, 0, sizeof *ev);
}

void
wlxi_ev_source_timer_remove(struct wlx *wlx, struct wlx_ev_source *ev)
{
	wlx->ev_funcs->timer_remove(wlx->ev_userdata, ev);
	memset(ev, 0, sizeof *ev);
}
