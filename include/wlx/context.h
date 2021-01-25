/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef WLX_CONTEXT_H
#define WLX_CONTEXT_H

#include <stdarg.h>

enum wlx_log_level {
	WLX_LOG_DEBUG,
	WLX_LOG_INFO,
	WLX_LOG_WARN,
	WLX_LOG_ERR,
	WLX_LOG_LAST
};

struct wlx;
struct wlx_ev_source;

typedef void (*wlx_log_fn)(void *userdata, enum wlx_log_level lvl,
			   const char *func, int line,
			   const char *fmt, va_list args);
typedef void (*wlx_ev_exit_fn)(void *userdata);
typedef int (*wlx_ev_fd_add_fn)(void *userdata, struct wlx_ev_source *ev,
				int fd, int events);
typedef int (*wlx_ev_fd_update_fn)(void *userdata, struct wlx_ev_source *ev,
				  int events);
typedef void (*wlx_ev_fd_remove_fn)(void *userdata, struct wlx_ev_source *ev);
typedef int (*wlx_ev_timer_add_fn)(void *userdata, struct wlx_ev_source *ev, int timeout_ms);
typedef int (*wlx_ev_timer_update_fn)(void *userdata, struct wlx_ev_source *ev, int timeout_ms);
typedef void (*wlx_ev_timer_remove_fn)(void *userdata, struct wlx_ev_source *ev);
typedef int (*wlx_ev_idle_fn)(void *userdata, struct wlx_ev_source *ev);

struct wlx_ev_funcs {
	wlx_ev_exit_fn exit;

	wlx_ev_fd_add_fn fd_add;
	wlx_ev_fd_update_fn fd_update;
	wlx_ev_fd_remove_fn fd_remove;

	wlx_ev_timer_add_fn timer_add;
	wlx_ev_timer_update_fn timer_update;
	wlx_ev_timer_remove_fn timer_remove;

	wlx_ev_idle_fn idle_add;
};

struct wlx *
wlx_context_create(void);
void
wlx_context_destroy(struct wlx *wlx);

void
wlx_context_set_log_fn(struct wlx *wlx, wlx_log_fn log, void *userdata);

void
wlx_context_set_ev(struct wlx *wlx, const struct wlx_ev_funcs *funcs, void *userdata);

void *
wlx_ev_source_get_userdata(struct wlx_ev_source *ev);
void
wlx_ev_source_set_userdata(struct wlx_ev_source *ev, void *userdata);

void
wlx_ev_source_fd_dispatch(struct wlx_ev_source *ev, int fd, int revents);
void
wlx_ev_source_timer_dispatch(struct wlx_ev_source *ev);
void
wlx_ev_source_idle_dispatch(struct wlx_ev_source *ev);

int
wlx_notify_init(struct wlx *wlx);

#endif
