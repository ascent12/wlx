/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CONTEXT_H
#define CONTEXT_H

#include <wlx/context.h>
#include <wlx/result.h>

#include <stdlib.h>
#include <stdint.h>

typedef void (*wlxi_ev_fd_callback_fn)(void *userdata, int fd, int revents);
typedef void (*wlxi_ev_timer_callback_fn)(void *userdata);
typedef void (*wlxi_ev_idle_callback_fn)(void *userdata);

struct wlx_ev_source {
	union {
		wlxi_ev_fd_callback_fn fd_cb;
		wlxi_ev_timer_callback_fn timer_cb;
		wlxi_ev_idle_callback_fn idle_cb;
	};
	int fd_events;
	void *cb_userdata;
	void *ev_userdata;
};

struct wlx {
	const struct wlx_ev_funcs *ev_funcs;
	void *ev_userdata;

	wlx_log_fn log;
	void *log_userdata;

	struct {
		int socket;
		uint64_t watchdog_ms;

		struct wlx_ev_source socket_event;
		struct wlx_ev_source watchdog;
	} notify;
};

void
wlxi_ev_exit(struct wlx *wlx);

int
wlxi_ev_source_init_fd(struct wlx *wlx, struct wlx_ev_source *ev,
		       wlxi_ev_fd_callback_fn cb,
		       void *userdata, int fd, int events);
int
wlxi_ev_source_init_timer(struct wlx *wlx, struct wlx_ev_source *ev,
			  wlxi_ev_timer_callback_fn cb,
			  void *userdata, int timeout_ms);
int
wlxi_ev_source_init_idle(struct wlx *wlx, struct wlx_ev_source *ev,
			 wlxi_ev_idle_callback_fn cb,
			 void *userdata);
int
wlxi_ev_source_fd_update(struct wlx *wlx, struct wlx_ev_source *ev,
			 int events);
int
wlxi_ev_source_timer_update(struct wlx *wlx, struct wlx_ev_source *ev,
			    int timeout_ms);
void
wlxi_ev_source_fd_remove(struct wlx *wlx, struct wlx_ev_source *ev);
void
wlxi_ev_source_timer_remove(struct wlx *wlx, struct wlx_ev_source *ev);

void
wlxi_log(struct wlx *wlx, enum wlx_log_level lvl,
	 const char *func, int line, const char *fmt, ...)
__attribute__((format(printf, 5, 6)));

#define wlxi_log_(wlx, lvl, ...) wlxi_log(wlx, lvl, __func__, __LINE__, __VA_ARGS__)
#define wlxi_debug(wlx, ...) wlxi_log_(wlx, WLX_LOG_DEBUG, __VA_ARGS__)
#define wlxi_info(wlx, ...) wlxi_log_(wlx, WLX_LOG_INFO, __VA_ARGS__)
#define wlxi_warn(wlx, ...) wlxi_log_(wlx, WLX_LOG_WARN, __VA_ARGS__)
#define wlxi_err(wlx, ...) wlxi_log_(wlx, WLX_LOG_ERR, __VA_ARGS__)

/* Simple wrapper over calloc(1, size) that logs a message on failure */
static inline void *
__attribute__((alloc_size(4)))
wlxi_alloc_(struct wlx *wlx, const char *func, int line, size_t size)
{
	void *ptr = calloc(1, size);
	if (!ptr)
		wlxi_log(wlx, WLX_LOG_ERR, func, line,
			 "Allocation of size %zu failed", size);
	return ptr;
}
#define wlxi_alloc(wlx, size) wlxi_alloc_(wlx, __func__, __LINE__, size)

#endif
