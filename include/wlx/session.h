/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef WLX_SESSION_H
#define WLX_SESSION_H

#include <wlx/context.h>
#include <stdbool.h>

struct wlx_session;

enum wlx_session_type {
	WLX_SESSION_TYPE_HEADLESS,
	WLX_SESSION_TYPE_TTY,
	WLX_SESSION_TYPE_WAYLAND,
	WLX_SESSION_TYPE_X11,
};

struct wlx_session_funcs {
	void (*add_gfx_device)(struct wlx_session *s);
};

struct wlx_session_tty_funcs {
	void (*active)(struct wlx_session *s, bool is_active);
	void (*lock)(struct wlx_session *s);
	void (*unlock)(struct wlx_session *s);
};

typedef void (*wlx_session_create_fn)(int result, struct wlx_session *s);

enum wlx_session_type
wlx_session_get_type(const struct wlx_session *s);

void
wlx_session_set_userdata(struct wlx_session *s, void *userdata);
void *
wlx_session_get_userdata(struct wlx_session *s);

int
wlx_session_create_tty(struct wlx *wlx,
		       const char *session_id,
		       struct wlx_session **session_out,
		       wlx_session_create_fn create);

#endif
