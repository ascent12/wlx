/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef SESSION_H
#define SESSION_H

#include <stdbool.h>

#include <wlx/session.h>
#include "context.h"

struct wlx_session {
	struct wlx *wlx;
	enum wlx_session_type type;
	wlx_session_create_fn create; /* Only used during init */
	void *userdata;

	bool failed;
};

void
wlxi_session_init_base(struct wlx_session *s,
		       struct wlx *wlx,
		       enum wlx_session_type type,
		       wlx_session_create_fn create);

void
wlxi_session_init_failed(struct wlx_session *s,
			 int result);

void
wlxi_session_add_gfx_device(struct wlx_session *s, int fd, bool render_only);

void
wlxi_session_add_input_device(struct wlx_session *s);

#endif
