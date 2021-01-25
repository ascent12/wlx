/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef WLX_LIBEVENT_H
#define WLX_LIBEVENT_H

#include <event2/event.h>

struct wlx;

int
wlx_context_set_libevent(struct wlx *wlx, struct event_base *ev_base);

#endif
