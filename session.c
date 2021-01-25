/* SPDX-License-Identifier: GPL-2.0-only */

#include "session.h"

void
wlxi_session_init_base(struct wlx_session *s,
		       struct wlx *wlx,
		       enum wlx_session_type type,
		       wlx_session_create_fn create)
{
	s->wlx = wlx;
	s->type = type;
	s->create = create;
}

void
wlxi_session_init_failed(struct wlx_session *s,
			 int result)
{
	s->failed = true;
	if (s->create)
		s->create(result, s);
}

enum wlx_session_type
wlx_session_get_type(const struct wlx_session *s)
{
	return s->type;
}

void
wlx_session_set_userdata(struct wlx_session *s, void *userdata)
{
	s->userdata = userdata;
}

void *
wlx_session_get_userdata(struct wlx_session *s)
{
	return s->userdata;
}
