/* SPDX-License-Identifier: GPL-2.0-only */

#include <signal.h>
#include <stdio.h>
#include <poll.h>

#include <wlx/context.h>
#include <wlx/session.h>
#include <wlx/result.h>
#include <wlx/libevent.h>

#include <event2/event.h>

static void
my_log(void *userdata, enum wlx_log_level lvl,
       const char *func, int line, const char *fmt, va_list args)
{
	printf("[%s:%d] ", func, line);
	vprintf(fmt, args);
	printf("\n");
}

static void
sigint_handler(int sig, short events, void *data)
{
	struct event_base *ev = data;
	event_base_loopexit(ev, NULL);

	printf("Got SIGINT\n");
}

int main()
{
	struct event_config *cfg = event_config_new();
	event_config_require_features(cfg, EV_FEATURE_EARLY_CLOSE);

	struct event_base *ev_base = event_base_new_with_config(cfg);

	struct event *sigint = event_new(ev_base, SIGINT, EV_SIGNAL,
					 sigint_handler, ev_base);
	event_add(sigint, NULL);

	struct wlx *wlx = wlx_context_create();
	struct wlx_session *session;
	
	wlx_context_set_log_fn(wlx, my_log, NULL);
	wlx_context_set_libevent(wlx, ev_base);

	wlx_session_create_tty(wlx, NULL, &session, NULL);

	event_base_dispatch(ev_base);
}
