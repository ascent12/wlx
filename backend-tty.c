/* SPDX-License-Identifier: GPL-2.0-only */

#include "session.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
/*
 * Non-standard: For major() / minor()
 * The BSDs put their version in <sys/types.h>
 */
#include <sys/sysmacros.h>
#endif

#include <dbus/dbus.h>
#include <libinput.h>
#include <libudev.h>

struct wlxi_dbus_info {
	const char *name;
	const char *path;
	const char *manager_iface;
	const char *seat_iface;
	const char *session_iface;
};

/*
 * Logind and consolekit2 are basically interchangable for what
 * we need, but the dbus interface names are different.
 */

static const struct wlxi_dbus_info wlxi_dbus_logind = {
	.name = "org.freedesktop.login1",
	.path = "/org/freedesktop/login1",
	.manager_iface = "org.freedesktop.login1.Manager",
	.seat_iface = "org.freedesktop.login1.Seat",
	.session_iface = "org.freedesktop.login1.Session",
};

static const struct wlxi_dbus_info wlxi_dbus_ck2 = {
	.name = "org.freedesktop.ConsoleKit",
	.path = "/org/freedesktop/ConsoleKit",
	.manager_iface = "org.freedesktop.ConsoleKit.Manager",
	.seat_iface = "org.freedesktop.ConsoleKit.Seat",
	.session_iface = "org.freedesktop.ConsoleKit.Session",
};

struct wlxi_tty_session {
	struct wlx_session base;

	/* Argument to wlx_session_create_tty */
	char *session_id;

	DBusConnection *dbus;

	struct udev *udev;
	struct udev_monitor *monitor;
	struct libinput *libinput;
	bool libinput_has_seat_assigned;

	struct wlx_ev_source dbus_dispatch;
	struct wlx_ev_source monitor_fd;
	struct wlx_ev_source libinput_fd;
	struct wlx_ev_source enum_drm_devs;

	const struct wlxi_dbus_info *info;
	char *session_path;
	char *seat_path;
	char *seat; /* e.g. "seat0" */
	bool active;
	bool have_control;
};

static void
wlxi_dbus_dispatch_event(void *userdata)
{
	struct wlxi_tty_session *s = userdata;

	while (dbus_connection_dispatch(s->dbus) == DBUS_DISPATCH_DATA_REMAINS)
		/* Keep dispatching */;
}

static void
wlxi_dbus_dispatch_status(DBusConnection *dbus, DBusDispatchStatus status, void *userdata)
{
	struct wlxi_tty_session *s = userdata;

	switch (status) {
	case DBUS_DISPATCH_DATA_REMAINS:
		/* Already scheduled, don't need to do it again */
		if (s->dbus_dispatch.idle_cb)
			break;

		wlxi_ev_source_init_idle(s->base.wlx, &s->dbus_dispatch,
					 wlxi_dbus_dispatch_event, s);

		break;
	case DBUS_DISPATCH_COMPLETE:
		/* Don't need to do anything */
		break;
	case DBUS_DISPATCH_NEED_MEMORY:
		/* TODO: Put more effort into handling OOM */
		break;
	}
}

static int
wlxi_to_dbus_flags(int revents)
{
	int ret = 0;
	if (revents & POLLIN)
		ret |= DBUS_WATCH_READABLE;
	if (revents & POLLOUT)
		ret |= DBUS_WATCH_WRITABLE;
	if (revents & POLLERR)
		ret |= DBUS_WATCH_ERROR;
	if (revents & POLLHUP)
		ret |= DBUS_WATCH_HANGUP;
	return ret;
}

struct wlxi_dbus_watch_userdata {
	struct wlxi_tty_session *s;
	struct wlx_ev_source ev;
};

static void
wlxi_dbus_watch_event(void *userdata, int fd, int revents)
{
	DBusWatch *watch = userdata;
	struct wlxi_dbus_watch_userdata *d = dbus_watch_get_data(watch);
	struct wlxi_tty_session *s = d->s;

	dbus_watch_handle(watch, wlxi_to_dbus_flags(revents));

	/*
	 * libdbus doesn't automatically dispatch messages when it has read
	 * them, but doesn't seem to notify us about pending messages at this
	 * point, which makes me wonder what
	 * dbus_connection_set_dispatch_status_function actually does.
	 * 
	 * Anyway, we just hijack that callback so we actually start
	 * dispatching messages.
	 */
	wlxi_dbus_dispatch_status(s->dbus,
				  dbus_connection_get_dispatch_status(s->dbus),
				  s);
}

static int
wlxi_from_dbus_flags(int flags)
{
	int ret = 0;
	if (flags & DBUS_WATCH_READABLE)
		ret |= POLLIN;
	if (flags & DBUS_WATCH_WRITABLE)
		ret |= POLLOUT;
	/* HANGUP and ERROR will never be used with this function */
	return ret;
}

static dbus_bool_t
wlxi_dbus_add_watch(DBusWatch *watch, void *userdata)
{
	struct wlxi_tty_session *s = userdata;
	struct wlxi_dbus_watch_userdata *d;
	int events = 0;
	int ret;

	d = calloc(1, sizeof *d);
	if (!d)
		return false;

	if (dbus_watch_get_enabled(watch))
		events = wlxi_from_dbus_flags(dbus_watch_get_flags(watch));

	ret = wlxi_ev_source_init_fd(s->base.wlx, &d->ev,
				     wlxi_dbus_watch_event,
				     watch,
				     dbus_watch_get_unix_fd(watch),
				     events);
	if (ret < 0) {
		free(d);
		return false;
	}

	d->s = s;
	dbus_watch_set_data(watch, d, free);

	return true;
}

static void
wlxi_dbus_remove_watch(DBusWatch *watch, void *userdata)
{
	struct wlxi_tty_session *s = userdata;
	struct wlxi_dbus_watch_userdata *d = dbus_watch_get_data(watch);

	wlxi_ev_source_fd_remove(s->base.wlx, &d->ev);
}

static void
wlxi_dbus_toggle_watch(DBusWatch *watch, void *userdata)
{
	struct wlxi_tty_session *s = userdata;
	struct wlxi_dbus_watch_userdata *d = dbus_watch_get_data(watch);
	int events = 0;

	if (dbus_watch_get_enabled(watch))
		events = wlxi_from_dbus_flags(dbus_watch_get_flags(watch));

	wlxi_ev_source_fd_update(s->base.wlx, &d->ev, events);
}

struct wlxi_dbus_timeout_userdata {
	struct wlx *wlx;
	struct wlx_ev_source ev;
};

static void
wlxi_dbus_timeout_event(void *userdata)
{
	DBusTimeout *timeout = userdata;
	struct wlxi_dbus_timeout_userdata *d = dbus_timeout_get_data(timeout);

	dbus_timeout_handle(timeout);

	wlxi_ev_source_timer_update(d->wlx, &d->ev,
				    dbus_timeout_get_interval(timeout));
}

static dbus_bool_t
wlxi_dbus_add_timeout(DBusTimeout *timeout, void *userdata)
{
	struct wlxi_tty_session *s = userdata;
	struct wlxi_dbus_timeout_userdata *d;
	int ret;

	d = calloc(1, sizeof *d);
	if (!d)
		return false;

	ret = wlxi_ev_source_init_timer(s->base.wlx, &d->ev,
					wlxi_dbus_timeout_event,
					timeout,
					dbus_timeout_get_interval(timeout));
	if (ret < 0) {
		free(d);
		return false;
	}

	d->wlx = s->base.wlx;
	dbus_timeout_set_data(timeout, d, free);

	return true;
}

static void
wlxi_dbus_remove_timeout(DBusTimeout *timeout, void *userdata)
{
	struct wlxi_dbus_timeout_userdata *d = dbus_timeout_get_data(timeout);

	wlxi_ev_source_timer_remove(d->wlx, &d->ev);
}

static void
wlxi_dbus_toggle_timeout(DBusTimeout *timeout, void *userdata)
{
	struct wlxi_tty_session *s = userdata;
	struct wlx_ev_source *ev = dbus_timeout_get_data(timeout);
	int timeout_ms = 0;

	if (dbus_timeout_get_enabled(timeout))
		timeout_ms = dbus_timeout_get_interval(timeout);

	wlxi_ev_source_timer_update(s->base.wlx, ev, timeout_ms);
}

static int
wlxi_res_from_dbus(DBusError *err)
{
	int ret;

	if (!dbus_error_is_set(err))
		ret = WLX_RESULT_SUCCESS;
	else if (dbus_error_has_name(err, DBUS_ERROR_NO_MEMORY))
		ret = WLX_RESULT_OOM;
	else
		ret = WLX_RESULT_FAILURE;

	dbus_error_free(err);
	return ret;
}

/* TODO: Move somewhere else */
static int
wlxi_res_from_errno(int e)
{
	switch (e) {
	case 0:
		return WLX_RESULT_SUCCESS;
	case ENOMEM:
		return WLX_RESULT_OOM;
	default:
		return WLX_RESULT_FAILURE;
	}
}

static void
wlxi_dbus_signal_add_match(struct wlxi_tty_session *s,
			   const char *sender,
			   const char *interface,
			   const char *path,
			   const char *member)
{
	static const char *fmt =
		"type='signal',"
		"sender='%s',"
		"interface='%s',"
		"path='%s',"
		"member='%s'";
	char buf[256];

	/*
	 * All of the inputs to this function will be compile time constants,
	 * so we don't really have to worry about truncation here.
	 */
	snprintf(buf, sizeof buf, fmt, sender, interface, path, member);

	dbus_bus_add_match(s->dbus, buf, NULL);
}

static int
wlxi_dbus_call_with_reply(struct wlxi_tty_session *s,
			  DBusPendingCallNotifyFunction fn,
			  const char *dest, const char *path,
			  const char *iface, const char *method,
			  ...)
{
	DBusMessage *msg;
	int first_arg;
	DBusPendingCall *reply;
	va_list args;
	
	msg = dbus_message_new_method_call(dest, path, iface, method);
	if (!msg)
		return WLX_RESULT_OOM;

	/* Absolutely no idea why we need to separate the first argument */
	va_start(args, method);
	first_arg = va_arg(args, int);
	if (!dbus_message_append_args_valist(msg, first_arg, args)) {
		va_end(args);
		goto err_unref;
	}
	va_end(args);

	if (!dbus_connection_send_with_reply(s->dbus, msg, &reply, -1))
		goto err_unref;

	if (!dbus_pending_call_set_notify(reply, fn, s, NULL))
		goto err_cancel;

	dbus_message_unref(msg);

	return WLX_RESULT_SUCCESS;

err_cancel:
	dbus_pending_call_cancel(reply);
	dbus_pending_call_unref(reply);
err_unref:
	dbus_message_unref(msg);
	return WLX_RESULT_OOM;
}

static int
wlxi_dbus_reply_(struct wlx *wlx, const char *func, int line,
		DBusPendingCall *pending,
		const char *sig, DBusMessage **msg_out)
{
	DBusMessage *msg = dbus_pending_call_steal_reply(pending);
	DBusError err = DBUS_ERROR_INIT;
	int res;

	dbus_pending_call_unref(pending);

	if (dbus_set_error_from_message(&err, msg)) {
		wlxi_log(wlx, WLX_LOG_ERR, func, line,
			 "%s: %s", err.name, err.message);
		res = wlxi_res_from_dbus(&err);
		goto error;
	}

	if (sig && !dbus_message_has_signature(msg, sig)) {
		wlxi_log(wlx, WLX_LOG_ERR, func, line,
			 "Signature mismatch: expected \"%s\", got \"%s\"",
			 sig, dbus_message_get_signature(msg));
		res = WLX_RESULT_FAILURE;
		goto error;
	}

	*msg_out = msg;
	return WLX_RESULT_SUCCESS;

error:
	*msg_out = NULL;
	dbus_message_unref(msg);
	return res;
}
#define wlxi_dbus_reply(wlx, pending, sig, msg_out) \
	wlxi_dbus_reply_(wlx, __func__, __LINE__, pending, sig, msg_out)

static void
wlxi_tty_notify_user(struct wlxi_tty_session *s)
{
	struct wlx *wlx = s->base.wlx;

	if (s->base.failed)
		return;

	/* Need both of "TakeControl" and "GetAll" properties to be complete */
	if (!s->have_control || !s->seat)
		return;

	/*
	 * Calling this will "activate" libinput, and cause it to go fetch a
	 * bunch of EVIOCREVOKE'd devices, which won't accomplish anything. We try
	 * to keep libinput to be in sync with "active", which means we have to
	 * delay this call until laster.
	 */
	if (s->active) {
		if (libinput_udev_assign_seat(s->libinput, s->seat) == -1) {
			wlxi_err(wlx, "Failed to assign seat to libinput");
			wlxi_session_init_failed(&s->base, WLX_RESULT_FAILURE);
			return;
		}
		s->libinput_has_seat_assigned = true;
	}

	/*
	 * However with DRM devices, opening them in an inactive state is fine.
	 * They won't have DRM master set, but we can still get a lot of
	 * useful initialization done.
	 */
	if (udev_monitor_enable_receiving(s->monitor) < 0) {
		wlxi_err(wlx, "Failed to enable udev monitor");
		wlxi_session_init_failed(&s->base, WLX_RESULT_FAILURE);
		return;
	}
}

static void
wlxi_dbus_recv_session_get_props(DBusPendingCall *pending, void *userdata)
{
	struct wlxi_tty_session *s = userdata;
	struct wlx *wlx = s->base.wlx;
	DBusMessage *msg;
	DBusMessageIter args, array;
	bool has_active = false, has_seat = true;
	int res;

	res = wlxi_dbus_reply(wlx, pending, "a{sv}", &msg);
	if (res < 0) {
		wlxi_session_init_failed(&s->base, res);
		return;
	}

	/* Top level container for all arguments */
	dbus_message_iter_init(msg, &args);

	res = WLX_RESULT_SUCCESS;
	/* Array of dictionary entries */
	dbus_message_iter_recurse(&args, &array);
	do {
		DBusMessageIter dict, value;
		const char *key;
		const char *sig;

		/* Struct of key and value */
		dbus_message_iter_recurse(&array, &dict);
		dbus_message_iter_get_basic(&dict, &key);
		dbus_message_iter_next(&dict);
		/* 'recurse' to unpack DBus variant */
		dbus_message_iter_recurse(&dict, &value);

		sig = dbus_message_iter_get_signature(&value);

		/* Logind is uppercase, CK2 lowercase */
		if (strcmp(key, "Active") == 0 || strcmp(key, "active") == 0) {
			dbus_bool_t active;

			if (strcmp(sig, "b") != 0) {
				wlxi_err(wlx, "Wrong DBus type: %s", sig);
				res = WLX_RESULT_FAILURE;
				break;
			}

			has_active = true;
			dbus_message_iter_get_basic(&value, &active);

			wlxi_info(wlx, "Session %sactive", active ? "" : "in");
		} else if (strcmp(key, "Seat") == 0) {
			DBusMessageIter tuple;
			const char *seat, *seat_path;

			if (strcmp(sig, "(so)") != 0) {
				wlxi_err(wlx, "Wrong DBus type: %s", sig);
				res = WLX_RESULT_FAILURE;
				break;
			}

			has_seat = true;
			dbus_message_iter_recurse(&value, &tuple);
			dbus_message_iter_get_basic(&tuple, &seat);
			dbus_message_iter_next(&tuple);
			dbus_message_iter_get_basic(&tuple, &seat_path);

			wlxi_info(wlx, "Seat: name: \"%s\", path: %s", seat, seat_path);

			s->seat = strdup(seat);
			s->seat_path = strdup(seat_path);

			if (!s->seat || !s->seat_path) {
				res = WLX_RESULT_OOM;
				break;
			}
		}
	} while (dbus_message_iter_next(&array));

	dbus_message_unref(msg);

	if (res < 0) {
		wlxi_session_init_failed(&s->base, res);
		return;
	}

	if (!has_active || !has_seat) {
		wlxi_err(wlx, "Missing required DBus properties");
		wlxi_session_init_failed(&s->base, WLX_RESULT_FAILURE);
		return;
	}

	wlxi_tty_notify_user(s);
}

static void
wlxi_dbus_recv_take_control(DBusPendingCall *pending, void *userdata)
{
	struct wlxi_tty_session *s = userdata;
	struct wlx *wlx = s->base.wlx;
	DBusMessage *msg;
	int res;

	res = wlxi_dbus_reply(wlx, pending, NULL, &msg);
	if (res < 0) {
		wlxi_session_init_failed(&s->base, res);
		return;
	}

	dbus_message_unref(msg);
	s->have_control = true;

	wlxi_tty_notify_user(s);
}

static void
wlxi_dbus_recv_get_session(DBusPendingCall *pending, void *userdata)
{
	struct wlxi_tty_session *s = userdata;
	struct wlx *wlx = s->base.wlx;
	DBusMessage *msg;
	const char *session_path;
	int res;

	res = wlxi_dbus_reply(wlx, pending, "o", &msg);
	if (res < 0) {
		wlxi_session_init_failed(&s->base, res);
		return;
	}

	dbus_message_get_args(msg, NULL,
			      DBUS_TYPE_OBJECT_PATH, &session_path,
			      DBUS_TYPE_INVALID);
	dbus_message_unref(msg);

	wlxi_info(wlx, "Session: path: %s", session_path);

	s->session_path = strdup(session_path);
	if (!s->session_path) {
		wlxi_session_init_failed(&s->base, WLX_RESULT_OOM);
		return;
	}

	wlxi_dbus_signal_add_match(s, s->info->name, s->info->session_iface,
				   session_path, "PauseDevice");
	wlxi_dbus_signal_add_match(s, s->info->name, s->info->session_iface,
				   session_path, "ResumeDevice");
	wlxi_dbus_signal_add_match(s, s->info->name, "org.freedesktop.DBus.Properties",
				   session_path, "PropertiesChanged");

	res = wlxi_dbus_call_with_reply(s, wlxi_dbus_recv_session_get_props,
					s->info->name,
					session_path,
					"org.freedesktop.DBus.Properties",
					"GetAll",
					DBUS_TYPE_STRING, &s->info->session_iface,
					DBUS_TYPE_INVALID);
	if (res < 0)
		wlxi_session_init_failed(&s->base, res);

	res = wlxi_dbus_call_with_reply(s, wlxi_dbus_recv_take_control,
					s->info->name,
					session_path,
					s->info->session_iface,
					"TakeControl",
					DBUS_TYPE_BOOLEAN, &(dbus_bool_t){ false },
					DBUS_TYPE_INVALID);
	if (res < 0)
		wlxi_session_init_failed(&s->base, res);
}

static void
wlxi_dbus_recv_list_names(DBusPendingCall *pending, void *userdata)
{
	struct wlxi_tty_session *s = userdata;
	struct wlx *wlx = s->base.wlx;
	DBusMessage *msg;
	DBusMessageIter args, names;
	bool have_logind = false, have_ck2 = false;
	const char *arg = s->session_id;
	int res;

	res = wlxi_dbus_reply(wlx, pending, "as", &msg);
	if (res < 0) {
		wlxi_session_init_failed(&s->base, res);
		return;
	}

	/* Top level container for all arguments */
	dbus_message_iter_init(msg, &args);

	/* Array of strings */
	dbus_message_iter_recurse(&args, &names);
	do {
		const char *name;
		dbus_message_iter_get_basic(&names, &name);

		if (strcmp(name, wlxi_dbus_logind.name) == 0) {
			wlxi_info(wlx, "Using logind");
			have_logind = true;
		} else if (strcmp(name, wlxi_dbus_ck2.name) == 0) {
			wlxi_info(wlx, "Using consolekit2");
			have_ck2 = true;
		}
	} while (dbus_message_iter_next(&names));

	dbus_message_unref(msg);

	if (have_logind) {
		s->info = &wlxi_dbus_logind;
		if (!arg)
			arg = "self";
		res = wlxi_dbus_call_with_reply(s, wlxi_dbus_recv_get_session,
						s->info->name,
						s->info->path,
						s->info->manager_iface,
						"GetSession",
						DBUS_TYPE_STRING, &arg,
						DBUS_TYPE_INVALID);
	} else if (have_ck2) {
		s->info = &wlxi_dbus_ck2;
		if (arg) {
			res = wlxi_dbus_call_with_reply(s, wlxi_dbus_recv_get_session,
							s->info->name,
							s->info->path,
							s->info->manager_iface,
							"GetSessionForCookie",
							DBUS_TYPE_STRING, &arg,
							DBUS_TYPE_INVALID);
		} else {
			res = wlxi_dbus_call_with_reply(s, wlxi_dbus_recv_get_session,
							s->info->name,
							s->info->path,
							s->info->manager_iface,
							"GetCurrentSession",
							DBUS_TYPE_INVALID);
		}
	} else {
		wlxi_err(wlx, "No session manager found (logind/consolekit2)");
		res = WLX_RESULT_NO_REMOTE;
	}

	if (res < 0)
		wlxi_session_init_failed(&s->base, res);
	else
		wlxi_dbus_signal_add_match(s, s->info->name, s->info->manager_iface,
					   s->info->path, "SessionRemoved");
}

static DBusHandlerResult
wlxi_dbus_filter(DBusConnection *dbus, DBusMessage *msg, void *userdata)
{
	struct wlxi_tty_session *s = userdata;

	/* Can happen in early initialization */
	if (!s->info)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_is_signal(msg, s->info->manager_iface, "SessionRemoved")) {
		wlxi_debug(s->base.wlx, "Session Removed");
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static void
wlxi_udev_event(void *userdata, int fd, int revents)
{
	struct wlxi_tty_session *s = userdata;
	struct udev_device *dev;

	dev = udev_monitor_receive_device(s->monitor);
	if (dev) {
		wlxi_warn(s->base.wlx, "Could not read udev event: %s",
			  strerror(errno));
		/* Not fatal */
		return;
	}

	udev_device_unref(dev);
}

static void
wlxi_libinput_event(void *userdata, int fd, int revents)
{
	struct wlxi_tty_session *s = userdata;
	struct libinput_event *ev;
	int res;

	res = libinput_dispatch(s->libinput);
	if (res < 0) {
		wlxi_warn(s->base.wlx, "libinput dispatch failed: %s",
			  strerror(-res));
		/* Not fatal; just keep going */
	}

	while ((ev = libinput_get_event(s->libinput)) != NULL) {
		/* TODO: Handle events */

		libinput_event_destroy(ev);
	}
}

static int
wlxi_libinput_open_restricted(const char *path, int flags, void *userdata)
{
	struct wlxi_tty_session *s = userdata;
	struct wlx *wlx = s->base.wlx;
	struct stat st;
	DBusMessage *msg, *reply;
	DBusError err = DBUS_ERROR_INIT;
	dbus_uint32_t maj, min;
	int fd;
	dbus_bool_t active;
	int fd_flags;

	if (stat(path, &st) == -1) {
		wlxi_err(wlx, "Failed to stat %s: %s", path, strerror(errno));
		return -errno;
	}

	maj = major(st.st_rdev);
	min = minor(st.st_rdev);

	msg = dbus_message_new_method_call(s->info->name,
					   s->session_path,
					   s->info->session_iface,
					   "TakeDevice");
	if (!msg)
		return -ENOMEM;

	if (!dbus_message_append_args(msg,
				      DBUS_TYPE_UINT32, &maj,
				      DBUS_TYPE_UINT32, &min,
				      DBUS_TYPE_INVALID)) {
		dbus_message_unref(msg);
		return -ENOMEM;
	}

	/*
	 * The libinput API doesn't allow us to do this asynchronously.
	 * TODO: Investigate changing libinput to allow for this.
	 */

	reply = dbus_connection_send_with_reply_and_block(s->dbus, msg, -1, &err);
	dbus_message_unref(msg);

	if (!reply) {
		wlxi_err(wlx, "%s: %s", err.name, err.message);
		dbus_error_free(&err);
		return -1;
	}

	if (!dbus_message_has_signature(reply, "hb")) {
		wlxi_err(wlx, "Signature mismatch: expected \"hb\", got \"%s\"",
			 dbus_message_get_signature(reply));
		dbus_message_unref(reply);
		return -1;
	}

	dbus_message_get_args(reply, NULL,
			      DBUS_TYPE_UNIX_FD, &fd,
			      DBUS_TYPE_BOOLEAN, &active,
			      DBUS_TYPE_INVALID);
	dbus_message_unref(reply);
	/* fd is dup()ed by libdbus, and also guarantees CLOEXEC */

	/*
	 * Due to the way EVIOCREVOKE works, an inactive device here would be
	 * useless, but doesn't break anything.
	 */
	if (!active)
		wlxi_warn(wlx, "Input device received, but is inactive");

	fd_flags = fcntl(fd, F_GETFD);
	if ((fd_flags & flags) != flags) {
		if (fcntl(fd, F_SETFD, fd_flags | flags) != -1) {
			wlxi_err(wlx, "fcntl failed: %s", strerror(errno));
			close(fd);
			return -errno;
		}
	}

	return fd;
}

static void
wlxi_libinput_close_restricted(int fd, void *userdata)
{
	struct wlxi_tty_session *s = userdata;
	struct wlx *wlx = s->base.wlx;
	struct stat st;
	DBusMessage *msg;
	dbus_uint32_t maj, min;

	if (fstat(fd, &st) == -1) {
		wlxi_err(wlx, "Failed to fstat device: %s", strerror(errno));
		close(fd);
		return;
	}

	/* We don't need this at any point past here */
	close(fd);

	maj = major(st.st_rdev);
	min = minor(st.st_rdev);

	msg = dbus_message_new_method_call(s->info->name,
					   s->session_path,
					   s->info->session_iface,
					   "ReleaseDevice");
	if (!msg)
		return;

	if (!dbus_message_append_args(msg,
				      DBUS_TYPE_UINT32, &maj,
				      DBUS_TYPE_UINT32, &min,
				      DBUS_TYPE_INVALID)) {
		dbus_message_unref(msg);
		return;
	}

	/*
	 * We don't care about the reply or any possible error that will happen
	 * here. It's not like we could do anything with it anyway.
	 */
	dbus_connection_send(s->dbus, msg, NULL);
	dbus_message_unref(msg);
}

static const struct libinput_interface wlxi_libinput_iface = {
	.open_restricted = wlxi_libinput_open_restricted,
	.close_restricted = wlxi_libinput_close_restricted,
};

/*
 * We use logind/consolekit2 as a session manager, which takes cares of opening
 * priviledged resources for us. This all over happens over DBus, and the code
 * is written to be as async as possible. It leads to it being pretty callback
 * heavy and doesn't have an obvious flow, so I'll give a brief overview of
 * the steps we take here:
 *
 * 1. Call "ListNames" to see if logind/consolekit2 exists (and which one).
 * 2. Call "GetSession" to get which session we're in.
 * 3.a Call "GetAll" properties on session to get seat we're on.
 * 3.b Call "TakeControl" to become the session controller
 * 4. Notify user of completion
 * 5. Enumerate DRM devices and start libinput to start sending the user
 *    new device events
 */
int
wlx_session_create_tty(struct wlx *wlx,
		       const char *session_id,
		       struct wlx_session **session_out,
		       wlx_session_create_fn create)
{
	struct wlxi_tty_session *s;
	DBusError err = DBUS_ERROR_INIT;
	int res;

	*session_out = NULL;

	s = wlxi_alloc(wlx, sizeof *s);
	if (!s)
		return WLX_RESULT_OOM;
	wlxi_session_init_base(&s->base, wlx, WLX_SESSION_TYPE_WAYLAND, create);

	/*
	 * Not going to use this immediately and can't gurantee the caller
	 * will keep it valid, so we have to strdup it.
	 */
	if (session_id) {
		s->session_id = strdup(session_id);
		if (!s->session_id) {
			res = WLX_RESULT_OOM;
			goto err_free;
		}
	}

	s->dbus = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
	if (dbus_error_is_set(&err)) {
		wlxi_err(wlx, "Failed to open system DBus: %s", err.message);
		res = wlxi_res_from_dbus(&err);
		goto err_free;
	}

	dbus_connection_set_exit_on_disconnect(s->dbus, false);

	dbus_connection_set_dispatch_status_function(s->dbus,
						     wlxi_dbus_dispatch_status,
						     s, NULL);

	if (!dbus_connection_set_watch_functions(s->dbus,
						 wlxi_dbus_add_watch,
						 wlxi_dbus_remove_watch,
						 wlxi_dbus_toggle_watch,
						 s, NULL)) {
		res = WLX_RESULT_OOM;
		goto err_dbus;
	}

	if (!dbus_connection_set_timeout_functions(s->dbus,
						   wlxi_dbus_add_timeout,
						   wlxi_dbus_remove_timeout,
						   wlxi_dbus_toggle_timeout,
						   s, NULL)) {
		res = WLX_RESULT_OOM;
		goto err_dbus;
	}

	if (!dbus_connection_add_filter(s->dbus, wlxi_dbus_filter, s, NULL)) {
		res = WLX_RESULT_OOM;
		goto err_dbus;
	}

	res = wlxi_dbus_call_with_reply(s, wlxi_dbus_recv_list_names,
					"org.freedesktop.DBus",
					"/org/freedesktop/DBus",
					"org.freedesktop.DBus",
					"ListNames",
					DBUS_TYPE_INVALID);
	if (res < 0)
		goto err_dbus;

	s->udev = udev_new();
	if (!s->udev) {
		res = wlxi_res_from_errno(errno);
		wlxi_err(wlx, "Could not create udev context: %s",
			 strerror(errno));
		goto err_dbus;
	}

	/*
	 * Both the udev monitor and the libinput context will be started in a
	 * deactivated state and not produce any events, and will not be
	 * started until later, once we've become the session controller.
	 *
	 * We may as well get all of the early initialization out of the way
	 * now though, so we can return errors from them earlier.
	 */

	s->monitor = udev_monitor_new_from_netlink(s->udev, "udev");
	if (!s->monitor) {
		res = wlxi_res_from_errno(errno);
		wlxi_err(wlx, "Could not create udev monitor: %s",
			 strerror(errno));
		goto err_udev;
	}

	res = udev_monitor_filter_add_match_subsystem_devtype(s->monitor,
							      "drm", "drm_minor");
	if (res < 0) {
		wlxi_err(wlx, "Could not add udev filter: %s",
			 strerror(-res));
		res = wlxi_res_from_errno(-res);
		goto err_monitor;
	}

	res = wlxi_ev_source_init_fd(wlx, &s->monitor_fd,
				     wlxi_udev_event,
				     s,
				     udev_monitor_get_fd(s->monitor),
				     POLLIN);
	if (res < 0) {
		wlxi_err(wlx, "Could not create udev event source");
		goto err_monitor;
	}

	s->libinput = libinput_udev_create_context(&wlxi_libinput_iface,
						   s, s->udev);
	if (!s->libinput) {
		wlxi_err(wlx, "Could not create libinput context");
		res = WLX_RESULT_FAILURE; /* libinput doesn't give any reason */
		goto err_monitor_fd;
	}

	res = wlxi_ev_source_init_fd(wlx, &s->libinput_fd,
				     wlxi_libinput_event,
				     s,
				     libinput_get_fd(s->libinput),
				     POLLIN);
	if (res < 0) {
		wlxi_err(wlx, "Could not create libinput event source");
		goto err_libinput;
	}

	*session_out = &s->base;
	return WLX_RESULT_SUCCESS;

err_libinput:
	libinput_unref(s->libinput);
err_monitor_fd:
	wlxi_ev_source_fd_remove(wlx, &s->monitor_fd);
err_monitor:
	udev_monitor_unref(s->monitor);
err_udev:
	udev_unref(s->udev);
err_dbus:
	dbus_connection_unref(s->dbus);
err_free:
	free(s->session_id);
	free(s);
	return res;
}
