/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef WLX_RESULT_H
#define WLX_RESULT_H

enum {
	WLX_RESULT_SUCCESS = 0,
	WLX_RESULT_FAILURE = -1, /* Generic error without any more precise information */
	WLX_RESULT_OOM = -2, /* Out of memory */
	WLX_RESULT_INVALID = -3, /* Invalid argument */
	WLX_RESULT_NO_REMOTE = -4, /* No remote session */
};

#endif
