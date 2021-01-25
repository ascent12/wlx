/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef UTIL_STRING_H
#define UTIL_STRING_H

#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>

#include <wlx/result.h>

/*
 * POSIX and ISO C provide serveral typedefs of integer types for various
 * reasons, and often the requirements for them are quite loose, often without
 * sizes or even signedness. This makes having to parse these from strings
 * "safely" and portably a little tricky, but we can use _Generic to get around
 * this by automatically bringing everything back in terms of fundamental
 * types.
 *
 * This function is quite strict about the string it accepts; there mustn't
 * be any leading or trailing characters. 'res' is not modified if the function
 * fails.
 */
#define wlxi_strtoi(str, res) _Generic((res), \
	/* Don't forget that 'char' and 'signed char' are different types in C */ \
	char *: wlxi_strtoi_CHAR, \
	signed char *: wlxi_strtoi_SCHAR, \
	unsigned char *: wlxi_strtoi_UCHAR, \
	short *: wlxi_strtoi_SHRT, \
	unsigned short *: wlxi_strtoi_USHRT, \
	int *: wlxi_strtoi_INT, \
	unsigned int *: wlxi_strtoi_UINT, \
	long *: wlxi_strtoi_LONG, \
	unsigned long *: wlxi_strtoi_ULONG, \
	long long *: wlxi_strtoi_LLONG, \
	unsigned long long* : wlxi_strtoi_ULLONG)((str), (res))

/*
 * Yes I know this whole next section looks disgusting.
 * It's just generating the functions for above.
 */

#define WLXI_DEF_STRTOI_BASE(name, type, lt, gt, fn_ret, fn) \
static inline int \
wlxi_strtoi_##name(const char *str, type *res) \
{ \
	char *endptr; \
	if (!isdigit(str[0]) && str[0] != '-') \
		return WLX_RESULT_INVALID; \
	errno = 0; \
	fn_ret n = fn(str, &endptr, 10); \
	if (errno || endptr == str || *endptr != '\0') \
		return WLX_RESULT_INVALID; \
	if (lt(name, n) || gt(name, n)) \
		return WLX_RESULT_INVALID; \
	*res = n; \
	return WLX_RESULT_SUCCESS; \
}

#define WLXI_ZERO(name, n) (0)
#define WLXI_LT_MIN(name, n) ((n) < name##_MIN)
#define WLXI_GT_MAX(name, n) ((n) > name##_MAX)

#define WLXI_DEF_STRTOI_SMALL_S(name, type) \
	WLXI_DEF_STRTOI_BASE(name, type, WLXI_LT_MIN, WLXI_GT_MAX, long, strtol)

#define WLXI_DEF_STRTOI_SMALL_U(name, type) \
	WLXI_DEF_STRTOI_BASE(name, type, WLXI_ZERO, WLXI_GT_MAX, unsigned long, strtoul)

#define WLXI_DEF_STRTOI_BASIC(name, type, fn) \
	WLXI_DEF_STRTOI_BASE(name, type, WLXI_ZERO, WLXI_ZERO, type, fn)

#if CHAR_MIN == 0
WLXI_DEF_STRTOI_SMALL_U(CHAR, char)
#else
WLXI_DEF_STRTOI_SMALL_S(CHAR, char)
#endif
WLXI_DEF_STRTOI_SMALL_S(SCHAR, signed char)
WLXI_DEF_STRTOI_SMALL_U(UCHAR, unsigned char)
WLXI_DEF_STRTOI_SMALL_S(SHRT, short)
WLXI_DEF_STRTOI_SMALL_U(USHRT, unsigned short)
WLXI_DEF_STRTOI_SMALL_S(INT, int)
WLXI_DEF_STRTOI_SMALL_U(UINT, unsigned int)
WLXI_DEF_STRTOI_BASIC(LONG, long, strtol)
WLXI_DEF_STRTOI_BASIC(ULONG, unsigned long, strtol)
WLXI_DEF_STRTOI_BASIC(LLONG, long long, strtoll)
WLXI_DEF_STRTOI_BASIC(ULLONG, unsigned long long, strtoull)

/* We don't need these anymore */
#undef WLXI_DEF_STRTOI_BASE
#undef WLXI_DEF_STRTOI_SMALL_S
#undef WLXI_DEF_STRTOI_SMALL_U
#undef WLXI_DEF_STRTOI_BASIC
#undef WLXI_ZERO
#undef WLXI_LT_MIN
#undef WLXI_LT_MAX

#endif
