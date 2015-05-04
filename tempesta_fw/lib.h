/**
 *		Tempesta FW
 *
 * Generic functions and macros that don't have enough cohesion for moving
 * into separate library units.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015 Tempesta Technologies, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __TFW_LIB_H__
#define __TFW_LIB_H__

/**
 * Convert C identifier (precisely, a preprocessing token) to a string literal.
 *
 * Usage:
 *   printk("%s", STRINGIFY(foo));
 *
 * You can use STRINGIFY(func_or_var_name) instead of "func_or_var_name" to
 * facilitate various static analysis tools.
 */
#ifndef STRINGIFY
#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)
#endif

/**
 * The macro is used instead of EXPORT_SYMBOL() mostly for testing.
 * Symbols marked with this macro are not exported in a release build and thus
 * don't pollute the global symbols table.
 */
#ifdef DEBUG
#define DEBUG_EXPORT_SYMBOL(sym) EXPORT_SYMBOL(sym)
#else
#define DEBUG_EXPORT_SYMBOL(sym)
#endif

#endif /* __TFW_LIB_H__ */
