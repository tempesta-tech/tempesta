/**
 *		Tempesta FW
 *
 * Generic functions and macros that don't have enough cohesion for moving
 * into separate library units.
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
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
#ifndef __TFW_LIB_MISC_H__
#define __TFW_LIB_MISC_H__

/**
 * An enum whose size is reduced to a minimum possible value.
 *
 * Usage:
 *  typedef packedenum {
 *          FOO = 0,
 *          BAR = 255,
 *  } one_byte_enum;
 *
 *  typedef packedenum {
 *          FOO = 0,
 *          BAR = 256,
 *  } two_byte_enum;
 */
#ifndef packedenum
#define packedenum  enum __attribute__((packed))
#endif

/**
 * Define C struct without member padding.
 *
 * Usage:
 *  typedef packedstruct {
 *          u8  field1;
 *          u16 field2;
 *          u8  field3;
 *  } MyFourByteStruct;
 */
#ifndef packedstruct
#define packedstruct struct __attribute__((packed))
#endif

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


#endif /* __TFW_LIB_MISC_H__ */
