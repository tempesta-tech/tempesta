/**
 *		Tempesta DB
 *
 * Copyright (C) 2015 Tempesta Technologies.
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
#ifndef __EXTENT_H__
#define __EXTENT_H__

#define TDB_EXT_BITS		21
#define TDB_EXT_SZ		(1UL << TDB_EXT_BITS)
#define TDB_EXT_MASK		(~(TDB_EXT_SZ - 1))

#endif /* __EXTENT_H__ */
