/**
 *	Tempesta kernel emulation unit testing framework.
 *
 * Copyright (C) 2020 Tempesta Technologies, Inc.
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
#ifndef __LINKAGE_H__
#define __LINKAGE_H__

#define ASM_NL		;

#define ALIGN		.align 4,0x90

#define ENTRY(name)							\
	.globl name ASM_NL						\
	ALIGN ASM_NL							\
	name:

#define END(name)							\
	.size name, .-name

#define ENDPROC(name)							\
	.type name, @function ASM_NL					\
	END(name)

#endif /* __LINKAGE_H__ */
