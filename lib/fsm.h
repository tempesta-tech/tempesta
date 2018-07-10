/**
 *		Tempesta kernel library
 *
 * Copyright (C) 2018 Tempesta Technologies, INC.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef __LIB_FSM_H__
#define __LIB_FSM_H__

#include "log.h"

#define T_FSM_INIT(st, name)						\
int __fsm_const_state = st; /* make compiler happy */			\
static const char *__fsm_name __attribute__((unused)) = name;

#define T_FSM_START(st)							\
fsm_reenter: __attribute__((unused))					\
switch(st)

#define T_FSM_STATE(st)							\
case st:								\
st: __attribute__((unused))						\
	T_DBG3("enter %s FSM at state %d(" #st ")\n", __fsm_name, st);	\
	__fsm_const_state = st; /* optimized out to constant */

#define T_FSM_EXIT()		goto __fsm_done;

/* Unconditional jump to state @st w/o additional logic and/or eating data. */
#define T_FSM_JMP(st)		goto st;

/* Goto next (saved) FSM state. */
#define T_FSM_NEXT()		goto fsm_reenter;

/*
 * Conditional (normal) FSM movement, usually eating more data and returning
 * T_POSTPONE if there is not enough data.
 */
#define T_FSM_MOVE(st, code)						\
do {									\
	do { code; } while (0);						\
	goto st;							\
} while (0)

/*
 * Exit the FSM. It's supposed to be close to the end of current function.
 * @ret		- return code variable;
 * @state	- the FSM state keeping variable;
 */
#define T_FSM_FINISH(ret, state)					\
__fsm_done: __attribute__((unused))					\
	T_DBG3("Finish %s FSM at state %d, ret=%d\n",			\
	       __fsm_name, __fsm_const_state, ret);			\
	state = __fsm_const_state;

#endif /* __LIB_FSM_H__ */
