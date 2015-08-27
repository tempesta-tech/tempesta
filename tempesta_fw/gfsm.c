/**
 *		Tempesta FW
 *
 * Generic Finite State Machine (GFSM).
 *
 * GFSM is a generic extension of hooks for traditional HTTP processing phases.
 * The basic concept is that there are number of processing FSMs (HTTP, ICAP,
 * some other module processing etc.) which can switch between each other
 * savin current FSM state in states stack.
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
#include "gfsm.h"
#include "log.h"

#define TFW_GFSM_STATE_ST(s)	(TFW_GFSM_STATE(s) & TFW_GFSM_STATE_MASK)
#define TFW_GFSM_FSM(s)		(TFW_GFSM_STATE(s) >> TFW_GFSM_FSM_SHIFT)
#define TFW_GFSM_HOOK_N		(TFW_GFSM_PRIO_N * TFW_GFSM_STATE_N)

typedef struct {
	int 		st0;
	unsigned short	fsm_id;
} TfwFsmHook;

/* Table of FSM handlers. */
static tfw_gfsm_handler_t fsm_htbl[TFW_FSM_NUM] __read_mostly;
/* Table of registered hook callbacks. */
static TfwFsmHook fsm_hooks[TFW_FSM_NUM][TFW_GFSM_HOOK_N] __read_mostly;
/*
 * Table of bitmaps for set hooks.
 * For each FSM there are 16 priorities by 32 states, see gfsm.h.
 */
static unsigned int fsm_hooks_bm[TFW_FSM_NUM][TFW_GFSM_WC_BMAP_SZ];

/**
 * The function must be called by first FSM processing @obj or
 * independent code, such that alls FSMs can use it for dispatching.
 */
void
tfw_gfsm_state_init(TfwGState *st, void *obj, int st0)
{
	st->st_p = 0;
	st->obj = obj;
	TFW_GFSM_STATE(st) = st0;
}

/**
 * Context switch from current FSM @fsm_id_curr at state @state.
 * This function is responsible for all context storing/restoring logic.
 * tfw_gfsm_pop_ctx() moves up on the context state reverting current FSM
 * context.
 */
static void
tfw_gfsm_switch(TfwGState *st, int fsm_id_curr, int state, int prio)
{
	int shift = prio * TFW_GFSM_PRIO_N + (state & TFW_GFSM_STATE_MASK);
	int fsm_id_next = fsm_hooks[TFW_GFSM_FSM(st)][shift].fsm_id;
	SsProto *proto = (SsProto *)st->obj;

	if (unlikely(st->st_p + 1 >= TFW_GFSM_STACK_DEPTH)) {
		TFW_WARN("Too deep gfsm call, can't run hooks\n");
		return;
	}

	/* Remember current FSM context. */
	st->fsm_id[st->st_p] = proto->type;
	TFW_GFSM_STATE(st) = state; /* @fsm_id_curr will continue from here. */

	/* Push down clear state for next FSM. */
	++st->st_p;
	TFW_GFSM_STATE(st) = fsm_hooks[fsm_id_curr][shift].st0;
	st->fsm_id[st->st_p] = fsm_id_next;

	/*
	 * The new FSM starts with connection type which it declared
	 * as enter sate argument of tfw_gfsm_register_hook().
	 */
	proto->type = fsm_id_next;
}

/**
 * Pop context of just called FSM from contexts stack if it finishes.
 */
static void
tfw_gfsm_pop_ctx(TfwGState *st)
{
	SsProto *proto = (SsProto *)st->obj;

	if (TFW_GFSM_STATE_ST(st) != TFW_GFSM_STATE_LAST)
		return;

	--st->st_p;
	BUG_ON(st->st_p < 0);

	proto->type = st->fsm_id[st->st_p];
}

/**
 * Dispatch connection data to proper FSM.
 */
int
tfw_gfsm_dispatch(void *obj, struct sk_buff *skb, unsigned int off)
{
	SsProto *proto = (SsProto *)obj;

	return fsm_htbl[TFW_FSM_TYPE(proto->type)](obj, skb, off);
}

/**
 * Move the FSM to new state @state and call all registered hooks for it.
 *
 * Iterates over all priorities for current state of top (current) FSM and
 * switch to the registered FSMs.
 *
 * Currently there is TFW_GFSM_WC_BMAP_SZ priorities (and each priority
 * has 32-bit states bitmap), so we use this fact to speedup the iteration.
 */
int
tfw_gfsm_move(TfwGState *st, unsigned short state, struct sk_buff *skb,
	      unsigned int off)
{
	int r = TFW_PASS, p;
	int fsm_id_curr = TFW_GFSM_FSM(st);
	unsigned int *hooks = fsm_hooks_bm[TFW_GFSM_FSM(st)];
	unsigned long mask = 1 << state;

	/* Start from higest priority. */
	for (p = TFW_GFSM_HOOK_PRIORITY_HIGH;
	     p < TFW_GFSM_HOOK_PRIORITY_NUM; ++p)
	{
		/* The bitmask is likely spread. */
		if (likely(!(hooks[p] & mask)))
			continue;
	
		/* Switch context to other FSM. */
		tfw_gfsm_switch(st, fsm_id_curr, state, p);

		/*
		 * Let the FSM do all its jobs.
		 * There is possible recursion when the new FSM moves through
		 * its states.
		 */
		r = tfw_gfsm_dispatch(st->obj, skb, off);

		/*
		 * XXX Should we continue processing for lower priorities
		 * if current FSM is still in progress?
		 */
		tfw_gfsm_pop_ctx(st);

		if (r == TFW_BLOCK)
			break;
	}

	TFW_GFSM_STATE(st) = state;

	return r;
}
EXPORT_SYMBOL(tfw_gfsm_move);

/**
 * Register a hook which will be called with priority @prio when FSM @fsm_id
 * reaches state @state. The hooks switches calling FSM to FSM represented by
 * @hndl_fsm_id at state @st0.
 *
 * TODO currently we don't have unregister hook logic, so any module using GFSM
 * hooks can't be unloaded for now. The problem is that there could be some
 * live messages with set hooks when a module is unloaded, so we need to scan
 * and adjust all the messages.
 */
int
tfw_gfsm_register_hook(int fsm_id, int prio, int state,
		       unsigned short hndl_fsm_id, int st0)
{
	int shift, st = state & TFW_GFSM_STATE_MASK;
	unsigned int st_bit = 1 << st;

	/* Initial FSM state isn't hookable. */
	BUG_ON(!st);

	if (prio == TFW_GFSM_HOOK_PRIORITY_ANY) {
		/*
		 * Try to register the hook with higest priority.
		 * If the state slot for the priority is already acquired,
		 * then try lower priority.
		 */
		for (prio = TFW_GFSM_HOOK_PRIORITY_HIGH;
		     prio < TFW_GFSM_HOOK_PRIORITY_NUM; ++prio)
			if (!(fsm_hooks_bm[fsm_id][prio] & st_bit))
				break;
		if (prio == TFW_GFSM_HOOK_PRIORITY_NUM) {
			TFW_ERR("All hook slots for FSM %d are acquired\n",
				fsm_id);
			return -EBUSY;
		}
	}
	shift = prio * TFW_GFSM_PRIO_N + st;

	if (fsm_hooks[fsm_id][shift].fsm_id)
		return -EBUSY;
	if (!fsm_htbl[fsm_id]) {
		TFW_ERR("gfsm: fsm %d is not registered\n", fsm_id);
		return -ENOENT;
	}

	fsm_hooks[fsm_id][shift].st0 = st0;
	fsm_hooks[fsm_id][shift].fsm_id = hndl_fsm_id;
	fsm_hooks_bm[fsm_id][prio] |= st_bit;

	return 0;
}
EXPORT_SYMBOL(tfw_gfsm_register_hook);

int
tfw_gfsm_register_fsm(int fsm_id, tfw_gfsm_handler_t handler)
{
	if (fsm_htbl[fsm_id])
		return -EBUSY;

	fsm_htbl[fsm_id] = handler;

	return 0;
}
EXPORT_SYMBOL(tfw_gfsm_register_fsm);

void
tfw_gfsm_unregister_fsm(int fsm_id)
{
	BUG_ON(!fsm_htbl[fsm_id]);

	fsm_htbl[fsm_id] = NULL;
}
EXPORT_SYMBOL(tfw_gfsm_unregister_fsm);
