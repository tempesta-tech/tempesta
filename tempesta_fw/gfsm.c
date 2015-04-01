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
#define TFW_GFSM_WC(s)		(s)->wish_call[(s)->st_p]
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

static void
__gfsm_state_init(TfwGState *st, int st0)
{
	TFW_GFSM_STATE(st) = st0;

	/* Set hooks for the FSM. */
	memcpy(TFW_GFSM_WC(st), fsm_hooks_bm[st0 >> TFW_GFSM_FSM_SHIFT],
	       TFW_GFSM_WC_BMAP_SZ * sizeof(int));
}

void
tfw_gfsm_state_init(TfwGState *st, void *obj, int st0)
{

	st->st_p = 0;
	st->obj = obj;
	__gfsm_state_init(st, st0);
}

/**
 * Context switch between different FSMs.
 * This function is responsible for all context storing/restoring logic.
 */
static void
tfw_gfsm_switch(TfwGState *st, unsigned short new_st, int prio)
{
	int curr_fsm = TFW_GFSM_FSM(st);
	int shift = prio * TFW_GFSM_PRIO_N + new_st;
	SsProto *proto = (SsProto *)st->obj;

	if (unlikely(st->st_p + 1 >= TFW_GFSM_STACK_DEPTH)) {
		TFW_WARN("Too deep gfsm call, can't run hooks\n");
		return;
	}

	/* Remember FSM ID with whole connection type on the stack. */
	st->fsm_id[st->st_p] = proto->type;

	/* Push down clear state for next FSM. */
	++st->st_p;
	__gfsm_state_init(st, fsm_hooks[curr_fsm][shift].st0);

	/*
	 * The new FSM starts with connection type which it declared
	 * as enter sate argument of tfw_gfsm_register_hook().
	 */
	proto->type = fsm_hooks[curr_fsm][shift].fsm_id;

	/* Push the parent's st->obj to the new FSM. */
	st->obj = proto;
}

/**
 * Pop context of just called FSM from FSM contexts stack if it finishes.
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
tfw_gfsm_dispatch(void *obj, unsigned char *data, size_t len)
{
	SsProto *proto = (SsProto *)obj;

	return fsm_htbl[TFW_FSM_TYPE(proto->type)](obj, data, len);
}

/**
 * Move the FSM to new state @new_state and call all registered hooks
 * for current (just fully processed state).
 *
 * Iterates over all priorities for current state of top (current) FSM and
 * switch to the registered FSMs.
 *
 * Currently there is TFW_GFSM_WC_BMAP_SZ priorities (and each priority
 * has 32-bit states bitmap), so we use this fact to speedup the iteration.
 */
int
tfw_gfsm_move(TfwGState *st, unsigned short new_state, unsigned char *data,
	      size_t len)
{
	int r = TFW_PASS, p;
	unsigned int *wc = st->wish_call[st->st_p];
	unsigned long mask = 1 << new_state;

	/* Start from higest priority. */
	for (p = TFW_GFSM_HOOK_PRIORITY_HIGH;
	     p < TFW_GFSM_HOOK_PRIORITY_NUM; ++p)
	{
		/* The bitmask is likely spread. */
		if (likely(!(wc[p] & mask)))
			continue;
	
		/* Switch context to other FSM. */
		tfw_gfsm_switch(st, new_state, p);
		/*
		 * Let the FSM do all its jobs.
		 * There is possible recursion when the new FSM moves through
		 * its states.
		 */
		r = tfw_gfsm_dispatch(st->obj, data, len);
		/*
		 * XXX Should we continue processing for lower priorities
		 * if current FSM is still in progress?
		 */
		tfw_gfsm_pop_ctx(st);

		if (r == TFW_BLOCK)
			break;
	}

	TFW_GFSM_STATE(st) = new_state;

	return r;
}

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

	/* Initial FSM state is never hookable. */
	BUG_ON(!st);

	if (prio == TFW_GFSM_HOOK_PRIORITY_ANY) {
		/*
		 * Register hook at first free slot to reduce spinning in
		 * tfw_gfsm_move().
		 */
		int p;
		for (p = 0; p < TFW_GFSM_HOOK_PRIORITY_NUM; ++p)
			if (!fsm_hooks_bm[fsm_id][prio])
				prio = p;
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
	fsm_hooks_bm[fsm_id][prio] |= 1 << st;

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
