/**
 *		Tempesta FW
 *
 * Generic Finite State Machine (GFSM).
 *
 * GFSM is a generic extension of hooks for traditional HTTP processing phases.
 * The basic concept is that there are number of processing FSMs (HTTP, ICAP,
 * some other module processing etc.) which can switch between each other
 * saving current FSM state in states stack.
 *
 * GFSM example for simplified HTTP/ICAP interoperability:
 * 1. softirq1 receives HTTP request and calls GFSM to switch to ICAP FSM;
 * 2. ICAP FSM sends the request to ICAP server in the same softirq1.
 *    softirq1 forgets about the request and goes to process other packets.
 *    However, current HTTP FSM state must be saved, so it can continue to
 *    process the request later;
 * 3. softirq2 receives response from ICAP server and calls GFSM to switch
 *    to HTTP FSM back;
 * 4. HTTP continues to process the request: cache it, forward it to
 *    an upstream etc.
 *
 * GFSM stores FSM states in an array w/ free organisation to allow graph-like
 * FSM switching scheme. The entry point to GFSM is defined by current
 * connection type and the next GFSM trasitions by registered FSM hooks for
 * currently running FSM.
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
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

#define FSM_STATE(s)		(s)->states[(unsigned char)(s)->curr]
#define __GFSM_FSM(_s)		(((_s) >> TFW_GFSM_FSM_SHIFT)	\
				 & TFW_GFSM_FSM_MASK)
#define FSM(s)			__GFSM_FSM(FSM_STATE(s))
#define GFSM_HOOK_N		(TFW_GFSM_PRIO_N * TFW_GFSM_STATE_N)
#define SET_STATE(s, x)						\
do {								\
	FSM_STATE(s) = (FSM_STATE(s) & ~TFW_GFSM_STATE_MASK) | (x); \
} while (0)

#define __BAD_STATE_BYTE	0xff
#define BAD_STATE		((__BAD_STATE_BYTE << 8) | __BAD_STATE_BYTE)

typedef struct {
	int 		st0;
	unsigned short	fsm_id;
} TfwFsmHook;

/* Table of FSM handlers. */
static tfw_gfsm_handler_t fsm_htbl[TFW_FSM_NUM] __read_mostly;
/* Table of registered hook callbacks. */
static TfwFsmHook fsm_hooks[TFW_FSM_NUM][GFSM_HOOK_N] __read_mostly;
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
	st->obj = obj;
	memset(st->states, __BAD_STATE_BYTE, sizeof(st->states));
	FSM_STATE(st) = st0;
}

/**
 * Lookup next FSM in stored states.
 */
static int
__gfsm_fsm_lookup(TfwGState *st, int fsm_id, int *free_slot)
{
	int i;
	for (i = 0, *free_slot = -1; i < TFW_GFSM_FSM_NUM; ++i) {
		if (__GFSM_FSM(st->states[i]) == fsm_id)
			return i;
		if (*free_slot == -1 && st->states[i] == BAD_STATE)
			*free_slot = i;
	}
	return -1;
}

/**
 * Context switch from current FSM at state @state to next FSM.
 */
static int
tfw_gfsm_switch(TfwGState *st, int state, int prio)
{
	int shift = prio * TFW_GFSM_PRIO_N + (state & TFW_GFSM_STATE_MASK);
	int fsm_next = fsm_hooks[FSM(st)][shift].fsm_id;
	int fsm_curr = state >> TFW_GFSM_FSM_SHIFT;
	int free_slot;

	TFW_DBG3("GFSM switch from fsm %d at state %d to fsm %d at state %#x\n",
		 fsm_curr, state, fsm_next, fsm_hooks[fsm_curr][shift].st0);

	st->curr = __gfsm_fsm_lookup(st, fsm_next, &free_slot);
	if (st->curr < 0) {
		/* Create new clear state for the next FSM. */
		BUG_ON(free_slot < 0);
		st->curr = free_slot;
		FSM_STATE(st) = fsm_hooks[fsm_curr][shift].st0;
	}

	return fsm_next;
}

static int
__gfsm_fsm_exec(TfwGState *st, int fsm_id, struct sk_buff *skb,
		unsigned int off)
{
	int r, slot, dummy;

	st->curr = slot = __gfsm_fsm_lookup(st, fsm_id, &dummy);
	BUG_ON(st->curr < 0);

	FSM_STATE(st) |= TFW_GFSM_ONSTACK;

	TFW_DBG3("GFSM exec fsm %d, state %#x\n", fsm_id, st->states[slot]);

	r = fsm_htbl[fsm_id](st->obj, skb, off);

	/* If current FSM finishes, remove its state. */
	if ((st->states[slot] & TFW_GFSM_STATE_MASK) == TFW_GFSM_STATE_LAST) {
		FSM_STATE(st) = BAD_STATE;
		st->curr = -1;
	} else {
		st->states[slot] &= ~TFW_GFSM_ONSTACK;
	}

	return r;
}

/**
 * Dispatch connection data to proper FSM by application protocol type.
 */
int
tfw_gfsm_dispatch(TfwGState *st, void *obj, struct sk_buff *skb,
		  unsigned int off)
{
	int fsm_id = TFW_FSM_TYPE(((SsProto *)obj)->type);

	return __gfsm_fsm_exec(st, fsm_id, skb, off);
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
	int r = TFW_PASS, p, fsm;
	unsigned int *hooks = fsm_hooks_bm[FSM(st)];
	unsigned long mask = 1 << state;

	TFW_DBG3("GFSM move from %#x to %#x\n", FSM_STATE(st), state);

	/* Remember current FSM context. */
	SET_STATE(st, state);

	/* Start from higest priority. */
	for (p = TFW_GFSM_HOOK_PRIORITY_HIGH;
	     p < TFW_GFSM_HOOK_PRIORITY_NUM; ++p)
	{
		/*
		 * TODO Handle different priorities by ordering the hooks,
		 * rather than fixed priority levels to avoid spinning in vain.
		 */
		if (!(hooks[p] & mask))
			return TFW_PASS;

		/* Switch context to other FSM. */
		fsm = tfw_gfsm_switch(st, state, p);

		/*
		 * Don't execute FSM handler who executed us,
		 * the FSM will just continue it's processing when all other
		 * executed FSMs exit.
		 */
		if (FSM_STATE(st) & TFW_GFSM_ONSTACK)
			continue;

		switch (__gfsm_fsm_exec(st, fsm, skb, off)) {
		case TFW_BLOCK:
			return TFW_BLOCK;
		case TFW_POSTPONE:
			/*
			 * Postpone processing if at least one FSM
			 * needs more data.
			 */
			r = TFW_POSTPONE;
		}
	}

	return r;
}
EXPORT_SYMBOL(tfw_gfsm_move);

/**
 * Register a hook which will be called with priority @prio when FSM @fsm_id
 * reaches state @state. The hooks switches calling FSM to FSM represented by
 * @hndl_fsm_id at state @st0.
 * @return resulting priority at which the hook was registered or
 * negative value of failure.
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

	return prio;
}
EXPORT_SYMBOL(tfw_gfsm_register_hook);

/**
 * The function called must be pretty sure that there is no live messages
 * with set hooks. Typically, the function should be called on shutdown
 * phase only when all connections are already terminated with all associated
 * messages.
 */
void
tfw_gfsm_unregister_hook(int fsm_id, int prio, int state)
{
	int st = state & TFW_GFSM_STATE_MASK;
	int shift = prio * TFW_GFSM_PRIO_N + st;

	memset(&fsm_hooks[fsm_id][shift], 0, sizeof(TfwFsmHook));
	fsm_hooks_bm[fsm_id][prio] &= ~(1 << st);
}
EXPORT_SYMBOL(tfw_gfsm_unregister_hook);

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
