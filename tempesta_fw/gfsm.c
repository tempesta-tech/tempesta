/**
 *		Tempesta FW
 *
 * Generic Finite State Machine (GFSM).
 *
 * GFSM is a replacement for traditional HTTP processing phases to build
 * arbitrary graph of traffic processing modules. The basic concept is that
 * there are number of processing FSMs, such as:
 *   - HTTP, TLS, ICAP, and other network protocol processing state machines;
 *   - security rules enforcement modules and traffic classifiers;
 *   - loadable TL programs;
 *   - user-space modules such as FastCGI or REST.
 *
 * The FSMs are essentially subroutines in sense of Knuth definition of
 * coroutines, i.e. a subroutine can:
 *   1. call other subroutine;
 *   2. yield control to other subroutine.
 *
 * GFSM is a voluntary (co-operative) data-driven scheduler for the subroutines.
 * While traditional preemptive (time-sharing) scheduler cares about fair time
 * slice sharing among processes, GFSM cares about processing hot (in sense of
 * CPU caches) data by all subroutines, who, and only who, are interested in
 * the data. I.e. when a packet arrives, all subroutines interested in
 * processing the packet are called immediately while the packet data resides
 * in CPU caches. A data is considered interesting for a subroutine if the
 * subroutine subscribed (hooked) for the states of other FSM or a network
 * packet reception (tfw_gfsm_dispatch()).
 *
 * Subroutines are registered in GFSM in order according to their priorities.
 * A subroutine registering as well as unregistering can be done in run-time
 * (crucial for TL loadable programs). A subroutine (especially security
 * enforcement) can stop current data processing by blocking return code, so
 * all subroutines with lower priorities won't see the data.
 *
 * GFSM example for simplified HTTP/ICAP interoperability:
 *   1. softirq1 receives HTTP request and calls GFSM to switch to ICAP FSM;
 *   2. ICAP FSM sends the request to ICAP server in the same softirq1.
 *      softirq1 forgets about the request and goes to process other packets.
 *      However, current HTTP FSM state must be saved, so it can continue to
 *      process the request later;
 *   3. softirq2 receives response from ICAP server and calls GFSM to switch
 *      to HTTP FSM back;
 *   4. HTTP continues to process the request: cache it, forward it to
 *      an upstream etc.
 *
 * Tempesta FW receives control on TCP socket callbacks, so GFSM subroutines
 * works at L4-L7. While L3 data is available for the subroutines, pure L3
 * logic should be processed using nftables and/or eBPF to get more
 * performance.
 *
 * GFSM stores FSM states in an array w/ free organisation to allow graph-like
 * FSM switching scheme. The entry point to GFSM is defined by current
 * connection type and the next GFSM transitions by registered FSM hooks for
 * currently running FSM.
 *
 * A subroutine yields it's control flow by moving to the next state using
 * tfw_gfsm_move().
 *
 * Copyright (C) 2014 NatSys Lab. (info@natsys-lab.com).
 * Copyright (C) 2015-2018 Tempesta Technologies, Inc.
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
#define __GFSM_PRIO(_s)		(((_s) >> TFW_GFSM_PRIO_SHIFT)	\
				 & TFW_GFSM_PRIO_MASK)
#define PRIO(s)			__GFSM_PRIO(FSM_STATE(s))
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
 * independent code, such that all FSMs can use it for dispatching.
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
	int fsm_curr = state >> TFW_GFSM_FSM_SHIFT;
	int fsm_next = fsm_hooks[fsm_curr][shift].fsm_id;
	int free_slot;

	st->curr = __gfsm_fsm_lookup(st, fsm_next, &free_slot);
	if (st->curr < 0) {
		/* Create new clear state for the next FSM. */
		BUG_ON(free_slot < 0);
		st->curr = free_slot;
		FSM_STATE(st) = fsm_hooks[fsm_curr][shift].st0;
	}

	TFW_DBG3("GFSM switch from fsm %d at state %d to fsm %d at state %#x\n",
		 fsm_curr, state, fsm_next, TFW_GFSM_STATE(st));

	return fsm_next;
}

/**
 * TODO #77 (User-kernel space transport): user-space processing is an
 * asynchronous operation which can be called at different states of different
 * FSMs, so GFSM must introduce STEAL logic:
 *   1. an FSM (responsible for user-space message mapping) can return
 *      TFW_STEAL;
 *   2. getting the return code from gfsm_move() current FSM must finish
 *      the message processing logic and return with stored current state;
 *   3. when a user-space program finish GFSM must unwind the call stack and
 *      call the original FSM at the same state, so it can finish the message
 *      processing.
 */
static int
__gfsm_fsm_exec(TfwGState *st, int fsm_id, const TfwFsmData *data)
{
	int r, slot, dummy;

	st->curr = slot = __gfsm_fsm_lookup(st, fsm_id, &dummy);
	BUG_ON(st->curr < 0);

	FSM_STATE(st) |= TFW_GFSM_ONSTACK;

	TFW_DBG3("GFSM exec fsm %d, state %#x\n", fsm_id, st->states[slot]);

	r = fsm_htbl[fsm_id](st->obj, data);

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
tfw_gfsm_dispatch(TfwGState *st, void *obj, const TfwFsmData *data)
{
	int fsm_id = TFW_FSM_TYPE(((SsProto *)obj)->type);

	return __gfsm_fsm_exec(st, fsm_id, data);
}

/**
 * Move the FSM with descriptor @st to new the state @state and call all
 * registered hooks for it.
 *
 * Iterates over all priorities for current state of top (current) FSM and
 * switch to the registered FSMs.
 *
 * Currently there is TFW_GFSM_WC_BMAP_SZ priorities (and each priority
 * has 32-bit states bitmap), so we use this fact to speedup the iteration.
 */
int
tfw_gfsm_move(TfwGState *st, unsigned short state, const TfwFsmData *data)
{
	int r = TFW_PASS, p, fsm;
	unsigned int *hooks = fsm_hooks_bm[FSM(st)];
	unsigned long mask = 1 << state;
	unsigned char curr_st = st->curr;

	TFW_DBG3("GFSM move from %#x to %#x\n", FSM_STATE(st), state);

	/* Remember current FSM context. */
	SET_STATE(st, state);

	/* Start from highest priority. */
	for (p = TFW_GFSM_HOOK_PRIORITY_HIGH;
	     p < TFW_GFSM_HOOK_PRIORITY_NUM; ++p)
	{
		/*
		 * TODO Handle different priorities by ordering the hooks,
		 * rather than fixed priority levels to avoid spinning in vain.
		 */
		if (!(hooks[p] & mask))
			goto done;

		/* Switch context to other FSM. */
		fsm = tfw_gfsm_switch(st, state, p);

		/*
		 * Don't execute FSM handler who executed us,
		 * the FSM will just continue it's processing when all other
		 * executed FSMs exit.
		 */
		if (FSM_STATE(st) & TFW_GFSM_ONSTACK)
			continue;

		switch (__gfsm_fsm_exec(st, fsm, data)) {
		case TFW_BLOCK:
			r = TFW_BLOCK;
			goto done;
		case TFW_POSTPONE:
			/*
			 * Postpone processing if at least one FSM
			 * needs more data.
			 */
			r = TFW_POSTPONE;
		}
	}
done:
	/* Restore current FSM context. */
	st->curr = curr_st;

	return r;
}
EXPORT_SYMBOL(tfw_gfsm_move);

#ifdef DEBUG
/**
 * Helper function to debug current fsm state.
 */
void
tfw_gfsm_debug_state(TfwGState *st, const char *msg)
{
	TFW_DBG("%s: curr=%d:  on_stack=%d fsm_id=%d prio=%d state=%d",
		msg, st->curr, !!(FSM_STATE(st) & TFW_GFSM_ONSTACK), FSM(st),
		PRIO(st), TFW_GFSM_STATE(st));
}
EXPORT_SYMBOL(tfw_gfsm_debug_state);
#endif

/**
 * Register a hook which will be called with priority @prio when FSM @fsm_id
 * reaches state @state. The hooks switches calling FSM to FSM represented by
 * @hndl_fsm_id at state @st0.
 * @return resulting priority at which the hook was registered or
 * negative value of failure.
 *
 * TODO #102 (TL) run-time FSM registration & unregistration, see concept.tl
 * for the discussion.
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
		 * Try to register the hook with highest priority.
		 * If the state slot for the priority is already acquired,
		 * then try lower priority.
		 */
		for (prio = TFW_GFSM_HOOK_PRIORITY_HIGH;
		     prio < TFW_GFSM_HOOK_PRIORITY_NUM; ++prio)
			if (!(fsm_hooks_bm[fsm_id][prio] & st_bit))
				break;
		if (prio == TFW_GFSM_HOOK_PRIORITY_NUM) {
			TFW_ERR_NL("All hook slots for FSM %d are acquired\n",
				   fsm_id);
			return -EBUSY;
		}
	}
	shift = prio * TFW_GFSM_PRIO_N + st;

	if (fsm_hooks[fsm_id][shift].fsm_id)
		return -EBUSY;
	if (!fsm_htbl[fsm_id]) {
		TFW_ERR_NL("gfsm: fsm %d is not registered\n", fsm_id);
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
