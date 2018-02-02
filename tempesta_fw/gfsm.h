/**
 *		Tempesta FW
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
#ifndef __TFW_GFSM_H__
#define __TFW_GFSM_H__

#include "msg.h"
#include "sync_socket.h"

/*
 * Full state representation requires 14 bits:
 *
 * 	o        ffff     pppp    sssss
 *     13       12  9     8  5    4   0
 *   on stack  FSM id   priority  state
 *
 * Maximum number of different states for each FSM = (1 << 5 = 32).
 * States 0 and 31 are reserved as initial and accepting for automaton.
 *
 * TODO #102 (TL) many FSMs (user programs) can be registered and run
 * simultaneously. See concept.tl for the discussion.
 */
#define TFW_GFSM_STATE_BITS	5
#define TFW_GFSM_STATE_N	(1 << TFW_GFSM_STATE_BITS)
#define TFW_GFSM_STATE_MASK	(TFW_GFSM_STATE_N - 1)
#define TFW_GFSM_STATE_LAST	TFW_GFSM_STATE_MASK
#define TFW_FSM_STATE(s)	(s & TFW_GFSM_STATE_MASK)
/* Priorities number (1 << 4 = 16). */
#define TFW_GFSM_PRIO_BITS	4
#define TFW_GFSM_PRIO_N		(1 << TFW_GFSM_PRIO_BITS)
#define TFW_GFSM_PRIO_SHIFT	TFW_GFSM_STATE_BITS
/* Maximum number of different FSMs (1 << 4 = 16). */
#define TFW_GFSM_FSM_BITS	4
#define TFW_GFSM_FSM_N		(1 << TFW_GFSM_FSM_BITS)
#define TFW_GFSM_FSM_MASK	(TFW_GFSM_FSM_N - 1)
#define TFW_GFSM_FSM_SHIFT	(TFW_GFSM_PRIO_SHIFT + TFW_GFSM_PRIO_BITS)
/* Reentrant call (the FSM is on the call stack) flag. */
#define TFW_GFSM_ONSTACK	(1 << (TFW_GFSM_FSM_SHIFT + TFW_GFSM_FSM_BITS))
/*
 * We limit maximum number of states tracked FSMs by 8, while the maximum
 * number of FSMs are much bigger. Firstly, we should do this to avoid deep
 * calling recursion on FSMs switch. Secondly, basically only complicated
 * modules (like FastCGI or ICAP) which depends on third-party services'
 * responses require storing state for processing message - other simple modules
 * can just call one hook function and exit w/o leaving current FSM state on
 * the stack.
 */
#define TFW_GFSM_FSM_NUM	8
/*
 * Actually equal to TFW_GFSM_PRIO_N -
 * be careful, this fact is used in GFSM code.
 */
#define TFW_GFSM_WC_BMAP_SZ	(TFW_GFSM_PRIO_N * TFW_GFSM_STATE_N \
				 / (sizeof(int) * 8))

/**
 * All state machines must get their number by registering in this enum.
 *
 * L5-L7 protocols stack is just TLS carrying application protocol,
 * so the secured application protocols have designated FSMs rather than
 * build real stack. This simplifies the protocols handling, makes it faster
 * and privides more flexibility to set classification FSMs' hooks for
 * specific secured application protocol.
 */
enum {
	/* Protocols */
	TFW_FSM_HTTP,
	TFW_FSM_HTTPS,

	/* Security rules enforcement. */
	TFW_FSM_FRANG_REQ,
	TFW_FSM_FRANG_RESP,

	TFW_FSM_NUM /* Must be <= TFW_GFSM_FSM_N */
};

#define TFW_FSM_TYPE(t)		((t) & TFW_GFSM_FSM_MASK)

/*
 * Hooks of each phase can also be ordered by their priority.
 * Since the hooks are stored in fixed size array (so we can quickly determine
 * whether we have hooks for a phase), then the maximum priority is limited
 * by sizeof the array.
 */
enum {
	TFW_GFSM_HOOK_PRIORITY_HIGH	= 0,
	TFW_GFSM_HOOK_PRIORITY_NUM	= TFW_GFSM_PRIO_N,
	TFW_GFSM_HOOK_PRIORITY_LOW	= TFW_GFSM_HOOK_PRIORITY_NUM - 1,
	TFW_GFSM_HOOK_PRIORITY_ANY	= TFW_GFSM_HOOK_PRIORITY_NUM
};

/*
 * Hooks return codes.
 */
enum {
	/*
	 * Current message looks good and we can safely pass it.
	 */
	TFW_PASS	= SS_OK,

	/*
	 * The message must be blocked. Also, all packets associated with it
	 * and the client who sent the message will be prohibited from further
	 * communication with a defended server.
	 */
	TFW_BLOCK	= SS_DROP,

	/*
	 * We need more requests (or parts of a request) to make a decision.
	 * Current message must be stashed and will be sent to the destination
	 * (if it is deemed innocent) with subsequent message/packets at once.
	 */
	TFW_POSTPONE	= SS_POSTPONE,
};

/**
 * An input data for a subroutine (FSM) to process.
 *
 * Typically an FSM works solely on L4 or L7, however, in future, there could be
 * quite complex FSMs which need access to input data on all layers, e.g.
 * loadable user custom modules. Usually L4 data is provided to FSMs for
 * protocol handlers while L7 is for application layer FSMs, e.g. Frang security
 * limits enforcing module. HTTP FSM processes L4 data and creates L7 data
 * for further processing by other FSMs. So for futher extensions we handle all
 * layers data in the structure instead of using a union to keep one layer data
 * at a time.
 *
 * GFSM resides at the top of classes hirarchy, so use generic message classes.
 *
 * @skb		- currently processed skb by the TCP/IP stack;
 * @off		- data offset within the @skb;
 * @req		- a request associated with current state of an FSM;
 * @resp	- a response associated with the state;
 */
typedef struct {
	/* L4 (TCP) members. */
	struct sk_buff	*skb;
	unsigned int	off;

	/* L7 members. */
	TfwMsg		*req;
	TfwMsg		*resp;
} TfwFsmData;

/**
 * Generic FSM state representation for all running FSMs.
 * The first two members should be on the same cache line.
 *
 * The GFSM describes only states for a subroutines, which can be hookable
 * by subroutines (i.e. yield states). The states are a subset of all the
 * states of an object @obj associated with the subroutine.
 *
 * @curr	- index of current FSM in @states;
 * @obj		- an object associated with the FSM,
 *		  e.g. a connection descriptor;
 * @states	- all FSM states, i.e. the FSM states set;
 */
typedef struct {
	char		curr;
	void		*obj;
	unsigned short	states[TFW_GFSM_FSM_NUM];
} TfwGState;

#define TFW_GFSM_STATE(s)	((s)->states[(unsigned char)(s)->curr]	\
				 & ((TFW_GFSM_FSM_MASK << TFW_GFSM_FSM_SHIFT) \
				    | TFW_GFSM_STATE_MASK))

typedef int (*tfw_gfsm_handler_t)(void *obj, const TfwFsmData *data);

void tfw_gfsm_state_init(TfwGState *st, void *obj, int st0);
int tfw_gfsm_dispatch(TfwGState *st, void *obj, const TfwFsmData *data);
int tfw_gfsm_move(TfwGState *st, unsigned short state, const TfwFsmData *data);

int tfw_gfsm_register_hook(int fsm_id, int prio, int state,
			   unsigned short hndl_fsm_id, int st0);
void tfw_gfsm_unregister_hook(int fsm_id, int prio, int state);
int tfw_gfsm_register_fsm(int fsm_id, tfw_gfsm_handler_t handler);
void tfw_gfsm_unregister_fsm(int fsm_id);

#endif /* __TFW_GFSM_H__ */
