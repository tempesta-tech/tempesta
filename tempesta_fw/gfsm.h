/**
 *		Tempesta FW
 *
 * Copyright (C) 2012-2014 NatSys Lab. (info@natsys-lab.com).
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Since all protocol FSMs should be able to jump between states of different
 * FSMs, all the FSM states are defined here.
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

#include "sync_socket.h"

/*
 * Full state representation requires 13 bits:
 *
 * 	ffff     pppp    sssss
 *     12  9     8  5    4   0
 *     FSM id  priority  state
 *
 * Maximum number of different states for each FSM = (1 << 5 = 32).
 * States 0 and 31 are reserved as initial and accepting for automaton.
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
/*
 * We limit maximum FSM switch stack depth by 8, while the maximum number of
 * FSMs are much bigger. Firstly, we should do this to avoid deep calling
 * recursion on FSMs switch. Secondly, basically only complicated modules
 * (like FastCGI or ICAP) which depends on third-party services' responses
 * require storing state for processing message - other simple modules can
 * just call one hook function and exit w/o leaving current FSM state on
 * the stack.
 */
#define TFW_GFSM_STACK_DEPTH	8
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

	/* Request connection limiting classifier */
	TFW_FSM_RCL_REQ,
	TFW_FSM_RCL_CHUNK,

	TFW_FSM_NUM /* Must be <= TFW_GFSM_FSM_N */
};

#define TFW_FSM_TYPE(t)		((t) & TFW_GFSM_FSM_MASK)

/**
 * HTTP FSM states.
 *
 * We (as Apache HTTP Server and other Web-servers do) define several phases
 * on HTTP messgas processing. However we set the hooks also to response
 * processing (local and received from backend server) as well as to request
 * processing. We can depict the phases as following:
 *
 *	Client			Tempesta			Server
 *	~~~~~~			~~~~~~~~			~~~~~~
 *
 * 	[req]		-->	(I) (process)	-->		[req]
 *
 * 	[resp]		<--	(process) (II)	<--		[resp]
 *
 * 	[resp]		<--	(III) (process) <-+
 * 						   \
 * 						(local cache)
 *
 * So generally hooks are called on receiving client request (I), on receiving
 * server response (II) and after generation of local response (III).
 *
 * TODO generic callback note. We need to:
 * 1. store all callbacks in fixed size array to eliminate random memory access
 *    on callbacks;
 * 2. modules must register a callback only if it has work to do (not just when
 *    it's loaded into kernel).
 */
/*
 * TODO
 * -- add state CHUNK_READ and remove the too verbouse states
 * -- add modules callbacks to adjust HTTP requests and responses
 *    (e.g. adjust Cookie and rewrite headers)
 * -- Slow Request: drop connection if a request isn't finished in timeout
 */
#define TFW_GFSM_HTTP_STATE(s)	((TFW_FSM_HTTP << TFW_GFSM_FSM_SHIFT) | (s))
enum {
	/* HTTP FSM initial state, not hookable. */
	TFW_HTTP_FSM_INIT		= TFW_GFSM_HTTP_STATE(0),

	/* Called on request End-Of-Skb (EOS). */
	TFW_HTTP_FSM_REQ_CHUNK		= TFW_GFSM_HTTP_STATE(1),

	/* Whole request is read. */
	TFW_HTTP_FSM_REQ_MSG		= TFW_GFSM_HTTP_STATE(2),

	/* Called on response EOS. */
	TFW_HTTP_FSM_RESP_CHUNK		= TFW_GFSM_HTTP_STATE(3),

	/* Whole response is read. */
	TFW_HTTP_FSM_RESP_MSG		= TFW_GFSM_HTTP_STATE(4),

	/* Run just before localy generated response sending. */
	TFW_HTTP_FSM_LOCAL_RESP_FILTER	= TFW_GFSM_HTTP_STATE(5),

	TFW_HTTP_FSM_DONE	= TFW_GFSM_HTTP_STATE(TFW_GFSM_STATE_LAST)
};

/**
 * HTTPS states.
 *
 * TODO Issue #81: this is just PoC states, write the right states here.
 */
#define TFW_GFSM_HTTPS_STATE(s)	((TFW_FSM_HTTPS << TFW_GFSM_FSM_SHIFT) | (s))
enum {
	/* HTTPS FSM initial state, not hookable. */
	TFW_HTTPS_FSM_INIT		= TFW_GFSM_HTTPS_STATE(0),

	/* TODO */
	TFW_HTTPS_FSM_TODO_ISSUE_81	= TFW_GFSM_HTTPS_STATE(1),

	TFW_HTTPS_FSM_DONE	= TFW_GFSM_HTTPS_STATE(TFW_GFSM_STATE_LAST)
};

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
	 * The message must be blocked, also all the packets associated with it
	 * and the client who sent the message will be prohibited from further
	 * commpunications with defended server.
	 */
	TFW_BLOCK	= SS_DROP,

	/*
	 * We need more requests (or parts of a request) to make a decision,
	 * current message must be stashed and will be sent to the destination
	 * (if is decided as innocent) with following message/packets at once.
	 */
	TFW_POSTPONE	= SS_POSTPONE,
};

/**
 * Generic FSM state representation with all related info.
 *
 * Current FSM state is placed on top of states stack (@st_stack).
 * On FSM switch a new FSM state is pushed to the stack, so current FSM state
 * is saved and we can continue from the previous state when the new FSM
 * finishes processing. @st_p is the stack pointer - current state possition.
 *
 * @wish_call is a bitmap of states for current FSM on which there are other
 * FSMs wishing to be called. It specifies on which priority and for which
 * state of the current FSM we should lookup a hook of FSM which wishes
 * to make a call.
 */
typedef struct {
	/* The two belows should be on the same cache line. */
	unsigned char	st_p;
	void		*obj; /* object which state we track */
	unsigned short	st_stack[TFW_GFSM_STACK_DEPTH];
	unsigned short	fsm_id[TFW_GFSM_STACK_DEPTH];
	unsigned int	wish_call[TFW_GFSM_STACK_DEPTH][TFW_GFSM_WC_BMAP_SZ]
							____cacheline_aligned;
} TfwGState;

#define TFW_GFSM_STATE(s)	(s)->st_stack[(s)->st_p]

typedef int (*tfw_gfsm_handler_t)(void *obj, unsigned char *data, size_t len);

void tfw_gfsm_state_init(TfwGState *st, void *obj, int st0);
int tfw_gfsm_dispatch(void *obj, unsigned char *data, size_t len);
int tfw_gfsm_move(TfwGState *st, unsigned short new_state, unsigned char *data,
		  size_t len);

int tfw_gfsm_register_hook(int fsm_id, int prio, int state,
			   unsigned short hndl_fsm_id, int st0);
int tfw_gfsm_register_fsm(int fsm_id, tfw_gfsm_handler_t handler);
void tfw_gfsm_unregister_fsm(int fsm_id);

#endif /* __TFW_GFSM_H__ */
