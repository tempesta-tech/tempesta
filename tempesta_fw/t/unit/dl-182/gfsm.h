#ifndef GFSM_H
#define GFSM_H

/**
 * Responses from socket hook functions.
 */
enum {
    /* Generic socket error. */
    SS_BAD		= -3,
    /* The packet must be dropped. */
    SS_DROP		= -2,
    /* The packet should be stashed (made by callback). */
    SS_POSTPONE	= -1,
    /* The packet looks good and we can safely pass it. */
    SS_OK		= 0,
    /* Stop passing data to the upper layer for processing. */
    SS_STOP		= 1,
};

/*
 * Hooks return codes.
 */
enum {
    /*
     * Stop passing data for processing from the lower layer.
     * Incoming data packets must be dropped.
     */
    TFW_STOP	= SS_STOP,

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
    TFW_FSM_FRANG,

    TFW_FSM_NUM /* Must be <= TFW_GFSM_FSM_N */
};

#endif // GFSM_H

