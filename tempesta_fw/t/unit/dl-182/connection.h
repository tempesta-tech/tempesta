#ifndef CONNECTION_H
#define CONNECTION_H

#include "gfsm.h"

enum {
    /* Protocol bits. */
    __Conn_Bits	= 0x8,

    /* Each connection has Client or Server bit. */
    Conn_Clnt	= 0x1 << __Conn_Bits,
    Conn_Srv	= 0x2 << __Conn_Bits,

    /* HTTP */
    Conn_HttpClnt	= Conn_Clnt | TFW_FSM_HTTP,
    Conn_HttpSrv	= Conn_Srv | TFW_FSM_HTTP,

    /* HTTPS */
    Conn_HttpsClnt	= Conn_Clnt | TFW_FSM_HTTPS,
    Conn_HttpsSrv	= Conn_Srv | TFW_FSM_HTTPS,
};

#endif // CONNECTION_H

