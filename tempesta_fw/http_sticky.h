#ifndef __TFW_HTTP_STICKY_H__
#define __TFW_HTTP_STICKY_H__

#include "connection.h"
#include "http.h"

int tfw_http_sticky_req_process(TfwHttpMsg *);
int tfw_http_sticky_resp_process(TfwHttpMsg *, TfwHttpMsg *);

#endif /* __TFW_HTTP_STICKY_H__ */
