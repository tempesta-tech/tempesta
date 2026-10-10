/*
 * **** WARNING: Add new events to the end of the file. ****
 *
 * Use DEFINE_EVENT() when an event has event-specific parameters.
 * @bin_fmt describes how these parameters are serialized into the binary
 * event body and must contain only supported conversion specifications.
 * @text_fmt describes their printable representation. Both formats must
 * consume the same parameters, in the same order and with matching types.
 *
 * Use DEFINE_EVENT_NO_PARAMS() when an event has fixed printable text and
 * no event-specific parameters.
 *
 * Examples:
 *
 * DEFINE_EVENT(TFW_VALUE_EXCEEDED, "%ld%ld",
 *              "value exceeded: %ld (lim=%ld)")
 * DEFINE_EVENT_NO_PARAMS(TFW_INVALID_HEADER, "invalid header")
 */
DEFINE_EVENT(TFW_LOG_EVENT_MAX_CONN_EXCEEDED, "%ld%ld",
	     "frang: connections max num. exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_CONN_BURST_EXCEEDED, "%ld%ld",
	     "frang: new connections burst exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_CONN_RATE_EXCEEDED, "%ld%ld",
	     "frang: new connections rate exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_CL_HEADER_TIMEOUT_EXCEEDED, "%ld%ld",
	     "frang: client header timeout exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_CL_HEADER_CHUNK_EXCEEDED, "%ld%ld",
	     "frang: HTTP header chunk count exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_CL_BODY_TIMEOUT_EXCEEDED, "%ld%ld",
	     "frang: client body timeout exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_CL_BODY_CHUNK_EXCEEDED, "%ld%ld",
	     "frang: HTTP body chunk count exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_BODY_LENGTH_EXCEEDED, "%ld%ld",
	     "frang: HTTP body length exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_REQ_BURST_EXCEEDED, "%ld%ld",
	     "frang: request burst exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_REQ_RATE_EXCEEDED, "%ld%ld",
	     "frang: request rate exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_URI_LEN_EXCEEDED, "%ld%ld",
	     "frang: HTTP URI length exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_RESTRICTED_HTTP_METHOD, "%u%lu",
	     "frang: restricted HTTP method: %u method=(%lu)")
DEFINE_EVENT(TFW_LOG_EVENT_RESTRICTED_OVERR_HTTP_METHOD, "%u%lu",
	     "frang: restricted overridden HTTP method: %u (%lu)")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_UPGRADE_NO_CONN_OPTION,
		       "frang: upgrade request without connection option. Protocol websocket")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_MISSED_CT_HDR,
		       "frang: Content-Type header field is missed")
DEFINE_EVENT(TFW_LOG_EVENT_RESTRICTED_CT_HDR, "%.*s",
	     "frang: restricted Content-Type: %.*s")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_EMPTY_CT_HDR,
		       "frang: restricted empty Content-Type")
DEFINE_EVENT(TFW_LOG_EVENT_VHOST_SNI_NOT_MATCH_AUTH, "%.*s%.*s",
	     "frang: vhost by SNI doesn't match vhost by authority ('%.*s' vs '%.*s')")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_REQ_AUTH_DIFF_HOST,
		       "frang: request :authority differs from Host header")
DEFINE_EVENT(TFW_LOG_EVENT_PORT_HOST_DIFF, "%u%u",
	     "frang: port from host header doesn't match port from uri %u (%u)")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_REQ_HOST_DIFF_URI,
		       "frang: request host from absolute URI differs from Host header")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_HOST_HDR_IN_OLD_PROTO,
		       "frang: Host header field in protocol prior to HTTP/1.1")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_IP_ADDR_IN_HOST,
		       "frang: Host header field contains IP address")
DEFINE_EVENT(TFW_LOG_EVENT_HOST_PORT_N_MATCH_REAL_PORT, "%u%u",
	     "frang: port from host header doesn't match real port %u (%u)")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_DUP_HDR_FIELD,
		       "frang: duplicate header field found")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_DUP_HDR_FIELD_IN_TRAILER,
		       "frang: duplicate header field found in trailer")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_DUP_HDR_FIELD_IN_TRAILER_REG,
		       "frang: HTTP field appear in header and trailer of the request")
DEFINE_EVENT(TFW_LOG_EVENT_BODY_LEN_EXCEEDED, "%ld%ld",
	     "frang: HTTP response body length exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_BODY_LEN_EXCEEDED_HM, "%ld%ld",
	     "frang: HTTP response body length exceeded for health monitor subsystem: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_RESP_CODE_BLOCK_EXCEEDED, "%ld%ld",
	     "frang: http_resp_code_block limit: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_TLS_CONN_BURST_EXCEEDED, "%ld%ld",
	     "frang: new TLS connection burst exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_TLS_CONN_RATE_EXCEEDED, "%ld%ld",
	     "frang: new TLS connection rate exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_TLS_INCOMP_CONN_RATE_EXCEEDED, "%ld%ld",
	     "frang: incomplete TLS connections rate exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_HTTP_HDR_LEN_EXCEEDED, "%ld%ld",
	     "frang: HTTP header length exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_HTTP_HDRS_COUNT_EXCEEDED, "%ld%ld",
	     "frang: HTTP headers count exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_HTTP_HDR_LIST_SIZE_EXCEEDED, "%ld%ld",
	     "frang: HTTP header list size exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_STICKY_MAX_MISSES_EXCEEDED, "%ld%ld",
	     "frang: sticky cookie max rmisses exceeded: %ld (lim=%ld)")
DEFINE_EVENT(TFW_LOG_EVENT_BODY_ATTACK, "%s%s",
	     "parser: Transfer-Encoding chunked and Content-Length in same" \
	     " %s considered as attempt to %s attack.")
DEFINE_EVENT(TFW_LOG_EVENT_BAD_STICKY_COOKIE_HMAC, "%c%d%lu%.*s",
	     "http_sess: bad received HMAC value %c(pos=%d)," \
	     " ts=%lu orig_hmac=[%.*s]")
DEFINE_EVENT(TFW_LOG_EVENT_BAD_STICKY_COOKIE_LENGTH, "%lu%lu",
	     "http_sess: bad sticky cookie length %lu(%lu)")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_STICKY_COOKIE_CALC_FAILED,
		       "http_sess: cannot compute sticky cookie value")
DEFINE_EVENT(TFW_LOG_EVENT_STICKY_COOKIE_EXPIRED, "%lu%lu%lu",
	     "http_sess: sticky cookie value expired" \
	     " (issued=%lu lifetime=%lu now=%lu)")
DEFINE_EVENT(TFW_LOG_EVENT_JSCH_EARLY_REDIRECT, "%lu%lu",
	     "http_sess: jsch redirect received too early" \
	     " (%lu is not after %lu)")
