/*
 * **** WARNING: Add new events to the end of the file. ****
 *
 * Use DEFINE_EVENT() when an event has event-specific parameters.
 * @bin_fmt describes how these parameters are serialized into the binary
 * event body and must contain only supported conversion specifications.
 * @text_fmt describes their printable representation. Both formats must
 * consume the same parameters, in the same order and with matching types.
 * @description is a fixed human-readable label that describes event.
 *
 * Use DEFINE_EVENT_NO_PARAMS() when an event has fixed printable text and
 * no event-specific parameters.
 *
 * Examples:
 *
 * DEFINE_EVENT(TFW_VALUE_EXCEEDED, "%ld%ld",
 *              "value exceeded: %ld (lim=%ld)", "Value limit exceeded")
 * DEFINE_EVENT_NO_PARAMS(TFW_INVALID_HEADER, "invalid header",
 *                        "Invalid header received")
 */
DEFINE_EVENT(TFW_LOG_EVENT_MAX_CONN_EXCEEDED, "%ld%ld",
	     "frang: connections max num. exceeded: %ld (lim=%ld)",
	     "Maximum concurrent client connections exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_CONN_BURST_EXCEEDED, "%ld%ld",
	     "frang: new connections burst exceeded: %ld (lim=%ld)",
	     "New client connection burst exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_CONN_RATE_EXCEEDED, "%ld%ld",
	     "frang: new connections rate exceeded: %ld (lim=%ld)",
	     "New client connection rate exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_CL_HEADER_TIMEOUT_EXCEEDED, "%ld%ld",
	     "frang: client header timeout exceeded: %ld (lim=%ld)",
	     "Client request header timeout exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_CL_HEADER_CHUNK_EXCEEDED, "%ld%ld",
	     "frang: HTTP header chunk count exceeded: %ld (lim=%ld)",
	     "Client request header chunk limit exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_CL_BODY_TIMEOUT_EXCEEDED, "%ld%ld",
	     "frang: client body timeout exceeded: %ld (lim=%ld)",
	     "Client request body timeout exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_CL_BODY_CHUNK_EXCEEDED, "%ld%ld",
	     "frang: HTTP body chunk count exceeded: %ld (lim=%ld)",
	     "Client request body chunk limit exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_BODY_LENGTH_EXCEEDED, "%ld%ld",
	     "frang: HTTP body length exceeded: %ld (lim=%ld)",
	     "Client request body length limit exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_REQ_BURST_EXCEEDED, "%ld%ld",
	     "frang: request burst exceeded: %ld (lim=%ld)",
	     "Client request burst exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_REQ_RATE_EXCEEDED, "%ld%ld",
	     "frang: request rate exceeded: %ld (lim=%ld)",
	     "Client request rate exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_URI_LEN_EXCEEDED, "%ld%ld",
	     "frang: HTTP URI length exceeded: %ld (lim=%ld)",
	     "Request URI length limit exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_RESTRICTED_HTTP_METHOD, "%u%lu",
	     "frang: restricted HTTP method: %u method=(%lu)",
	     "Request used a restricted HTTP method")
DEFINE_EVENT(TFW_LOG_EVENT_RESTRICTED_OVERR_HTTP_METHOD, "%u%lu",
	     "frang: restricted overridden HTTP method: %u (%lu)",
	     "Request used a restricted overridden HTTP method")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_UPGRADE_NO_CONN_OPTION,
		       "frang: upgrade request without connection option. Protocol websocket",
		       "WebSocket upgrade missing the Connection option")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_MISSED_CT_HDR,
		       "frang: Content-Type header field is missed",
		       "Request missing a required Content-Type header")
DEFINE_EVENT(TFW_LOG_EVENT_RESTRICTED_CT_HDR, "%.*s",
	     "frang: restricted Content-Type: %.*s",
	     "Request used a restricted Content-Type")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_EMPTY_CT_HDR,
		       "frang: restricted empty Content-Type",
		       "Request contained an empty Content-Type header")
DEFINE_EVENT(TFW_LOG_EVENT_VHOST_SNI_NOT_MATCH_AUTH, "%.*s%.*s",
	     "frang: vhost by SNI doesn't match vhost by authority ('%.*s' vs '%.*s')",
	     "TLS SNI and request authority selected different virtual hosts")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_REQ_AUTH_DIFF_HOST,
		       "frang: request :authority differs from Host header",
		       "Request authority differed from the Host header")
DEFINE_EVENT(TFW_LOG_EVENT_PORT_HOST_DIFF, "%u%u",
	     "frang: port from host header doesn't match port from uri %u (%u)",
	     "Host header port differed from the absolute URI port")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_REQ_HOST_DIFF_URI,
		       "frang: request host from absolute URI differs from Host header",
		       "Absolute URI host differed from the Host header")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_HOST_HDR_IN_OLD_PROTO,
		       "frang: Host header field in protocol prior to HTTP/1.1",
		       "Host header used with an HTTP version before HTTP/1.1")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_IP_ADDR_IN_HOST,
		       "frang: Host header field contains IP address",
		       "Host header contained an IP address")
DEFINE_EVENT(TFW_LOG_EVENT_HOST_PORT_N_MATCH_REAL_PORT, "%u%u",
	     "frang: port from host header doesn't match real port %u (%u)",
	     "Request host port differed from the local connection port")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_DUP_HDR_FIELD,
		       "frang: duplicate header field found",
		       "Request contained a duplicate header field")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_DUP_HDR_FIELD_IN_TRAILER,
		       "frang: duplicate header field found in trailer",
		       "Request contained a duplicate trailer field")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_DUP_HDR_FIELD_IN_TRAILER_REG,
		       "frang: HTTP field appear in header and trailer of the request",
		       "Request repeated a header field in its trailers")
DEFINE_EVENT(TFW_LOG_EVENT_BODY_LEN_EXCEEDED, "%ld%ld",
	     "frang: HTTP response body length exceeded: %ld (lim=%ld)",
	     "Response body length limit exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_BODY_LEN_EXCEEDED_HM, "%ld%ld",
	     "frang: HTTP response body length exceeded for health monitor subsystem: %ld (lim=%ld)",
	     "Health monitor response body length limit exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_RESP_CODE_BLOCK_EXCEEDED, "%ld%ld",
	     "frang: http_resp_code_block limit: %ld (lim=%ld)",
	     "Configured response status count limit exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_TLS_CONN_BURST_EXCEEDED, "%ld%ld",
	     "frang: new TLS connection burst exceeded: %ld (lim=%ld)",
	     "New TLS connection burst exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_TLS_CONN_RATE_EXCEEDED, "%ld%ld",
	     "frang: new TLS connection rate exceeded: %ld (lim=%ld)",
	     "New TLS connection rate exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_TLS_INCOMP_CONN_RATE_EXCEEDED, "%ld%ld",
	     "frang: incomplete TLS connections rate exceeded: %ld (lim=%ld)",
	     "Incomplete TLS connection rate exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_HTTP_HDR_LEN_EXCEEDED, "%ld%ld",
	     "frang: HTTP header length exceeded: %ld (lim=%ld)",
	     "HTTP header field length limit exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_HTTP_HDRS_COUNT_EXCEEDED, "%ld%ld",
	     "frang: HTTP headers count exceeded: %ld (lim=%ld)",
	     "HTTP header count limit exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_HTTP_HDR_LIST_SIZE_EXCEEDED, "%ld%ld",
	     "frang: HTTP header list size exceeded: %ld (lim=%ld)",
	     "HTTP header list size limit exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_STICKY_MAX_MISSES_EXCEEDED, "%ld%ld",
	     "frang: sticky cookie max rmisses exceeded: %ld (lim=%ld)",
	     "Sticky cookie redirect miss limit exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_BODY_ATTACK, "%s%s",
	     "parser: Transfer-Encoding chunked and Content-Length in same" \
	     " %s considered as attempt to %s attack.",
	     "Conflicting Transfer-Encoding and Content-Length headers")
DEFINE_EVENT(TFW_LOG_EVENT_BAD_STICKY_COOKIE_HMAC, "%c%d%lu%.*s",
	     "http_sess: bad received HMAC value %c(pos=%d)," \
	     " ts=%lu orig_hmac=[%.*s]",
	     "Sticky cookie authentication failed")
DEFINE_EVENT(TFW_LOG_EVENT_BAD_STICKY_COOKIE_LENGTH, "%lu%lu",
	     "http_sess: bad sticky cookie length %lu(%lu)",
	     "Sticky cookie length was invalid")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_STICKY_COOKIE_CALC_FAILED,
		       "http_sess: cannot compute sticky cookie value",
		       "Sticky cookie calculation failed")
DEFINE_EVENT(TFW_LOG_EVENT_STICKY_COOKIE_EXPIRED, "%lu%lu%lu",
	     "http_sess: sticky cookie value expired" \
	     " (issued=%lu lifetime=%lu now=%lu)",
	     "Sticky cookie lifetime expired")
DEFINE_EVENT(TFW_LOG_EVENT_JSCH_EARLY_REDIRECT, "%lu%lu",
	     "http_sess: jsch redirect received too early" \
	     " (%lu is not after %lu)",
	     "JavaScript challenge response arrived too early")
DEFINE_EVENT_NO_PARAMS(TFW_LOG_EVENT_SPLITTING_ATTACK,
		       "Paired request missing, HTTP Response Splitting attack?",
		       "Unpaired response indicated a possible response splitting attack")
DEFINE_EVENT(TFW_LOG_EVENT_REQ_PARSE_INCONSISTENCY, "%d",
	     "Request parsing inconsistency (status=%d)",
	     "Request parsing state was inconsistent")
DEFINE_EVENT(TFW_LOG_EVENT_BODYLESS_METHOD_HEADERS, "%d",
	     "Request contains Content-Length or Content-Type field"
	     " for bodyless method (status=%d)",
	     "Bodyless request method carried Content-Length or Content-Type")
DEFINE_EVENT(TFW_LOG_EVENT_POSTPONED_REQ_FILTERED, "%d",
	     "postponed request has been filtered out (status=%d)",
	     "Request was filtered before parsing completed")
DEFINE_EVENT(TFW_LOG_EVENT_REQ_TFH_LIMIT_EXCEEDED, "%d",
	     "parsed request exceeded tfh limit (status=%d)",
	     "Request fingerprint rate limit exceeded")
DEFINE_EVENT(TFW_LOG_EVENT_PIPELINED_REQ_AFTER_UPGRADE, "%d",
	     "Request dropped: Pipelined request received"
	     " after UPGRADE request (status=%d)",
	     "Pipelined request followed a protocol upgrade request")
DEFINE_EVENT(TFW_LOG_EVENT_PIPELINED_REQ_SPLIT_FAILED, "%d",
	     "Can't split pipelined requests (status=%d)",
	     "Pipelined request buffer could not be split")
DEFINE_EVENT(TFW_LOG_EVENT_INVALID_AUTHORITY, "%d",
	     "Invalid authority (status=%d)",
	     "Request authority was invalid")
DEFINE_EVENT(TFW_LOG_EVENT_INVALID_X_FORWARDED_FOR, "%d",
	     "request dropped: incorrect X-Forwarded-For header (status=%d)",
	     "X-Forwarded-For header was invalid")
DEFINE_EVENT(TFW_LOG_EVENT_REQ_HTTP_TABLE_FILTERED, "%d",
	     "request has been filtered out via http table (status=%d)",
	     "Request was rejected by HTTP table rules")
DEFINE_EVENT(TFW_LOG_EVENT_PARSED_REQ_FILTERED, "%d",
	     "parsed request has been filtered out (status=%d)",
	     "Request was rejected after parsing completed")
DEFINE_EVENT(TFW_LOG_EVENT_UNSAFE_METHOD_OVERRIDE, "%d",
	     "request dropped: unsafe method override (status=%d)",
	     "Safe request method was overridden with an unsafe method")
DEFINE_EVENT(TFW_LOG_EVENT_STICKY_INTERNAL_ERROR, "%d",
	     "request dropped: internal error in Sticky module (status=%d)",
	     "Internal sticky session processing failed")
DEFINE_EVENT(TFW_LOG_EVENT_RESP_FILTERED, "%d",
	     "response blocked: filtered out (status=%d)",
	     "Response was rejected by a filter")
DEFINE_EVENT(TFW_LOG_EVENT_RESP_PROCESSING_ERROR, "%d",
	     "response dropped: processing error (status=%d)",
	     "Response processing failed")
