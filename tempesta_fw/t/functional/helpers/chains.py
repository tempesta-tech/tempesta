from __future__ import print_function
import copy
from helpers import tf_cfg, deproxy, tempesta

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

def base(uri='/', method='GET', forward=True, date=None):
    """Base message chain. Looks like simple Curl request to Tempesta and
    response for it.

    Return new message chain.
    """

    if date is None:
        date = deproxy.HttpMessage.date_time_string()

    #
    # Prepare request and response contents (common variant for a GET request)
    #

    # common part of request headers
    common_req_headers = [
        'Host: %s' % tf_cfg.cfg.get('Tempesta', 'ip'),
        'User-Agent: curl/7.53.1',
        'Connection: keep-alive',
        'Accept: */*'
    ]
    # request headers added in client->tempesta
    client_req_headers_addn = [
    ]
    # request headers added in tempesta->backend
    tempesta_req_headers_addn = [
        'Via: 1.1 tempesta_fw (Tempesta FW %s)' % tempesta.version(),
        'X-Forwarded-For: %s' % tf_cfg.cfg.get('Client', 'ip')
    ]

    # response HTTP code
    common_resp_code = 200
    # response Date: header
    common_resp_date = date
    # response body
    common_resp_body = (
        "<html>\r\n"
        "<head>\r\n"
        "  <title>An Example Page</title>\r\n"
        "</head>\r\n"
        "<body>\r\n"
        "  Hello World, this is a very simple HTML document.\r\n"
        "</body>\r\n"
        "</html>\r\n"
    )
    common_resp_body_void = False
    # common part of response headers 
    common_resp_headers = [
        'Content-type: text/html',
        'Connection: keep-alive',
        'Content-Length: 138',
        'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT'
    ]
    # response headers added in tempesta->client
    tempesta_resp_headers_addn = [
        'Server: Tempesta FW/%s' % tempesta.version(),
        'Via: 1.1 tempesta_fw (Tempesta FW %s)' % tempesta.version()
    ]
    # response headers added in backend->tempesta
    backend_resp_headers_addn = [
        'Server: Deproxy Server'
    ]

    #
    # Adjust requst and response based on actual method
    #

    if method == "PURGE":
        assert(forward == False)
        common_resp_headers = [
            'Connection: keep-alive',
            'Content-Length: 0'
        ]
        tempesta_resp_headers_addn = []
        common_resp_body = ''
    elif method == "HEAD":
        common_resp_body = ''
        common_resp_body_void = True
    else:
        pass

    #
    # Build requests and responses
    #

    client_req = deproxy.Request.create(
        method=method,
        headers=common_req_headers + client_req_headers_addn,
        uri=uri
    )
    tempesta_resp = deproxy.Response.create(
        status=common_resp_code,
        headers=common_resp_headers + tempesta_resp_headers_addn,
        date=common_resp_date,
        body=common_resp_body,
        body_void=common_resp_body_void
    )

    if forward:
        tempesta_req = deproxy.Request.create(
            method=method,
            headers=common_req_headers + tempesta_req_headers_addn,
            uri=uri
        )
        backend_resp = deproxy.Response.create(
            status=common_resp_code,
            headers=common_resp_headers + backend_resp_headers_addn,
            date=common_resp_date,
            body=common_resp_body,
            body_void=common_resp_body_void
        )
    else:
        tempesta_req = None
        backend_resp = None

    base_chain = deproxy.MessageChain(request=client_req,
                                      expected_response=tempesta_resp,
                                      forwarded_request=tempesta_req,
                                      server_response=backend_resp)
    return copy.copy(base_chain)


def base_chunked(uri='/'):
    """Same as chains.base(), but returns a copy of message chain with
    chunked body.
    """
    rule = base()
    body = ("4\r\n"
            "1234\r\n"
            "0\r\n"
            "\r\n")

    for response in [rule.response, rule.server_response]:
        response.headers.delete_all('Content-Length')
        response.headers.add('Transfer-Encoding', 'chunked')
        response.body = body
        response.update()

    return rule

def base_repeated(count, *args, **kwargs):
    chain = base(*args, **kwargs)
    return [chain for _ in range(count)]

def cache(*args, **kwargs):
    return base(forward=False, *args, **kwargs)

def proxy(*args, **kwargs):
    return base(forward=True, *args, **kwargs)

def cache_repeated(count, *args, **kwargs):
    chains = [proxy(*args, **kwargs)]
    chain = cache(*args, **kwargs)
    cached_chains = [chain for _ in range(1, count)]
    return chains + cached_chains

def proxy_repeated(count, *args, **kwargs):
    chain = proxy(*args, **kwargs)
    return [chain for _ in range(count)]
