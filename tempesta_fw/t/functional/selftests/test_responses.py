from __future__ import print_function
import unittest
from helpers import deproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class ParseResponse(unittest.TestCase):

    def setUp(self):
        self.plain = deproxy.Response(PLAIN, body_parsing=False)
        self.reordered = deproxy.Response(REORDERED, body_parsing=False)
        self.no_body = deproxy.Response(NO_BODY, body_parsing=False)
        self.o_body = deproxy.Response(OTHER_BODY, body_parsing=False)
        self.duplicated = deproxy.Response(DUPLICATED, body_parsing=False)
        self.o_status = deproxy.Response(OTHER_STATUS, body_parsing=False)

    def test_equal(self):
        # Reordering of headers is allowed.
        self.assertTrue(self.plain == self.reordered)
        self.assertFalse(self.plain != self.reordered)

        for resp in [self.no_body, self.o_body, self.duplicated, self.o_status]:
            self.assertFalse(self.plain == resp)
            self.assertTrue(self.plain != resp)

        for resp in [self.no_body, self.o_body, self.duplicated, self.o_status]:
            self.assertFalse(self.reordered == resp)
            self.assertTrue(self.reordered != resp)

        for resp in [self.o_body, self.duplicated, self.o_status]:
            self.assertFalse(self.no_body == resp)
            self.assertTrue(self.no_body != resp)

        for resp in [self.duplicated, self.o_status]:
            self.assertFalse(self.o_body == resp)
            self.assertTrue(self.o_body != resp)

        self.assertFalse(self.duplicated == self.o_status)
        self.assertTrue(self.duplicated != self.o_status)

    def test_parse(self):
        self.assertEqual(self.plain.status, '200')
        self.assertEqual(self.plain.reason, 'OK')
        self.assertEqual(self.plain.version, 'HTTP/1.1')

        headers = [('Date', 'Mon, 23 May 2005 22:38:34 GMT'),
                   ('Content-Type', 'text/html; charset=UTF-8'),
                   ('Content-Encoding', 'UTF-8'),
                   ('Content-Length', '138'),
                   ('Last-Modified', 'Wed, 08 Jan 2003 23:11:55 GMT'),
                   ('Server', 'Apache/1.3.3.7 (Unix) (Red-Hat/Linux)'),
                   ('ETag', '"3f80f-1b6-3e1cb03b"'),
                   ('Accept-Ranges', 'bytes'),
                   ('Connection', 'close')]
        for header, value in headers:
            self.assertEqual(self.plain.headers[header], value.strip())

        self.assertEqual(self.plain.body,
                         ("<html>\n"
                          "<head>\n"
                          "  <title>An Example Page</title>\n"
                          "</head>\n"
                          "<body>\n"
                          "  Hello World, this is a very simple HTML document.\n"
                          "</body>\n"
                          "</html>\n\n"))


PLAIN = """HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Encoding: UTF-8
Content-Length: 138
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close

<html>
<head>
  <title>An Example Page</title>
</head>
<body>
  Hello World, this is a very simple HTML document.
</body>
</html>

"""

# Reordered:
REORDERED = """HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close
Content-Encoding: UTF-8
Content-Length: 138

<html>
<head>
  <title>An Example Page</title>
</head>
<body>
  Hello World, this is a very simple HTML document.
</body>
</html>

"""

# No body:
NO_BODY = """HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Encoding: UTF-8
Content-Length: 138
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close

"""

# With other body:
OTHER_BODY = """HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Encoding: UTF-8
Content-Length: 138
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close

id=7cf02319db002de9d962021aab8a9e1e
id=7cf02319db002de9d962021aab8a9e1e
"""

# With duplicated header:
DUPLICATED = """HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Encoding: UTF-8
Content-Length: 138
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close
Connection: aloha

<html>
<head>
  <title>An Example Page</title>
</head>
<body>
  Hello World, this is a very simple HTML document.
</body>
</html>

"""


# With other status:
OTHER_STATUS = """HTTP/1.1 302 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Encoding: UTF-8
Content-Length: 138
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close

<html>
<head>
  <title>An Example Page</title>
</head>
<body>
  Hello World, this is a very simple HTML document.
</body>
</html>

"""

class ParseBody(unittest.TestCase):

    def try_body(self, request_text, body_text=None):
        if body_text == None:
            body_text = ("<html>\n"
                         "<head>\n"
                         "  <title>An Example Page</title>\n"
                         "</head>\n"
                         "<body>\n"
                         "  Hello World, this is a very simple HTML document.\n"
                         "</body>\n"
                         "</html>\n")
        request = deproxy.Request(request_text)
        self.assertEqual(request.body, body_text)

    def test_chunked_empty(self):
        self.try_body(PARSE_CHUNKED_EMPTY, '')

    def test_chunked(self):
        self.try_body(PARSE_CHUNKED)

    def test_chunked_and_trailer(self):
        self.try_body(PARSE_CHUNKED_AND_TRAILER)

    def test_contentlength(self):
        self.try_body(PARSE_CONTENT_LENGTH)

    def test_contentlength_too_short(self):
        with self.assertRaises(AssertionError):
            self.try_body(PARSE_CONTENT_LENGTH_TOO_SHORT)


PARSE_CHUNKED_EMPTY = """HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Encoding: UTF-8
Transfer-Encoding: compress, gzip, chunked
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close

"""

PARSE_CHUNKED = """HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Encoding: UTF-8
Transfer-Encoding: compress, gzip, chunked
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close

<html>
<head>
  <title>An Example Page</title>
</head>
<body>
  Hello World, this is a very simple HTML document.
</body>
</html>

"""

PARSE_CHUNKED_AND_TRAILER = """HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Encoding: UTF-8
Transfer-Encoding: compress, gzip, chunked
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close

<html>
<head>
  <title>An Example Page</title>
</head>
<body>
  Hello World, this is a very simple HTML document.
</body>
</html>

Expires: Wed, 21 Oct 2015 07:28:00 GMT
"""

PARSE_CONTENT_LENGTH = """HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Encoding: UTF-8
Content-Length: 130
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close

<html>
<head>
  <title>An Example Page</title>
</head>
<body>
  Hello World, this is a very simple HTML document.
</body>
</html>

"""

PARSE_CONTENT_LENGTH_TOO_SHORT = """HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Encoding: UTF-8
Content-Length: 1000
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close

<html>
<head>
  <title>An Example Page</title>
</head>
<body>
  Hello World, this is a very simple HTML document.
</body>
</html>

"""

if __name__ == '__main__':
    unittest.main()
