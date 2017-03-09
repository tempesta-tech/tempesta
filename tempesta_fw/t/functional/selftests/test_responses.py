from __future__ import print_function
import unittest
from helpers import deproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class ParseResponse(unittest.TestCase):

    def setUp(self):
        self.plain = deproxy.Response(PLAIN)
        self.reordered = deproxy.Response(REORDERED)
        self.o_body = deproxy.Response(OTHER_BODY)
        self.duplicated = deproxy.Response(DUPLICATED)
        self.o_status = deproxy.Response(OTHER_STATUS)

        self.trailer = deproxy.Response(TRAILER)
        self.o_trailer = deproxy.Response(OTHER_TRAILER)

    def test_equal(self):
        # Reordering of headers is allowed.
        self.assertTrue(self.plain == self.reordered)
        self.assertFalse(self.plain != self.reordered)

        for resp in [self.o_body, self.duplicated, self.o_status]:
            self.assertFalse(self.plain == resp)
            self.assertTrue(self.plain != resp)

        for resp in [self.o_body, self.duplicated, self.o_status]:
            self.assertFalse(self.reordered == resp)
            self.assertTrue(self.reordered != resp)

        for resp in [self.duplicated, self.o_status]:
            self.assertFalse(self.o_body == resp)
            self.assertTrue(self.o_body != resp)

        self.assertFalse(self.duplicated == self.o_status)
        self.assertTrue(self.duplicated != self.o_status)

        self.assertFalse(self.trailer == self.o_trailer)
        self.assertTrue(self.trailer != self.o_trailer)

    def test_parse(self):
        self.assertEqual(self.plain.status, '200')
        self.assertEqual(self.plain.reason, 'OK')
        self.assertEqual(self.plain.version, 'HTTP/1.1')

        headers = [('Date', 'Mon, 23 May 2005 22:38:34 GMT'),
                   ('Content-Type', 'text/html; charset=UTF-8'),
                   ('Content-Encoding', 'UTF-8'),
                   ('Content-Length', '130'),
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
                          "</html>\n"))


PLAIN = """HTTP/1.1 200 OK
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
Content-Length: 130

<html>
<head>
  <title>An Example Page</title>
</head>
<body>
  Hello World, this is a very simple HTML document.
</body>
</html>

"""

# With other body:
OTHER_BODY = """HTTP/1.1 200 OK
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
  <title>An EXAMPLE Page</title>
</head>
<body>
  Hello World, this is a very simple HTML document.
</body>
</html>
"""

# With duplicated header:
DUPLICATED = """HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Encoding: UTF-8
Content-Length: 130
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

TRAILER = """HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Encoding: UTF-8
Transfer-Encoding: compress, gzip, chunked
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close

4
1234
0

Expires: Wed, 21 Oct 2015 07:28:00 GMT
"""

OTHER_TRAILER = """HTTP/1.1 200 OK
Date: Mon, 23 May 2005 22:38:34 GMT
Content-Type: text/html; charset=UTF-8
Content-Encoding: UTF-8
Transfer-Encoding: compress, gzip, chunked
Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT
Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)
ETag: "3f80f-1b6-3e1cb03b"
Accept-Ranges: bytes
Connection: close

4
1234
0

Expires: Wed, 21 Dec 2015 07:28:00 GMT
"""

class ParseBody(unittest.TestCase):

    def default_body(self):
        return ("<html>\n"
                "<head>\n"
                "  <title>An Example Page</title>\n"
                "</head>\n"
                "<body>\n"
                "  Hello World, this is a very simple HTML document.\n"
                "</body>\n"
                "</html>\n")

    def chunked_body(self):
        return ("4\n"
                "1234\n"
                "0\n"
                "\n")

    def try_body(self, response_text, body_text, trailer_headers=None):
        response = deproxy.Response(response_text)
        self.assertEqual(response.body, body_text)
        if not trailer_headers:
            self.assertEqual(len(response.trailer), 0)
        else:
            for header, value in trailer_headers:
                self.assertEqual(response.trailer[header], value.strip())

    def test_chunked_empty(self):
        self.try_body(PARSE_CHUNKED_EMPTY, '0\n\n')

    def test_chunked(self):
        self.try_body(PARSE_CHUNKED, self.chunked_body())

    def test_chunked_and_trailer(self):
        self.try_body(PARSE_CHUNKED_AND_TRAILER, self.chunked_body(),
                      [('Expires', 'Wed, 21 Oct 2015 07:28:00 GMT')])

    def test_contentlength(self):
        self.try_body(PARSE_CONTENT_LENGTH, self.default_body())

    def test_contentlength_too_short(self):
        with self.assertRaises(deproxy.ParseError):
            self.try_body(PARSE_CONTENT_LENGTH_TOO_SHORT, '')


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

0

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

4
1234
0

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

4
1234
0

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
