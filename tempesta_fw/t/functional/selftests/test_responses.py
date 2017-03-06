from __future__ import print_function
import unittest
from helpers import deproxy, framework

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class ParseResponse(unittest.TestCase):

    def setUp(self):
        self.plain = deproxy.Response(PLAIN)
        self.reordered = deproxy.Response(REORDERED)
        self.no_body = deproxy.Response(NO_BODY)
        self.o_body = deproxy.Response(OTHER_BODY)
        self.duplicated = deproxy.Response(DUPLICATED)
        self.o_status = deproxy.Response(OTHER_STATUS)

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

if __name__ == '__main__':
    unittest.main()
