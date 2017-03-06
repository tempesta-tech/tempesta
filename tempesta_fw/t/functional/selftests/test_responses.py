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

    def test_parse(self):
        # Reordering of headers is allowed.
        self.assertTrue(self.plain.is_equal(self.reordered))

        responses = [self.no_body, self.o_body, self.duplicated, self.o_status]
        for response in responses:
            self.assertFalse(self.plain.is_equal(response))

        responses_same_headers = [self.reordered, self.no_body, self.o_body]
        for response in responses_same_headers:
            self.assertFalse(self.plain.is_equal(response, header_only=True))

        responses_differ_headers = [self.duplicated, self.o_status]
        for response in responses_differ_headers:
            self.assertFalse(self.plain.is_equal(response, header_only=True))


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
