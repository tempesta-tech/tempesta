from __future__ import print_function
import unittest
from helpers import deproxy, framework

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class ParseRequest(unittest.TestCase):

    def setUp(self):
        self.plain = deproxy.Request(PLAIN)
        self.reordered = deproxy.Request(REORDERED)
        self.body = deproxy.Request(WITH_BODY)
        self.body2 = deproxy.Request(WITH_BODY_2)
        self.duplicated = deproxy.Request(DUPLICATED)

    def test_equal(self):
        # Reordering of headers is allowed.
        self.assertTrue(self.plain == self.reordered)
        self.assertFalse(self.plain != self.reordered)

        # Headers and Body must be the same:
        for req in [self.body, self.body2, self.duplicated]:
            self.assertFalse(self.plain == req)
            self.assertTrue(self.plain != req)

        for req in [self.body, self.body2, self.duplicated]:
            self.assertFalse(self.reordered == req)
            self.assertTrue(self.reordered != req)

        for req in [self.body2, self.duplicated]:
            self.assertFalse(self.body == req)
            self.assertTrue(self.body != req)

        self.assertFalse(self.body2 == self.duplicated)
        self.assertTrue(self.body2 != self.duplicated)

    def test_parse(self):
        self.assertEqual(self.body.method, 'GET')
        self.assertEqual(self.body.uri, '/foo')
        self.assertEqual(self.body.version, 'HTTP/1.1')

        headers = [('User-Agent', 'Wget/1.13.4 (linux-gnu)'),
                   ('Accept', '*/*'),
                   ('Host', 'localhost'),
                   ('Connection', 'Keep-Alive'),
                   ('X-Custom-Hdr', 'custom header values'),
                   ('X-Forwarded-For', '127.0.0.1, example.com'),
                   ('Content-Type', 'text/html; charset=iso-8859-1'),
                   ('Cache-Control', 'max-age=1, no-store, min-fresh=30'),
                   ('Pragma', 'no-cache, fooo'),
                   ('Transfer-Encoding', 'compress, gzip, chunked'),
                   ('Cookie', 'session=42; theme=dark'),
                   ('Authorization', 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==')]
        for header, value in headers:
            self.assertEqual(self.body.headers[header], value.strip())

        self.assertEqual(self.body.body,
                         'id=7cf02319db002de9d962021aab8a9e1e\n\n')


PLAIN = """GET /foo HTTP/1.1
User-Agent: Wget/1.13.4 (linux-gnu)
Accept: */*
Host: localhost
Connection: Keep-Alive
X-Custom-Hdr: custom header values
X-Forwarded-For: 127.0.0.1, example.com
Content-Type: text/html; charset=iso-8859-1
Cache-Control: max-age=1, no-store, min-fresh=30
Pragma: no-cache, fooo
Transfer-Encoding: compress, gzip, chunked
Cookie: session=42; theme=dark
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

"""

# Reordered:
REORDERED = """GET /foo HTTP/1.1
User-Agent: Wget/1.13.4 (linux-gnu)
Accept: */*
Host: localhost
Cache-Control: max-age=1, no-store, min-fresh=30
Connection: Keep-Alive
X-Custom-Hdr: custom header values
X-Forwarded-For: 127.0.0.1, example.com
Content-Type: text/html; charset=iso-8859-1
Pragma: no-cache, fooo
Transfer-Encoding: compress, gzip, chunked
Cookie: session=42; theme=dark
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

"""

# With body:
WITH_BODY = """GET /foo HTTP/1.1
User-Agent: Wget/1.13.4 (linux-gnu)
Accept: */*
Host: localhost
Connection: Keep-Alive
X-Custom-Hdr: custom header values
X-Forwarded-For: 127.0.0.1, example.com
Content-Type: text/html; charset=iso-8859-1
Cache-Control: max-age=1, no-store, min-fresh=30
Pragma: no-cache, fooo
Transfer-Encoding: compress, gzip, chunked
Cookie: session=42; theme=dark
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

id=7cf02319db002de9d962021aab8a9e1e

"""

# With other body:
WITH_BODY_2 = """GET /foo HTTP/1.1
User-Agent: Wget/1.13.4 (linux-gnu)
Accept: */*
Host: localhost
Connection: Keep-Alive
X-Custom-Hdr: custom header values
X-Forwarded-For: 127.0.0.1, example.com
Content-Type: text/html; charset=iso-8859-1
Cache-Control: max-age=1, no-store, min-fresh=30
Pragma: no-cache, fooo
Transfer-Encoding: compress, gzip, chunked
Cookie: session=42; theme=dark
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

id=7cf02319db002de9d962021aab8a9e1e
id=7cf02319db002de9d962021aab8a9e1e

"""

# With duplicated header:
DUPLICATED = """GET /foo HTTP/1.1
User-Agent: Wget/1.13.4 (linux-gnu)
Accept: */*
Host: localhost
Connection: Keep-Alive
X-Custom-Hdr: custom header values
X-Forwarded-For: 127.0.0.1, example.com
Content-Type: text/html; charset=iso-8859-1
Cache-Control: max-age=1, no-store, min-fresh=30
Pragma: no-cache, fooo
Transfer-Encoding: compress, gzip, chunked
Cookie: session=42; theme=dark
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
X-Custom-Hdr: other custom header values

"""

if __name__ == '__main__':
    unittest.main()
