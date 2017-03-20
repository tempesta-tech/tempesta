from __future__ import print_function
import unittest
from helpers import deproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class ParseRequest(unittest.TestCase):

    def setUp(self):
        self.plain = deproxy.Request(PLAIN)
        self.reordered = deproxy.Request(REORDERED)
        self.duplicated = deproxy.Request(DUPLICATED)

    def test_equal(self):
        # Reordering of headers is allowed.
        self.assertTrue(self.plain == self.reordered)
        self.assertFalse(self.plain != self.reordered)

        self.assertFalse(self.plain == self.duplicated)
        self.assertTrue(self.plain != self.duplicated)

        self.assertFalse(self.reordered == self.duplicated)
        self.assertTrue(self.reordered != self.duplicated)

    def test_parse(self):
        self.assertEqual(self.plain.method, 'GET')
        self.assertEqual(self.plain.uri, '/foo')
        self.assertEqual(self.plain.version, 'HTTP/1.1')

        headers = [('User-Agent', 'Wget/1.13.4 (linux-gnu)'),
                   ('Accept', '*/*'),
                   ('Host', 'localhost'),
                   ('Connection', 'Keep-Alive'),
                   ('X-Custom-Hdr', 'custom header values'),
                   ('X-Forwarded-For', '127.0.0.1, example.com'),
                   ('Content-Type', 'text/html; charset=iso-8859-1'),
                   ('Cache-Control', 'max-age=1, no-store, min-fresh=30'),
                   ('Pragma', 'no-cache, fooo'),
                   ('Cookie', 'session=42; theme=dark'),
                   ('Authorization', 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==')]
        for header, value in headers:
            self.assertEqual(self.plain.headers[header], value.strip())

        self.assertEqual(self.plain.body, '')


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
Cookie: session=42; theme=dark
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==

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
Cookie: session=42; theme=dark
Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
X-Custom-Hdr: other custom header values

"""

if __name__ == '__main__':
    unittest.main()
