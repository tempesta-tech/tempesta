from __future__ import print_function
import unittest
from helpers import deproxy, framework

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class Request(unittest.TestCase):

    def create_reqs(self, is_raw):
        self.plain = deproxy.Request(PLAIN, is_raw)
        self.reordered = deproxy.Request(REORDERED, is_raw)
        self.body = deproxy.Request(WITH_BODY, is_raw)
        self.body2 = deproxy.Request(WITH_BODY_2, is_raw)
        self.duplicated = deproxy.Request(DUPLICATED, is_raw)

    def test_raw(self):
        self.create_reqs(True)
        self.reqs = [self.plain, self.reordered, self.body, self.body2,
                     self.duplicated]
        for first in self.reqs:
            for second in self.reqs:
                with self.assertRaises(framework.Error):
                    first.is_equal(second)

    def test_parsed(self):
        self.create_reqs(False)

        self.assertTrue(self.plain.is_equal(self.reordered))

        self.assertFalse(self.plain.is_equal(self.body))
        self.assertFalse(self.plain.is_equal(self.body2))
        self.assertFalse(self.plain.is_equal(self.duplicated))

        self.assertFalse(self.reordered.is_equal(self.body))
        self.assertFalse(self.reordered.is_equal(self.body2))
        self.assertFalse(self.reordered.is_equal(self.duplicated))

        self.assertFalse(self.body.is_equal(self.body2))
        self.assertFalse(self.body.is_equal(self.duplicated))

        self.assertFalse(self.body.is_equal(self.duplicated))


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
