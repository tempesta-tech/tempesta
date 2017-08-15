from __future__ import print_function
import unittest
from helpers import deproxy

class TestDeproxyMessage(unittest.TestCase):

    def setUp(self):
        deproxy.HeaderCollection._disable_report_wrong_is_expected = True

    def tearDown(self):
        deproxy.HeaderCollection._disable_report_wrong_is_expected = False

    def test_incomplite(self):
        message_1 = "HTTP/1.1 20"
        message_2 = ("HTTP/1.1 200 OK\r\n"
                     "Date: Mon, 23 May 2005 22:38:34 GMT\r\n"
                     "Content-Type: text/html; charset=UTF-8\r\n"
                     "Content-Enco")
        message_3 = ("HTTP/1.1 200 OK\r\n"
                     "Date: Mon, 23 May 2005 22:38:34 GMT\r\n"
                     "Content-Type: text/html; charset=UTF-8\r\n")
        message_4 = ("HTTP/1.1 200 OK\r\n"
                     "Date: Mon, 23 May 2005 22:38:34 GMT\r\n"
                     "Content-Type: text/html; charset=UTF-8\r\n"
                     "Content-Encoding: UTF-8\r\n"
                     "Transfer-Encoding: compress, gzip, chunked\r\n"
                     "Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT\r\n"
                     "Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)\r\n"
                     """ETag: "3f80f-1b6-3e1cb03b"\r\n"""
                     "Accept-Ranges: bytes\r\n"
                     "Connection: close\r\n"
                     "\r\n")
        message_5 = ("HTTP/1.1 200 OK\r\n"
                     "Date: Mon, 23 May 2005 22:38:34 GMT\r\n"
                     "Content-Type: text/html; charset=UTF-8\r\n"
                     "Content-Encoding: UTF-8\r\n"
                     "Transfer-Encoding: compress, gzip, chunked\r\n"
                     "Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT\r\n"
                     "Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)\r\n"
                     """ETag: "3f80f-1b6-3e1cb03b"\r\n"""
                     "Accept-Ranges: bytes\r\n"
                     "Connection: close\r\n"
                     "\r\n"
                     "6\r\n"
                     "<html>\r\n"
                     "0\r\n"
                     "Expires: Wed, 21 Oct 2015 07:28:00 GMT")
        message_6 = ("HTTP/1.1 200 OK\r\n"
                     "Date: Mon, 23 May 2005 22:38:34 GMT\r\n"
                     "Content-Type: text/html; charset=UTF-8\r\n"
                     "Content-Encoding: UTF-8\r\n"
                     "Content-Length: 1000\r\n"
                     "Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT\r\n"
                     "Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)\r\n"
                     """ETag: "3f80f-1b6-3e1cb03b"\r\n"""
                     "Accept-Ranges: bytes\r\n"
                     "Connection: close\r\n"
                     "\r\n"
                     "<html>\r\n")
        incomplite = [(message_1, 'header'),
                      (message_2, 'header'),
                      (message_3, 'header: no CRLF'),
                      (message_4, 'body: no last-chunk'),
                      (message_5, 'trailer: no CRLF'),
                      (message_6, 'body: too short')]
        for message, reason in incomplite:
            msg = ('Message parsed, but it has incomplite %s. Message:\n%s'
                   % (reason, message))
            parsed = True
            try:
                deproxy.Response(message)
            except deproxy.ParseError:
                parsed = False
            self.assertFalse(parsed, msg)

    def test_valid(self):
        message_1 = ("HTTP/1.1 200 OK\r\n"
                     "Date: Mon, 23 May 2005 22:38:34 GMT\r\n"
                     "Content-Type: text/html; charset=UTF-8\r\n"
                     "\r\n")
        message_2 = ("HTTP/1.1 200 OK\r\n"
                     "Date: Mon, 23 May 2005 22:38:34 GMT\r\n"
                     "Content-Type: text/html; charset=UTF-8\r\n"
                     "Content-Encoding: UTF-8\r\n"
                     "Transfer-Encoding: compress, gzip, chunked\r\n"
                     "Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT\r\n"
                     "Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)\r\n"
                     """ETag: "3f80f-1b6-3e1cb03b"\r\n"""
                     "Accept-Ranges: bytes\r\n"
                     "Connection: close\r\n"
                     "\r\n"
                     "0\r\n"
                     "\r\n")
        message_3 = ("HTTP/1.1 200 OK\r\n"
                     "Date: Mon, 23 May 2005 22:38:34 GMT\r\n"
                     "Content-Type: text/html; charset=UTF-8\r\n"
                     "Content-Encoding: UTF-8\r\n"
                     "Transfer-Encoding: compress, gzip, chunked\r\n"
                     "Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT\r\n"
                     "Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)\r\n"
                     """ETag: "3f80f-1b6-3e1cb03b"\r\n"""
                     "Accept-Ranges: bytes\r\n"
                     "Connection: close\r\n"
                     "\r\n"
                     "6\r\n"
                     "<html>\r\n"
                     "0\r\n"
                     "\r\n")
        message_4 = ("HTTP/1.1 200 OK\r\n"
                     "Date: Mon, 23 May 2005 22:38:34 GMT\r\n"
                     "Content-Type: text/html; charset=UTF-8\r\n"
                     "Content-Encoding: UTF-8\r\n"
                     "Transfer-Encoding: compress, gzip, chunked\r\n"
                     "Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT\r\n"
                     "Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)\r\n"
                     """ETag: "3f80f-1b6-3e1cb03b"\r\n"""
                     "Accept-Ranges: bytes\r\n"
                     "Connection: close\r\n"
                     "\r\n"
                     "6\r\n"
                     "<html>\r\n"
                     "0\r\n"
                     "\r\n"
                     "Expires: Wed, 21 Oct 2015 07:28:00 GMT\r\n"
                     "\r\n")
        message_5 = ("HTTP/1.1 200 OK\r\n"
                     "Date: Mon, 23 May 2005 22:38:34 GMT\r\n"
                     "Content-Type: text/html; charset=UTF-8\r\n"
                     "Content-Encoding: UTF-8\r\n"
                     "Content-Length: 6\r\n"
                     "Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT\r\n"
                     "Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)\r\n"
                     """ETag: "3f80f-1b6-3e1cb03b"\r\n"""
                     "Accept-Ranges: bytes\r\n"
                     "Connection: close\r\n"
                     "\r\n"
                     "<html>"
                     "\r\n")
        message_6 = ("HTTP/1.1 200 OK\r\n"
                     "Date: Mon, 23 May 2005 22:38:34 GMT\r\n"
                     "Content-Type: text/html; charset=UTF-8\r\n"
                     "Content-Encoding: UTF-8\r\n"
                     "Content-Length: 0\r\n"
                     "Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT\r\n"
                     "Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)\r\n"
                     """ETag: "3f80f-1b6-3e1cb03b"\r\n"""
                     "Accept-Ranges: bytes\r\n"
                     "Connection: close\r\n"
                     "\r\n")
        valid_messages = [message_1, message_2, message_3, message_4, message_5,
                          message_6]
        for message in valid_messages:
            try:
                deproxy.Response(message)
            except deproxy.ParseError:
                print('Error happen when processed message\n%s' % message)
                raise

    def test_request_plain(self):
        request = deproxy.Request(
            "GET / HTTP/1.1\r\n"
            "Host: 10.0.10.2\r\n"
            "User-Agent: curl/7.53.1\r\n"
            "Accept: */*\r\n"
            "\r\n")
        headers = ['Host: 10.0.10.2', 'User-Agent: curl/7.53.1', 'Accept: */*']
        created = deproxy.Request.create('GET', headers)
        self.assertEqual(request, created)

    def test_request_body(self):
        request = deproxy.Request(
            "GET / HTTP/1.1\r\n"
            "Host: 10.0.10.2\r\n"
            "User-Agent: curl/7.53.1\r\n"
            "Accept: */*\r\n"
            "Content-Length: 6\r\n"
            "\r\n"
            "<html>"
            "\r\n")
        headers = ['Host: 10.0.10.2', 'User-Agent: curl/7.53.1', 'Accept: */*',
                   'Content-Length: 6']
        body = "<html>\r\n"
        created = deproxy.Request.create('GET', headers, body=body)
        self.assertEqual(request, created)

    def test_response_plain(self):
        response = deproxy.Response(
            "HTTP/1.1 200 OK\r\n"
            "Server: SimpleHTTP/0.6 Python/3.6.0\r\n"
            "Content-type: text/html\r\n"
            "Content-Length: 138\r\n"
            "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            "\r\n"
            "<html>\r\n"
            "<head>\r\n"
            "  <title>An Example Page</title>\r\n"
            "</head>\r\n"
            "<body>\r\n"
            "  Hello World, this is a very simple HTML document.\r\n"
            "</body>\r\n"
            "</html>\r\n"
        )
        headers = [
            'Server: SimpleHTTP/0.6 Python/3.6.0',
            'Content-type: text/html',
            'Content-Length: 138',
            'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT']
        body = (
            "<html>\r\n"
            "<head>\r\n"
            "  <title>An Example Page</title>\r\n"
            "</head>\r\n"
            "<body>\r\n"
            "  Hello World, this is a very simple HTML document.\r\n"
            "</body>\r\n"
            "</html>\r\n")
        created = deproxy.Response.create(200, headers, body=body)
        self.assertEqual(response, created)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
