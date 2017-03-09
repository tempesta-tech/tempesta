from __future__ import print_function
import unittest
import asyncore
from helpers import deproxy

class TestDeproxyMessage(unittest.TestCase):

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

    def test_request_fabric(self):
        pass

    def test_response_fabric(self):
        pass
