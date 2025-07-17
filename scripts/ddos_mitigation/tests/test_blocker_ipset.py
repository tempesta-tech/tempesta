import multiprocessing
import time
import unittest
import urllib
from urllib.request import urlopen
from ipaddress import IPv4Address

from blockers.ipset import IpSetBlocker
from datatypes import User
from http.server import BaseHTTPRequestHandler, HTTPServer

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestBlockerIpSet(unittest.TestCase):
    def setUp(self):
        self.blocker = IpSetBlocker(blocking_ip_set_name='tempesta_blocked_ips')
        self.blocker.prepare()

    def tearDown(self):
        self.blocker.reset()

    def run_http_server(self):
        class SimpleHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")

        with HTTPServer(("127.0.0.1", 8000), SimpleHandler) as httpd:
            httpd.serve_forever()

    def test_block_single(self):
        user = User(ipv4=[IPv4Address('127.0.1.1')])
        self.blocker.block(user)

        users = self.blocker.info()
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].ipv4, [IPv4Address('127.0.1.1')])

    def test_block_multiple(self):
        user = User(ipv4=[IPv4Address('127.0.1.1'), IPv4Address('127.0.1.2')])
        self.blocker.block(user)

        users = self.blocker.info()
        users.sort(key=lambda u: u.ipv4)

        self.assertEqual(len(users), 2)
        self.assertEqual(users[0].ipv4, [IPv4Address('127.0.1.1')])
        self.assertEqual(users[1].ipv4, [IPv4Address('127.0.1.2')])

    def test_release_single(self):
        user = User(ipv4=[IPv4Address('127.0.1.1')])
        self.blocker.block(user)

        users = self.blocker.info()
        self.assertEqual(len(users), 1)

        self.blocker.release(user)
        users = self.blocker.info()
        self.assertEqual(len(users), 0)

    def test_release_multiple(self):
        user = User(ipv4=[IPv4Address('127.0.1.1'), IPv4Address('127.0.1.2')])
        self.blocker.block(user)

        users = self.blocker.info()
        self.assertEqual(len(users), 2)

        self.blocker.release(user)
        users = self.blocker.info()
        self.assertEqual(len(users), 0)

    def test_load_empty_table(self):
        users = self.blocker.load()
        self.assertEqual(len(users), 0)

    def test_load_blocked(self):
        user = User(ipv4=[IPv4Address('127.0.1.1'), IPv4Address('127.0.1.2')])
        self.blocker.block(user)
        users = self.blocker.load()
        self.assertEqual(len(users), 2)

    def test_rules_work(self):
        user = User(ipv4=[IPv4Address('127.0.0.1')])
        process = multiprocessing.Process(target=self.run_http_server)
        process.start()

        time.sleep(0.1)

        response = urlopen("http://localhost:8000")
        self.assertEqual(response.getcode(), 200)

        self.blocker.block(user)
        self.assertRaises(
            urllib.error.URLError,
            urlopen,
            "http://localhost:8000",
            timeout=0.1
        )

        self.blocker.release(user)
        response = urlopen("http://localhost:8000", timeout=0.1)
        self.assertEqual(response.getcode(), 200)

        process.terminate()
        process.join()
