import multiprocessing
import time
import urllib
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import IPv4Address
from urllib.request import urlopen

import pytest

from blockers.ipset import IpSetBlocker
from blockers.nft import NFTBlocker
from utils.datatypes import User

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@pytest.fixture(
    params=[
        IpSetBlocker(blocking_ip_set_name="tempesta_blocked_ips"),
        NFTBlocker(blocking_table_name="tempesta_blocked_ips"),
    ],
    ids=["IpSet", "NFT"],
)
def blocker(request):
    request.param.prepare()
    yield request.param
    request.param.reset()


@pytest.fixture
def http_server():
    def run_http_server():
        class SimpleHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")

        with HTTPServer(("127.0.0.1", 8000), SimpleHandler) as httpd:
            httpd.serve_forever()

    process = multiprocessing.Process(target=run_http_server)
    process.start()

    time.sleep(0.1)

    yield process

    process.terminate()
    process.join()


def test_block_single(blocker):
    user = User(ipv4=[IPv4Address("127.0.1.1")])
    blocker.block(user)

    users = blocker.info()
    assert len(users) == 1
    assert users[0].ipv4 == [IPv4Address("127.0.1.1")]


def test_block_multiple(blocker):
    user = User(ipv4=[IPv4Address("127.0.1.1"), IPv4Address("127.0.1.2")])
    blocker.block(user)

    users = blocker.info()
    users.sort(key=lambda u: u.ipv4)

    assert len(users) == 2
    assert users[0].ipv4 == [IPv4Address("127.0.1.1")]
    assert users[1].ipv4 == [IPv4Address("127.0.1.2")]


def test_release_single(blocker):
    user = User(ipv4=[IPv4Address("127.0.1.1")])
    blocker.block(user)

    users = blocker.info()
    assert len(users) == 1

    blocker.release(user)
    users = blocker.info()
    assert len(users) == 0


def test_release_multiple(blocker):
    user = User(ipv4=[IPv4Address("127.0.1.1"), IPv4Address("127.0.1.2")])
    blocker.block(user)

    users = blocker.info()
    assert len(users) == 2

    blocker.release(user)
    users = blocker.info()
    assert len(users) == 0


def test_load_empty_table(blocker):
    users = blocker.load()
    assert len(users) == 0


def test_load_blocked(blocker):
    user = User(ipv4=[IPv4Address("127.0.1.1"), IPv4Address("127.0.1.2")])
    blocker.block(user)
    users = blocker.load()
    assert len(users) == 2


def test_rules_work(blocker, http_server):
    user = User(ipv4=[IPv4Address("127.0.0.1")])
    response = urlopen("http://localhost:8000")
    assert response.getcode() == 200

    blocker.block(user)

    with pytest.raises(urllib.error.URLError):
        urlopen("http://localhost:8000", timeout=0.1)

    blocker.release(user)
    response = urlopen("http://localhost:8000", timeout=0.1)
    assert response.getcode() == 200
