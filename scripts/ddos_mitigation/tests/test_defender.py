import multiprocessing
import os
import time
import unittest
import urllib
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import urlopen

from clickhouse_connect.driverc.dataconv import IPv4Address

from access_log import ClickhouseAccessLog
from config import AppConfig
from defender import DDOSMonitor, User
from ja5_config import Ja5Config
from user_agents import UserAgentsManager

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestMitigation(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.access_log = ClickhouseAccessLog()
        await self.access_log.connect()
        await self.access_log.conn.query("create database test_db")
        await self.access_log.conn.close()

        self.access_log = ClickhouseAccessLog(database="test_db")
        await self.access_log.connect()
        await self.access_log.conn.query(
            """
            CREATE TABLE IF NOT EXISTS access_log (
                timestamp DateTime64(3, 'UTC'),
                address IPv6,
                method UInt8,
                version UInt8,
                status UInt16,
                response_content_length UInt32,
                response_time UInt32,
                vhost String,
                uri String,
                referer String,
                user_agent String,
                ja5t UInt64,
                ja5h UInt64,
                dropped_events UInt64,
                PRIMARY KEY(timestamp)
            );
            """
        )
        await self.access_log.user_agents_table_create()
        await self.access_log.conn.query(
            """
            insert into access_log values 
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751536000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751537000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 400, 0, 10, 'default', '/', '/', 'UserAgent', 13, 23, 0)
            """
        )
        self.ja5t_config_path = "/tmp/test_ja5t_config"
        self.ja5h_config_path = "/tmp/test_ja5h_config"

        open(self.ja5t_config_path, "w").close()
        open(self.ja5h_config_path, "w").close()

        self.ja5t_config = Ja5Config(self.ja5t_config_path)
        self.ja5h_config = Ja5Config(self.ja5h_config_path)

        self.monitor = DDOSMonitor(
            clickhouse_client=self.access_log,
            ja5t_config=self.ja5t_config,
            ja5h_config=self.ja5h_config,
            app_config=AppConfig(clickhouse_database="test_db"),
            user_agent_manager=UserAgentsManager(
                clickhouse_client=self.access_log, config_path=""
            ),
        )
        try:
            self.monitor.ipset_reset()
        except Exception as e:
            if "doesn't exist" not in str(e):
                print("cant not reset ipset ", e)

        try:
            self.monitor.nftables_reset()
        except Exception as e:
            if "No such file" not in str(e):
                print("cant reset nftables ", e)

    async def asyncTearDown(self):
        os.remove(self.ja5t_config_path)
        os.remove(self.ja5h_config_path)

        await self.access_log.conn.query("drop database if exists test_db")

    def test_hash_risk_user_function(self):
        risk_user_1 = User(ja5t=1)
        risk_user_2 = User(ja5t=2)
        risk_user_3 = User(ja5t=2)

        self.assertEqual(hash(risk_user_2), hash(risk_user_3))
        self.assertNotEqual(hash(risk_user_1), hash(risk_user_3))

    def test_set_thresholds(self):
        self.monitor.set_thresholds(
            requests_threshold=Decimal(1),
            time_threshold=Decimal(2),
            errors_threshold=Decimal(3),
        )
        self.assertEqual(self.monitor.requests_threshold, 1)
        self.assertEqual(self.monitor.time_threshold, 2)
        self.assertEqual(self.monitor.errors_threshold, 3)

    async def test_set_known_users(self):
        risk_user = User(ja5t=1)
        self.monitor.set_known_users([risk_user])
        self.assertEqual(len(self.monitor.known_users), 1)
        self.assertIn(hash(risk_user), self.monitor.known_users)

    def test_load_blocked_users_from_ja5t_hashes(self):
        self.monitor.ja5t_mark_as_blocked([1, 2, 3])
        self.assertEqual(len(self.monitor.blocked), 3)
        self.assertEqual(
            set(self.monitor.blocked.values()),
            {User(ja5t=1), User(ja5t=2), User(ja5t=3)},
        )

    def test_load_blocked_users_from_ja5h_hashes(self):
        self.monitor.ja5h_mark_as_blocked([1, 2, 3])
        self.assertEqual(len(self.monitor.blocked), 3)
        self.assertEqual(
            set(self.monitor.blocked.values()),
            {User(ja5h=1), User(ja5h=2), User(ja5h=3)},
        )

    def test_block_and_unblock_by_ja5t(self):
        self.monitor.jat5t_block(1)
        self.assertEqual(len(self.monitor.blocked), 1)
        self.assertEqual(list(self.monitor.blocked.values())[0], User(ja5t=1))

        self.monitor.ja5t_release(1)
        self.assertEqual(len(self.monitor.blocked), 0)

    def test_block_and_unblock_by_ja5h(self):
        self.monitor.ja5h_block(1)
        self.assertEqual(len(self.monitor.blocked), 1)
        self.assertEqual(list(self.monitor.blocked.values())[0], User(ja5h=1))

        self.monitor.ja5h_release(1)
        self.assertEqual(len(self.monitor.blocked), 0)

    def test_block_and_unblock_by_ip_with_ipset(self):
        self.monitor.ipset_prepare()

        self.monitor.ipset_block(["127.0.0.2", "127.0.0.3"])
        self.monitor.ipset_block(["127.0.0.4"])

        ipset_info = self.monitor.ipset_info()
        self.assertIn("127.0.0.2", ipset_info)
        self.assertIn("127.0.0.3", ipset_info)
        self.assertIn("127.0.0.4", ipset_info)

        self.monitor.ipset_release(["127.0.0.2", "127.0.0.3"])
        self.monitor.ipset_release(["127.0.0.4"])

        ipset_info = self.monitor.ipset_info()
        self.assertNotIn("127.0.0.2", ipset_info)
        self.assertNotIn("127.0.0.3", ipset_info)
        self.assertNotIn("127.0.0.4", ipset_info)

        self.monitor.ipset_reset()

    def run_http_server(self):
        class SimpleHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")

        with HTTPServer(("127.0.0.1", 8000), SimpleHandler) as httpd:
            httpd.serve_forever()

    def test_iptables_rules_work(self):
        process = multiprocessing.Process(target=self.run_http_server)
        process.start()

        time.sleep(0.1)

        response = urlopen("http://localhost:8000")
        self.assertEqual(response.getcode(), 200)

        self.monitor.ipset_prepare()

        self.monitor.ipset_block(["127.0.0.1"])
        self.assertRaises(
            urllib.error.URLError, urlopen, "http://localhost:8000", timeout=0.1
        )

        self.monitor.ipset_release(["127.0.0.1"])
        response = urlopen("http://localhost:8000", timeout=0.1)
        self.assertEqual(response.getcode(), 200)

        process.terminate()
        process.join()
        self.monitor.ipset_reset()

    def test_block_unblock_by_ip_with_nftables(self):
        self.monitor.nftables_prepare()

        self.monitor.nftables_block(["127.0.0.2", "127.0.0.3"])
        self.monitor.nftables_block(["127.0.0.4"])

        nft_info = self.monitor.nftables_info()
        self.assertIn("127.0.0.2", nft_info)
        self.assertIn("127.0.0.3", nft_info)
        self.assertIn("127.0.0.4", nft_info)

        self.monitor.nftables_release(["127.0.0.2", "127.0.0.3"])
        self.monitor.nftables_release(["127.0.0.4"])

        nft_info = self.monitor.nftables_info()
        self.assertNotIn("127.0.0.2", nft_info)
        self.assertNotIn("127.0.0.3", nft_info)
        self.assertNotIn("127.0.0.4", nft_info)

        self.monitor.nftables_reset()

    def test_nftable_rules_work(self):
        process = multiprocessing.Process(target=self.run_http_server)
        process.start()

        time.sleep(0.1)

        response = urlopen("http://localhost:8000")
        self.assertEqual(response.getcode(), 200)

        self.monitor.nftables_prepare()

        self.monitor.nftables_block(["127.0.0.1"])
        self.assertRaises(
            urllib.error.URLError, urlopen, "http://localhost:8000", timeout=0.1
        )

        self.monitor.nftables_release(["127.0.0.1"])
        response = urlopen("http://localhost:8000", timeout=0.1)
        self.assertEqual(response.getcode(), 200)

        process.terminate()
        process.join()
        self.monitor.nftables_reset()

    async def test_persistent_users_load(self):
        result = await self.monitor.persistent_users_load(
            start_at=1751535000,
            period_in_seconds=10,
            requests_amount=Decimal(1),
            time_amount=Decimal(1),
            users_amount=1,
        )
        self.assertEqual(
            result,
            [
                User(
                    ja5t=11,
                    ja5h=21,
                    ipv4=[IPv4Address("127.0.0.1")],
                    value=None,
                    type=None,
                    blocked_at=None,
                )
            ],
        )

    async def test_average_stats_load(self):
        result = await self.monitor.average_stats_load(
            start_at=1751535000, period_in_minutes=1
        )
        self.assertEqual(
            result.requests, self.monitor.app_config.default_requests_threshold
        )
        self.assertEqual(result.time, self.monitor.app_config.default_time_threshold)
        self.assertEqual(
            result.errors, self.monitor.app_config.default_errors_threshold
        )

        result = await self.monitor.average_stats_load(
            start_at=1751534999, period_in_minutes=1
        )
        self.assertEqual(result.requests, Decimal("0.02"))
        self.assertEqual(result.time, Decimal("0.17"))
        self.assertEqual(result.errors, Decimal("0.0"))

    async def test_risk_clients_fetch(self):
        result = await self.monitor.risk_clients_fetch(
            start_at=1751535000,
            period_in_seconds=10,
            requests_threshold=Decimal(1),
            time_threshold=Decimal(10),
            errors_threshold=Decimal(1),
            hashes_limit=10,
        )
        self.assertEqual(
            result,
            [User(ja5t=11, ja5h=21, ipv4=[IPv4Address("127.0.0.1")], value=1, type=0)],
        )

    def test_compare_users(self):
        generator = self.monitor.compare_users(
            new_users=[User(ja5t=11)], already_blocked=dict(), exclude_users=dict()
        )
        self.assertEqual(list(generator), [User(ja5t=11)])

    async def test_risk_clients_block(self):
        async def fake_db_response(*_, **__):

            class Response:
                result_rows = [(11, 12, "127.0.0.1", 1, 0)]

            return Response

        self.monitor.clickhouse_client.get_top_risk_clients = fake_db_response

        with self.assertRaises(ValueError):
            await self.monitor.risk_clients_block()

        self.assertEqual(len(self.monitor.blocked), 1)

    async def test_risk_clients_block_empty_list(self):
        async def fake_db_response(*_, **__):

            class Response:
                result_rows = []

            return Response

        self.monitor.clickhouse_client.get_top_risk_clients = fake_db_response

        await self.monitor.risk_clients_block()
        self.assertEqual(len(self.monitor.blocked), 0)

    async def test_risk_clients_release(self):
        blocked_at = int(time.time())
        blocked_at -= self.monitor.app_config.blocking_time_min * 60
        # to be sure
        blocked_at -= 1

        self.monitor.jat5t_block(11)
        self.monitor.blocked[hash(User(ja5t=11))].blocked_at = blocked_at

        with self.assertRaises(ValueError):
            await self.monitor.risk_clients_release()

        self.assertEqual(len(self.monitor.blocked), 0)

    async def test_risk_clients_release_empty_list(self):
        await self.monitor.risk_clients_release()
        self.assertEqual(len(self.monitor.blocked), 0)
