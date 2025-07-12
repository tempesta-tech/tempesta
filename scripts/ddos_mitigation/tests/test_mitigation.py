import unittest
import os
import urllib
from decimal import Decimal

from clickhouse_connect.driverc.dataconv import IPv4Address

from mitigator import DDOSMonitor, RiskUser
from ja5_config import Ja5Config, Ja5Hash
from access_log import ClickhouseAccessLog
from config import AppConfig
from http.server import BaseHTTPRequestHandler, HTTPServer
import multiprocessing
import time
from urllib.request import urlopen


class TestMitigation(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.access_log = ClickhouseAccessLog()
        await self.access_log.connect()
        await self.access_log.conn.query('create database test_db')
        await self.access_log.conn.query(
            """
            CREATE TABLE IF NOT EXISTS test_db.access_log (
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
        await self.access_log.conn.query(
            """
            insert into test_db.access_log values 
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751536000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751537000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 400, 0, 10, 'default', '/', '/', 'UserAgent', 13, 23, 0)
            """
        )
        self.ja5t_config_path = '/tmp/test_ja5t_config'
        self.ja5h_config_path = '/tmp/test_ja5h_config'

        open(self.ja5t_config_path, 'w').close()
        open(self.ja5h_config_path, 'w').close()

        self.ja5t_config = Ja5Config(self.ja5t_config_path)
        self.ja5h_config = Ja5Config(self.ja5h_config_path)

        self.monitor = DDOSMonitor(
            clickhouse_client=self.access_log,
            ja5t_config=self.ja5t_config,
            ja5h_config=self.ja5h_config,
            app_config=AppConfig(),
        )
        try:
            self.monitor.reset_ipset()
        except Exception as e:
            if "doesn't exist" not in str(e):
                print('cant not reset ipset ', e)

        try:
            self.monitor.reset_nftables()
        except Exception as e:
            if "No such file" not in str(e):
                print('cant reset nftables ', e)

    async def asyncTearDown(self):
        os.remove(self.ja5t_config_path)
        os.remove(self.ja5h_config_path)

        await self.access_log.conn.query('drop database if exists test_db')

    def test_hash_risk_user_function(self):
        risk_user_1 = RiskUser(ja5t=1)
        risk_user_2 = RiskUser(ja5t=2)
        risk_user_3 = RiskUser(ja5t=2)

        self.assertEqual(hash(risk_user_2), hash(risk_user_3))
        self.assertNotEqual(hash(risk_user_1), hash(risk_user_3))

    def test_set_thresholds(self):
        self.monitor.set_thresholds(
            requests_threshold=1,
            time_threshold=2,
            errors_threshold=3
        )
        self.assertEqual(self.monitor.requests_threshold, 1)
        self.assertEqual(self.monitor.time_threshold, 2)
        self.assertEqual(self.monitor.errors_threshold, 3)

    async def test_set_known_users(self):
        risk_user = RiskUser(ja5t=1)
        self.monitor.set_known_users([risk_user])
        self.assertEqual(len(self.monitor.known_users), 1)
        self.assertIn(hash(risk_user), self.monitor.known_users)

    def test_load_blocked_users_from_ja5t_hashes(self):
        self.monitor.load_blocked_users_from_ja5t_hashes([1, 2, 3])
        self.assertEqual(len(self.monitor.blocked), 3)
        self.assertEqual(
            set(self.monitor.blocked.values()),
            {RiskUser(ja5t=1), RiskUser(ja5t=2), RiskUser(ja5t=3)}
        )

    def test_load_blocked_users_from_ja5h_hashes(self):
        self.monitor.load_blocked_users_from_ja5h_hashes([1, 2, 3])
        self.assertEqual(len(self.monitor.blocked), 3)
        self.assertEqual(
            set(self.monitor.blocked.values()),
            {RiskUser(ja5h=1), RiskUser(ja5h=2), RiskUser(ja5h=3)}
        )

    def test_block_and_unblock_by_ja5t(self):
        self.monitor.block_by_ja5t(1)
        self.assertEqual(len(self.monitor.blocked), 1)
        self.assertEqual(list(self.monitor.blocked.values())[0], RiskUser(ja5t=1))

        self.monitor.unblock_by_ja5t(1)
        self.assertEqual(len(self.monitor.blocked), 0)

    def test_block_and_unblock_by_ja5h(self):
        self.monitor.block_by_ja5h(1)
        self.assertEqual(len(self.monitor.blocked), 1)
        self.assertEqual(list(self.monitor.blocked.values())[0], RiskUser(ja5h=1))

        self.monitor.unblock_by_ja5h(1)
        self.assertEqual(len(self.monitor.blocked), 0)

    def test_block_and_unblock_by_ip_with_ipset(self):
        self.monitor.prepare_ipset()

        self.monitor.block_by_ip_with_ipset(['127.0.0.2', '127.0.0.3'])
        self.monitor.block_by_ip_with_ipset(['127.0.0.4'])

        ipset_info = self.monitor.get_ipset_info()
        self.assertIn('127.0.0.2', ipset_info)
        self.assertIn('127.0.0.3', ipset_info)
        self.assertIn('127.0.0.4', ipset_info)

        self.monitor.unblock_by_ip_with_ipset(['127.0.0.2', '127.0.0.3'])
        self.monitor.unblock_by_ip_with_ipset(['127.0.0.4'])

        ipset_info = self.monitor.get_ipset_info()
        self.assertNotIn('127.0.0.2', ipset_info)
        self.assertNotIn('127.0.0.3', ipset_info)
        self.assertNotIn('127.0.0.4', ipset_info)

        self.monitor.reset_ipset()

    def run_http_server(self):
        class SimpleHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"OK")

        with HTTPServer(('127.0.0.1', 8000), SimpleHandler) as httpd:
            httpd.serve_forever()

    def test_iptables_rules_work(self):
        process = multiprocessing.Process(target=self.run_http_server)
        process.start()

        time.sleep(0.1)

        response = urlopen("http://localhost:8000")
        self.assertEqual(response.getcode(), 200)

        self.monitor.prepare_ipset()

        self.monitor.block_by_ip_with_ipset(['127.0.0.1'])
        self.assertRaises(urllib.error.URLError, urlopen, "http://localhost:8000", timeout=0.1)

        self.monitor.unblock_by_ip_with_ipset(['127.0.0.1'])
        response = urlopen("http://localhost:8000", timeout=0.1)
        self.assertEqual(response.getcode(), 200)

        process.terminate()
        process.join()
        self.monitor.reset_ipset()

    def test_block_unblock_by_ip_with_nftables(self):
        self.monitor.prepare_nftables()

        self.monitor.block_by_ip_with_nftables(['127.0.0.2', '127.0.0.3'])
        self.monitor.block_by_ip_with_nftables(['127.0.0.4'])

        nft_info = self.monitor.get_info_about_nftables()
        self.assertIn('127.0.0.2', nft_info)
        self.assertIn('127.0.0.3', nft_info)
        self.assertIn('127.0.0.4', nft_info)

        self.monitor.unblock_by_ip_with_nftables(['127.0.0.2', '127.0.0.3'])
        self.monitor.unblock_by_ip_with_nftables(['127.0.0.4'])

        nft_info = self.monitor.get_info_about_nftables()
        self.assertNotIn('127.0.0.2', nft_info)
        self.assertNotIn('127.0.0.3', nft_info)
        self.assertNotIn('127.0.0.4', nft_info)

        self.monitor.reset_nftables()

    def test_nftable_rules_work(self):
        process = multiprocessing.Process(target=self.run_http_server)
        process.start()

        time.sleep(0.1)

        response = urlopen("http://localhost:8000")
        self.assertEqual(response.getcode(), 200)

        self.monitor.prepare_nftables()

        self.monitor.block_by_ip_with_nftables(['127.0.0.1'])
        self.assertRaises(urllib.error.URLError, urlopen, "http://localhost:8000", timeout=0.1)

        self.monitor.unblock_by_ip_with_nftables(['127.0.0.1'])
        response = urlopen("http://localhost:8000", timeout=0.1)
        self.assertEqual(response.getcode(), 200)

        process.terminate()
        process.join()
        self.monitor.reset_nftables()

    async def test_load_last_real_users(self):
        result = await self.monitor.load_last_real_users(
            start_at=1751535000,
            time_long=10,
            requests_amount=1,
            time_amount=1,
            users_amount=1
        )
        self.assertEqual(
            result,
            [RiskUser(
                ja5t=11,
                ja5h=21,
                ipv4=[IPv4Address('127.0.0.1')],
                value=None,
                type=None,
                blocked_at=None
            )]
        )

    async def test_get_stats_for_period(self):
        result = await self.monitor.get_stats_for_period(
            time_from=1751535000,
            period_in_minutes=1
        )
        self.assertEqual(result.requests, self.monitor.app_config.default_requests_threshold)
        self.assertEqual(result.time, self.monitor.app_config.default_time_threshold)
        self.assertEqual(result.errors, self.monitor.app_config.default_errors_threshold)

        result = await self.monitor.get_stats_for_period(
            time_from=1751534999,
            period_in_minutes=1
        )
        self.assertEqual(result.requests, Decimal('0.02'))
        self.assertEqual(result.time, Decimal('0.17'))
        self.assertEqual(result.errors, Decimal('0.0'))

    async def test_get_risk_clients(self):
        result = await self.monitor.get_risk_clients(
            time_from=1751535000,
            time_frame_seconds=10,
            requests_threshold=1,
            time_threshold=10,
            errors_threshold=1,
            hashes_limit=10
        )
        self.assertEqual(
            result,
            [
                RiskUser(
                    ja5t=11,
                    ja5h=21,
                    ipv4=[IPv4Address('127.0.0.1')],
                    value=1,
                    type=0
                )
            ]
        )

    def test_compare_users(self):
        generator = self.monitor.compare_users(
            new_users=[
                RiskUser(ja5t=11)
            ],
            already_blocked=dict(),
            exclude_users=dict()
        )
        self.assertEqual(list(generator), [RiskUser(ja5t=11)])

    async def test_find_new_risk_users(self):
        async def fake_db_response(*_, **__):

            class Response:
                result_rows = [(11, 12, '127.0.0.1', 1, 0)]

            return Response

        self.monitor.clickhouse_client.get_top_risk_clients = fake_db_response

        with self.assertRaises(ValueError):
            await self.monitor.find_new_risk_users()

        self.assertEqual(len(self.monitor.blocked), 1)

    async def test_release_blocked_users(self):
        blocked_at = int(time.time())
        blocked_at -= self.monitor.app_config.blocking_default_time_minutes * 60
        # to be sure
        blocked_at -= 1

        self.monitor.block_by_ja5t(11)
        self.monitor.blocked[hash(RiskUser(ja5t=11))].blocked_at = blocked_at

        with self.assertRaises(ValueError):
            await self.monitor.release_blocked_users()

        self.assertEqual(len(self.monitor.blocked), 0)
