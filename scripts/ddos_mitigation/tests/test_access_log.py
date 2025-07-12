import math
import unittest
from decimal import Decimal
from ipaddress import IPv4Address

from access_log import ClickhouseAccessLog

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestClickhouseClient(unittest.IsolatedAsyncioTestCase):
    async def asyncTearDown(self):
        await self.client.conn.query("drop database test_db")

    async def asyncSetUp(self):
        self.client = ClickhouseAccessLog()
        await self.client.connect()
        await self.client.conn.query("drop database if exists test_db")

        await self.client.conn.query("create database test_db")
        await self.client.conn.query(
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
        await self.client.conn.query(
            """
            insert into test_db.access_log values 
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 13, 23, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.2', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.2', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.2', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 13, 23, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 20, 'default', '/', '/', 'UserAgent', 13, 23, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.4', 0, 1, 400, 0, 10, 'default', '/', '/', 'UserAgent', 14, 24, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.4', 0, 1, 400, 0, 10, 'default', '/', '/', 'UserAgent', 14, 24, 0),
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.5', 0, 1, 200, 0, 0,  'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751535100' as DateTime64(3, 'UTC')), '127.0.0.5', 0, 1, 200, 0, 0,  'default', '/', '/', 'UserAgent', 12, 22, 0)
            """
        )

    async def test_get_top_risk_clients_out_of_time_period(self):
        response = await self.client.get_top_risk_clients(
            start_at=1751536000,
            period_in_seconds=1,
            rps_threshold=Decimal(4),
            errors_threshold=Decimal(2),
            time_threshold=Decimal(40),
            ja5_hashes_limit=10
        )
        self.assertEqual(response.result_rows, [])

    async def test_get_top_risk_clients(self):
        response = await self.client.get_top_risk_clients(
            start_at=1751535000,
            period_in_seconds=60,
            rps_threshold=Decimal(4),
            errors_threshold=Decimal(2),
            time_threshold=Decimal(40),
            ja5_hashes_limit=10
        )
        self.assertEqual(
            response.result_rows,
            [
                (
                    12,
                    22,
                    [
                        IPv4Address("127.0.0.2"),
                        IPv4Address("127.0.0.3"),
                        IPv4Address("127.0.0.1"),
                        IPv4Address("127.0.0.5"),
                    ],
                    4,
                    0,
                ),
                (
                    13,
                    23,
                    [
                        IPv4Address("127.0.0.2"),
                        IPv4Address("127.0.0.3"),
                        IPv4Address("127.0.0.1"),
                    ],
                    40,
                    1,
                ),
                (14, 24, [IPv4Address("127.0.0.4")], 2, 2),
            ],
        )

    async def test_get_stats_out_of_time_period(self):
        response = await self.client.get_request_stats_for_period(
            start_at=1751536000,
            period_in_minutes=1,
        )
        self.assertTrue(math.isnan(response.result_rows[0][0]))
        self.assertTrue(math.isnan(response.result_rows[1][0]))
        self.assertTrue(math.isnan(response.result_rows[2][0]))

    async def test_get_stats(self):
        response = await self.client.get_request_stats_for_period(
            start_at=1751534999,
            period_in_minutes=1,
        )
        # requests avr( ja5=11 (3), ja5=12 (4), ja5=13 (3), ja5=14(2) ) = 12/4 = 3
        # time avr( ja5=11 (30), ja5=12 (30), ja5=13 (40), ja5=14(20) ) = 120/4 = 30
        # errors avr( ja5=11 (0), ja5=12 (0), ja5=13 (0), ja5=14(2) ) = 2/4 = 0.5

        self.assertEqual(response.result_rows, [(3.0, 0), (30.0, 1), (0.5, 2)])
