import math
from decimal import Decimal
from ipaddress import IPv4Address

from tests.base import BaseTestCaseWithFilledDB

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestClickhouseClient(BaseTestCaseWithFilledDB):
    # async def create_records(self):
    #     await self.access_log.conn.query(
    #         """
    #         insert into test_db.access_log values
    #         (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
    #         (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
    #         (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 13, 23, 0),
    #         (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.2', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
    #         (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.2', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
    #         (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.2', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 13, 23, 0),
    #         (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
    #         (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
    #         (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 20, 'default', '/', '/', 'UserAgent', 13, 23, 0),
    #         (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.4', 0, 1, 400, 0, 10, 'default', '/', '/', 'UserAgent', 14, 24, 0),
    #         (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.4', 0, 1, 400, 0, 10, 'default', '/', '/', 'UserAgent', 14, 24, 0),
    #         (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.5', 0, 1, 200, 0, 0,  'default', '/', '/', 'UserAgent', 12, 22, 0),
    #         (cast('1751535100' as DateTime64(3, 'UTC')), '127.0.0.5', 0, 1, 200, 0, 0,  'default', '/', '/', 'UserAgent', 12, 22, 0)
    #         """
    #     )
    #
    # async def test_get_top_risk_clients_out_of_time_period(self):
    #     response = await self.access_log.get_top_risk_clients(
    #         start_at=1751536000,
    #         period_in_seconds=1,
    #         rps_threshold=Decimal(4),
    #         errors_threshold=Decimal(2),
    #         time_threshold=Decimal(40),
    #         ja5_hashes_limit=10,
    #         legal_response_statuses=[200],
    #     )
    #     self.assertEqual(response.result_rows, [])
    #
    # async def test_get_top_risk_clients(self):
    #     response = await self.access_log.get_top_risk_clients(
    #         start_at=1751535000,
    #         period_in_seconds=60,
    #         rps_threshold=Decimal(4),
    #         errors_threshold=Decimal(2),
    #         time_threshold=Decimal(40),
    #         ja5_hashes_limit=10,
    #         legal_response_statuses=[200],
    #     )
    #     self.assertEqual(
    #         response.result_rows,
    #         [
    #             (
    #                 12,
    #                 22,
    #                 [
    #                     IPv4Address("127.0.0.2"),
    #                     IPv4Address("127.0.0.3"),
    #                     IPv4Address("127.0.0.1"),
    #                     IPv4Address("127.0.0.5"),
    #                 ],
    #                 4,
    #                 0,
    #             ),
    #             (
    #                 13,
    #                 23,
    #                 [
    #                     IPv4Address("127.0.0.2"),
    #                     IPv4Address("127.0.0.3"),
    #                     IPv4Address("127.0.0.1"),
    #                 ],
    #                 40,
    #                 1,
    #             ),
    #             (14, 24, [IPv4Address("127.0.0.4")], 2, 2),
    #         ],
    #     )
    #
    # async def test_get_top_risk_clients_not_allowed_statuses(self):
    #     response = await self.access_log.get_top_risk_clients(
    #         start_at=1751535000,
    #         period_in_seconds=60,
    #         rps_threshold=Decimal(4),
    #         errors_threshold=Decimal(2),
    #         time_threshold=Decimal(40),
    #         ja5_hashes_limit=10,
    #         legal_response_statuses=[201],
    #     )
    #
    #     self.assertEqual(
    #         response.result_rows,
    #         [
    #             (
    #                 12,
    #                 22,
    #                 [
    #                     IPv4Address("127.0.0.2"),
    #                     IPv4Address("127.0.0.3"),
    #                     IPv4Address("127.0.0.1"),
    #                     IPv4Address("127.0.0.5"),
    #                 ],
    #                 4,
    #                 0,
    #             ),
    #             (
    #                 13,
    #                 23,
    #                 [
    #                     IPv4Address("127.0.0.2"),
    #                     IPv4Address("127.0.0.3"),
    #                     IPv4Address("127.0.0.1"),
    #                 ],
    #                 40,
    #                 1,
    #             ),
    #             (
    #                 11,
    #                 21,
    #                 [
    #                     IPv4Address("127.0.0.2"),
    #                     IPv4Address("127.0.0.3"),
    #                     IPv4Address("127.0.0.1"),
    #                 ],
    #                 3,
    #                 2,
    #             ),
    #             (14, 24, [IPv4Address("127.0.0.4")], 2, 2),
    #         ],
    #     )
    #
    # async def test_get_stats_out_of_time_period(self):
    #     response = await self.access_log.get_request_stats_for_period(
    #         start_at=1751536000, period_in_minutes=1, legal_response_statuses=[200]
    #     )
    #     self.assertTrue(math.isnan(response.result_rows[0][0]))
    #     self.assertTrue(math.isnan(response.result_rows[1][0]))
    #     self.assertTrue(math.isnan(response.result_rows[2][0]))
    #
    # async def test_get_stats(self):
    #     response = await self.access_log.get_request_stats_for_period(
    #         start_at=1751534999, period_in_minutes=1, legal_response_statuses=[200]
    #     )
    #     # requests avr( ja5=11 (3), ja5=12 (4), ja5=13 (3), ja5=14(2) ) = 12/4 = 3
    #     # time avr( ja5=11 (30), ja5=12 (30), ja5=13 (40), ja5=14(20) ) = 120/4 = 30
    #     # errors avr( ja5=11 (0), ja5=12 (0), ja5=13 (0), ja5=14(2) ) = 2/4 = 0.5
    #
    #     self.assertEqual(response.result_rows, [(3.0, 0), (30.0, 1), (0.5, 2)])
    #
    # async def test_get_stats_no_allowed_statuses(self):
    #     response = await self.access_log.get_request_stats_for_period(
    #         start_at=1751534999, period_in_minutes=1, legal_response_statuses=[201]
    #     )
    #     # all responses are illegal
    #     self.assertEqual(response.result_rows, [(3.0, 0), (30.0, 1), (3, 2)])
    #
    async def test_create_user_agents_table(self):
        await self.access_log.user_agents_table_create()
        items = await self.access_log.user_agents_all()
        self.assertEqual(len(items.result_rows), 0)

    async def test_insert_into_user_agents_table(self):
        await self.access_log.user_agents_table_insert(
            [["TestUserAgent"], ["HelloKitty"]]
        )
        items = await self.access_log.user_agents_all()
        self.assertEqual(len(items.result_rows), 2)

    async def test_create_persistent_user_table(self):
        await self.access_log.persistent_users_table_create()
        items = await self.access_log.persistent_users_all()
        self.assertEqual(len(items.result_rows), 0)

    async def test_insert_into_persistent_user_table(self):
        await self.access_log.persistent_users_table_insert(
            [["127.0.0.1"], ["fa00::01"]]
        )
        items = await self.access_log.persistent_users_all()
        self.assertEqual(len(items.result_rows), 2)
