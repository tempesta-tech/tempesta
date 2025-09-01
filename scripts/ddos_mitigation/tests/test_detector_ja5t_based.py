import unittest
from decimal import Decimal
from ipaddress import IPv4Address

from detectors.ja5t import (Ja5tAccumulativeTimeDetector,
                            Ja5tErrorRequestDetector, Ja5tRPSDetector)
from utils.access_log import ClickhouseAccessLog
from utils.datatypes import User

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestBackgroundMonitorReleaseUsers(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.access_log = ClickhouseAccessLog()
        await self.access_log.connect()
        await self.access_log.conn.query("truncate table access_log")
        await self.access_log.user_agents_table_truncate()
        await self.access_log.persistent_users_table_truncate()
        await self.access_log.conn.query(
            """
            insert into access_log values
            (cast('1751535005' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751535006' as DateTime64(3, 'UTC')), '127.0.0.2', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent2', 12, 22, 0),
            (cast('1751535007' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent2', 13, 23, 0),
            (cast('1751535007' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent3', 13, 23, 0),
            (cast('1751535007' as DateTime64(3, 'UTC')), '127.0.0.4', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent4', 13, 23, 0)
            """
        )

    async def test_rps(self):
        detector = Ja5tRPSDetector(
            access_log=self.access_log,
            default_threshold=Decimal("2"),
            difference_multiplier=Decimal("10"),
        )
        users_before, users_after = await detector.find_users(
            current_time=1751535010, interval=5
        )
        assert users_before == []
        assert len(users_after) == 1
        assert users_after[0].ja5t == [13]
        assert set(users_after[0].ipv4) == set(
            [IPv4Address("127.0.0.3"), IPv4Address("127.0.0.4")]
        )

    async def test_rps_with_user_agents(self):
        await self.access_log.user_agents_table_insert([["UserAgent"], ["UserAgent4"]])
        detector = Ja5tRPSDetector(
            access_log=self.access_log,
            default_threshold=Decimal("2"),
            difference_multiplier=Decimal("10"),
        )
        users_before, users_after = await detector.find_users(
            current_time=1751535010, interval=5
        )
        assert users_before == []
        assert users_after == [
            User(ja5t=[13], ja5h=[23], ipv4=[IPv4Address("127.0.0.3")])
        ]

    async def test_rps_with_persistent_users(self):
        await self.access_log.persistent_users_table_insert(
            [
                ["127.0.0.3"],
            ]
        )
        detector = Ja5tRPSDetector(
            access_log=self.access_log,
            default_threshold=Decimal("2"),
            difference_multiplier=Decimal("10"),
        )
        users_before, users_after = await detector.find_users(
            current_time=1751535010, interval=5
        )
        assert users_before == []
        assert users_after == []

    async def test_errors(self):
        detector = Ja5tErrorRequestDetector(
            access_log=self.access_log,
            default_threshold=Decimal("2"),
            difference_multiplier=Decimal("10"),
            allowed_statues=[300],
        )
        users_before, users_after = await detector.find_users(
            current_time=1751535010, interval=5
        )
        assert users_before == []
        assert users_after == [
            User(
                ja5t=[13],
                ja5h=[23],
                ipv4=[IPv4Address("127.0.0.4"), IPv4Address("127.0.0.3")],
            )
        ]

    async def test_errors_with_user_agents(self):
        await self.access_log.user_agents_table_insert([["UserAgent"], ["UserAgent3"]])
        detector = Ja5tErrorRequestDetector(
            access_log=self.access_log,
            default_threshold=Decimal("2"),
            difference_multiplier=Decimal("10"),
            allowed_statues=[300],
        )
        users_before, users_after = await detector.find_users(
            current_time=1751535010, interval=5
        )
        assert users_before == []
        assert len(users_after) == 1
        assert users_after[0].ja5t == [13]
        assert set(users_after[0].ipv4) == set(
            [IPv4Address("127.0.0.3"), IPv4Address("127.0.0.4")]
        )

    async def test_errors_with_persistent_users(self):
        await self.access_log.persistent_users_table_insert(
            [
                ["127.0.0.3"],
            ]
        )
        detector = Ja5tErrorRequestDetector(
            access_log=self.access_log,
            default_threshold=Decimal("2"),
            difference_multiplier=Decimal("10"),
            allowed_statues=[300],
        )
        users_before, users_after = await detector.find_users(
            current_time=1751535010, interval=5
        )
        assert users_before == []
        assert users_after == []

    async def test_errors_forbidden_statuses(self):
        detector = Ja5tErrorRequestDetector(
            access_log=self.access_log,
            default_threshold=Decimal("2"),
            difference_multiplier=Decimal("10"),
            allowed_statues=[200],
        )
        users_before, users_after = await detector.find_users(
            current_time=1751535010, interval=5
        )
        assert users_before == []
        assert users_after == []

    async def test_time(self):
        detector = Ja5tAccumulativeTimeDetector(
            access_log=self.access_log,
            default_threshold=Decimal("15"),
            difference_multiplier=Decimal("10"),
        )
        users_before, users_after = await detector.find_users(
            current_time=1751535010, interval=5
        )
        assert users_before == []
        assert len(users_after) == 1
        assert users_after[0].ja5t == [13]
        assert set(users_after[0].ipv4) == set(
            [IPv4Address("127.0.0.3"), IPv4Address("127.0.0.4")]
        )

    async def test_time_with_user_agents(self):
        await self.access_log.user_agents_table_insert([["UserAgent"], ["UserAgent3"]])
        detector = Ja5tAccumulativeTimeDetector(
            access_log=self.access_log,
            default_threshold=Decimal("15"),
            difference_multiplier=Decimal("10"),
        )
        users_before, users_after = await detector.find_users(
            current_time=1751535010, interval=5
        )
        assert users_before == []
        assert len(users_after) == 1
        assert users_after[0].ja5t == [13]
        assert set(users_after[0].ipv4) == set(
            [IPv4Address("127.0.0.3"), IPv4Address("127.0.0.4")]
        )

    async def test_time_with_persistent_users(self):
        await self.access_log.persistent_users_table_insert(
            [
                ["127.0.0.3"],
            ]
        )
        detector = Ja5tAccumulativeTimeDetector(
            access_log=self.access_log,
            default_threshold=Decimal("15"),
            difference_multiplier=Decimal("10"),
        )
        users_before, users_after = await detector.find_users(
            current_time=1751535010, interval=5
        )
        assert users_before == []
        assert users_after == []
