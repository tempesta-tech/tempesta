from decimal import Decimal

from clickhouse_connect.driverc.dataconv import IPv4Address

from defender import User
from detectors.threshold import ThresholdDetector
from tests.base import BaseTestCaseWithFilledDB

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestThresholdDetector(BaseTestCaseWithFilledDB):
    async def asyncSetUp(self):
        await super().asyncSetUp()

        self.detector = ThresholdDetector(
            app_config=self.app_config, clickhouse_client=self.access_log
        )

    def test_set_thresholds(self):
        self.detector.set_thresholds(
            requests_threshold=Decimal(1),
            time_threshold=Decimal(2),
            errors_threshold=Decimal(3),
        )
        self.assertEqual(self.detector.requests_threshold, 1)
        self.assertEqual(self.detector.time_threshold, 2)
        self.assertEqual(self.detector.errors_threshold, 3)

    async def test_set_known_users(self):
        risk_user = User(ja5t="1")
        self.detector.set_known_users([risk_user])
        self.assertEqual(len(self.detector.known_users), 1)
        self.assertIn(hash(risk_user), self.detector.known_users)

    async def test_persistent_users_load(self):
        result = await self.detector.persistent_users_load(
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
                    ja5t="11",
                    ja5h="21",
                    ipv4=[IPv4Address("127.0.0.1")],
                    value=None,
                    type=None,
                    blocked_at=None,
                )
            ],
        )

    async def test_average_stats_load(self):
        result = await self.detector.average_stats_load(
            start_at=1751535000, period_in_minutes=1
        )
        self.assertEqual(
            result.requests, self.detector.app_config.default_requests_threshold
        )
        self.assertEqual(result.time, self.detector.app_config.default_time_threshold)
        self.assertEqual(
            result.errors, self.detector.app_config.default_errors_threshold
        )

        self.detector.app_config.stats_rps_precision = Decimal("0.01")
        self.detector.app_config.stats_time_precision = Decimal("0.01")

        result = await self.detector.average_stats_load(
            start_at=1751534999, period_in_minutes=1
        )
        self.assertEqual(result.requests, Decimal("0.02"))
        self.assertEqual(result.time, Decimal("0.17"))
        self.assertEqual(result.errors, Decimal("0.0"))

    async def test_find_users(self):
        self.detector.app_config.blocking_window_duration_sec = 10
        self.detector.requests_threshold = Decimal(1)
        self.detector.time_threshold = Decimal(10)
        self.detector.errors_threshold = Decimal(1)
        self.detector.app_config.blocking_ja5_limit = 10

        result = await self.detector.find_users(
            current_time=1751535000,
        )
        self.assertEqual(
            result,
            [
                User(
                    ja5t="b",
                    ja5h="15",
                    ipv4=[IPv4Address("127.0.0.1")],
                    value=1,
                    type=0,
                )
            ],
        )

    def test_compare_users(self):
        generator = self.detector.compare_users(
            new_users=[User(ja5t="11")], exclude_users=dict()
        )
        self.assertEqual(list(generator), [User(ja5t="11")])

    async def test_prepare_without_analisys(self):
        await self.detector.prepare()

    async def test_prepare_historical_mode(self):
        self.detector.app_config.training_mode = "historical"
        self.detector.app_config.training_mode_duration_min = 1
        self.detector.seconds_in_minute = 1
        await self.detector.prepare()

    async def test_prepare_real_mode(self):
        self.detector.app_config.training_mode = "real"
        self.detector.app_config.training_mode_duration_min = 1
        self.detector.seconds_in_minute = 1
        await self.detector.prepare()
