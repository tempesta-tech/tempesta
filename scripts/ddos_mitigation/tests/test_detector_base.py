import unittest
from decimal import Decimal
from ipaddress import IPv4Address

from detectors.base import BaseDetector
from utils.access_log import ClickhouseAccessLog
from utils.datatypes import User

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class FakeDetector(BaseDetector):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.groups = []

    @staticmethod
    def name() -> str:
        return "ip_rps"

    async def fetch_for_period(self, start_at: int, finish_at: int) -> list[User]:
        self.groups.append([start_at, finish_at])
        return []


class TestBackgroundMonitorReleaseUsers(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.detector = FakeDetector(
            access_log=ClickhouseAccessLog(),
            default_threshold=Decimal(0),
            difference_multiplier=Decimal(10),
        )

    def test_name(self):
        assert self.detector.name() == "ip_rps"

    def test_threshold(self):
        assert self.detector.threshold == Decimal("0.0")

        self.detector.threshold = Decimal("100.123")
        assert self.detector.threshold == Decimal("100.12")

    async def test_find_users(self):
        await self.detector.find_users(0, 10)
        assert self.detector.groups == [[-20, -10], [-10, 0]]

    def test_arithmetic_mean(self):
        res = self.detector.arithmetic_mean(
            [
                Decimal(1),
                Decimal(2),
                Decimal(3),
            ]
        )
        assert res == Decimal(2)

    def test_standard_deviation(self):
        res = self.detector.standard_deviation(
            values=[
                Decimal(1),
                Decimal(2),
                Decimal(3),
            ],
            arithmetic_mean=Decimal(2),
        )
        assert res == Decimal("0.82")

    def test_model_validation(self):
        res = self.detector.validate_model(
            users_before=[
                User(ipv4=[IPv4Address("127.0.0.1")], value=Decimal(10)),
                User(ipv4=[IPv4Address("127.0.0.2")], value=Decimal(10)),
                User(ipv4=[IPv4Address("127.0.0.3")], value=Decimal(10)),
            ],
            users_after=[
                User(ipv4=[IPv4Address("127.0.0.1")], value=Decimal(100)),
                User(ipv4=[IPv4Address("127.0.0.2")], value=Decimal(100)),
                User(ipv4=[IPv4Address("127.0.0.3")], value=Decimal(100)),
            ],
        )
        assert set(res) == {
            User(ipv4=[IPv4Address("127.0.0.1")]),
            User(ipv4=[IPv4Address("127.0.0.2")]),
            User(ipv4=[IPv4Address("127.0.0.3")]),
        }

    def test_model_validation_one_user(self):
        res = self.detector.validate_model(
            users_before=[
                User(ipv4=[IPv4Address("127.0.0.1")], value=Decimal(10)),
                User(ipv4=[IPv4Address("127.0.0.2")], value=Decimal(10)),
                User(ipv4=[IPv4Address("127.0.0.3")], value=Decimal(10)),
            ],
            users_after=[
                User(ipv4=[IPv4Address("127.0.0.1")], value=Decimal(20)),
                User(ipv4=[IPv4Address("127.0.0.2")], value=Decimal(50)),
                User(ipv4=[IPv4Address("127.0.0.3")], value=Decimal(100)),
            ],
        )
        assert set(res) == {User(ipv4=[IPv4Address("127.0.0.3")])}
