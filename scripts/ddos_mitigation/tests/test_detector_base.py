import unittest
from decimal import Decimal
from ipaddress import IPv4Address

import pytest

from detectors.base import BaseDetector
from utils.access_log import ClickhouseAccessLog
from utils.datatypes import User

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@pytest.fixture
def detector(access_log):
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

    detector = FakeDetector(
        access_log=access_log,
        default_threshold=Decimal(0),
        difference_multiplier=Decimal(10),
    )
    yield detector


def test_name(detector):
    assert detector.name() == "ip_rps"


def test_threshold(detector):
    assert detector.threshold == Decimal("0.0")

    detector.threshold = Decimal("100.123")
    assert detector.threshold == Decimal("100.12")


async def test_find_users(detector):
    await detector.find_users(0, 10)
    assert detector.groups == [[-20, -10], [-10, 0]]


def test_arithmetic_mean(detector):
    res = detector.arithmetic_mean(
        [
            Decimal(1),
            Decimal(2),
            Decimal(3),
        ]
    )
    assert res == Decimal(2)


def test_standard_deviation(detector):
    res = detector.standard_deviation(
        values=[
            Decimal(1),
            Decimal(2),
            Decimal(3),
        ],
        arithmetic_mean=Decimal(2),
    )
    assert res == Decimal("0.82")


def test_model_validation(detector):
    res = detector.validate_model(
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


def test_model_validation_one_user(detector):
    res = detector.validate_model(
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
