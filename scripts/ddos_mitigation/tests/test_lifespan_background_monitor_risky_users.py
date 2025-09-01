from decimal import Decimal

import pytest
from clickhouse_connect.driverc.dataconv import IPv4Address

from blockers.base import BaseBlocker
from config import AppConfig
from core.context import AppContext
from core.lifespan import BackgroundRiskyUsersMonitoring
from detectors.base import BaseDetector
from utils.datatypes import User

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@pytest.fixture
async def app_context(access_log):
    class FakeBlocker(BaseBlocker):
        def __init__(self):
            self.prepare_called = False
            self.block_called = 0

        @staticmethod
        def name() -> str:
            return "ipset"

        def prepare(self):
            self.prepare_called = True

        def block(self, user: User):
            self.block_called += 1

        def release(self, user: User):
            return

        def info(self) -> dict[int, User]:
            return {2: User(ja5t=["4444"])}

        def load(self) -> dict[int, User]:
            return {1: User(ja5t=["3333"])}

    class FrozenTimeAppContext(AppContext):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.time = 0

        @property
        def utc_now(self) -> int:
            return self.time

    class FakeDetector(BaseDetector):
        groups = [
            [
                User(ja5t=["111"], value=Decimal(1), ipv4=[IPv4Address("127.0.0.1")]),
                User(ja5t=["112"], value=Decimal(2), ipv4=[IPv4Address("127.0.0.2")]),
                User(ja5t=["113"], value=Decimal(3), ipv4=[IPv4Address("127.0.0.3")]),
            ],
            [
                User(ja5t=["111"], value=Decimal(1), ipv4=[IPv4Address("127.0.0.1")]),
                User(ja5t=["112"], value=Decimal(2), ipv4=[IPv4Address("127.0.0.2")]),
                User(ja5t=["113"], value=Decimal(3), ipv4=[IPv4Address("127.0.0.3")]),
            ],
        ]

        def __init__(self, *args, **kwargs):
            super(FakeDetector, self).__init__(*args, **kwargs)
            self.passed_time = []

        @staticmethod
        def name() -> str:
            return "ip_rps"

        async def fetch_for_period(self, start_at: int, finish_at: int) -> list[User]:
            self.passed_time.append((start_at, finish_at))
            head, *self.groups = self.groups
            return head

    class FakeDetector2(FakeDetector):
        groups = [
            [
                User(ja5t=["211"], value=Decimal(1), ipv4=[IPv4Address("127.0.0.1")]),
                User(ja5t=["212"], value=Decimal(2), ipv4=[IPv4Address("127.0.0.2")]),
                User(ja5t=["213"], value=Decimal(3), ipv4=[IPv4Address("127.0.0.3")]),
            ],
            [
                User(ja5t=["211"], value=Decimal(5), ipv4=[IPv4Address("127.0.0.1")]),
                User(ja5t=["212"], value=Decimal(10), ipv4=[IPv4Address("127.0.0.2")]),
                User(ja5t=["213"], value=Decimal(30), ipv4=[IPv4Address("127.0.0.3")]),
            ],
        ]

        @staticmethod
        def name() -> str:
            return "ip_time"

    context = FrozenTimeAppContext(
        blockers={FakeBlocker.name(): FakeBlocker()},
        detectors={
            FakeDetector.name(): FakeDetector(
                access_log=access_log,
                default_threshold=Decimal(1),
                difference_multiplier=Decimal(10),
            ),
            FakeDetector2.name(): FakeDetector2(
                access_log=access_log,
                default_threshold=Decimal(20),
                difference_multiplier=Decimal(10),
            ),
        },
        clickhouse_client=access_log,
        app_config=AppConfig(detectors={"ip_rps", "ip_time"}, blocking_types={"ipset"}),
    )
    yield context


@pytest.fixture
async def lifespan(app_context):
    lifespan = BackgroundRiskyUsersMonitoring(context=app_context)
    yield lifespan


def test_active_detectors(app_context):
    assert len(app_context.active_detectors) == 2


async def test_block_users(app_context, lifespan):
    app_context.time = 1751535020

    await lifespan.run(testing=True)

    assert app_context.detectors["ip_rps"].passed_time == [
        (1751535000, 1751535010),
        (1751535010, 1751535020),
    ]
    assert app_context.detectors["ip_rps"].threshold == Decimal("2.82")

    assert app_context.detectors["ip_time"].passed_time == [
        (1751535000, 1751535010),
        (1751535010, 1751535020),
    ]
    assert app_context.detectors["ip_time"].threshold == Decimal("25.80")

    assert app_context.blockers["ipset"].block_called == 1
    assert list(app_context.blocked.values()) == [
        User(ja5t=["213"], ipv4=[IPv4Address("127.0.0.3")])
    ]
