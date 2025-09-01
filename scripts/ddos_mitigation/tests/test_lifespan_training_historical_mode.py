from decimal import Decimal

import pytest

from config import AppConfig
from core.context import AppContext
from core.lifespan import HistoricalModeTraining
from detectors.base import BaseDetector
from utils.datatypes import User

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@pytest.fixture
def app_config():
    class FlexibleTimeAppConfig(AppConfig):

        def __init__(self, *args, **kwargs):
            super(FlexibleTimeAppConfig, self).__init__(*args, **kwargs)

            self._duration_sec = 0

        @property
        def training_mode_duration_sec(self):
            return self._duration_sec

    config = FlexibleTimeAppConfig(detectors={"ip_rps", "ip_time"})
    yield config


@pytest.fixture
def app_context(access_log, app_config):
    class FrozenTimeAppContext(AppContext):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.time = 0

        @property
        def utc_now(self) -> int:
            return self.time

    class FakeDetector(BaseDetector):
        def __init__(self, *args, **kwargs):
            super(FakeDetector, self).__init__(*args, **kwargs)
            self.start_at = None
            self.finish_at = None

        @staticmethod
        def name() -> str:
            return "ip_rps"

        async def fetch_for_period(self, start_at: int, finish_at: int) -> list[User]:
            self.start_at = start_at
            self.finish_at = finish_at
            return [
                User(ja5t=["111"], value=Decimal(1)),
                User(ja5t=["112"], value=Decimal(2)),
                User(ja5t=["113"], value=Decimal(3)),
            ]

    class FakeDetector2(FakeDetector):
        @staticmethod
        def name() -> str:
            return "ip_time"

        async def fetch_for_period(self, start_at: int, finish_at: int) -> list[User]:
            self.start_at = start_at
            self.finish_at = finish_at
            return [
                User(ja5t=["111"], value=Decimal(100)),
                User(ja5t=["112"], value=Decimal(200)),
                User(ja5t=["113"], value=Decimal(300)),
            ]

    context = FrozenTimeAppContext(
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
        app_config=app_config,
    )
    yield context


@pytest.fixture
def lifespan(app_context):
    obj = HistoricalModeTraining(context=app_context)
    yield obj


def test_active_detectors(app_context):
    assert len(app_context.active_detectors) == 2


async def test_time_frame_before(app_context, lifespan):
    app_context.time = 1751535010
    app_context.app_config._duration_sec = 10

    await lifespan.run()

    assert app_context.detectors["ip_rps"].threshold.quantize(
        Decimal("0.01")
    ) == Decimal("2.82")
    assert app_context.detectors["ip_rps"].start_at == 1751535000
    assert app_context.detectors["ip_rps"].finish_at == 1751535010

    assert app_context.detectors["ip_time"].threshold.quantize(
        Decimal("0.01")
    ) == Decimal("281.65")
    assert app_context.detectors["ip_rps"].start_at == 1751535000
    assert app_context.detectors["ip_rps"].finish_at == 1751535010
