import pytest

from blockers.base import BaseBlocker
from config import AppConfig
from core.context import AppContext
from core.lifespan import BackgroundReleaseUsersMonitoring
from utils.datatypes import User

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@pytest.fixture
def app_config():
    class FlexibleTimeAppConfig(AppConfig):
        def __init__(self, *args, **kwargs):
            super(FlexibleTimeAppConfig, self).__init__(*args, **kwargs)

            self._time = 0

        @property
        def blocking_time_sec(self):
            return self._time

    config = FlexibleTimeAppConfig(blocking_types={"ipset"})
    yield config


@pytest.fixture
def app_context(app_config, access_log):
    class FakeBlocker(BaseBlocker):
        def __init__(self):
            self.release_called = 0

        @staticmethod
        def name() -> str:
            return "ipset"

        def prepare(self):
            return

        def block(self, user: User):
            return

        def release(self, user: User):
            self.release_called += 1

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

    context = FrozenTimeAppContext(
        blockers={FakeBlocker.name(): FakeBlocker()},
        clickhouse_client=access_log,
        app_config=app_config,
    )
    yield context


@pytest.fixture
def lifespan(app_context):
    user1 = User(ja5t=["4441"], blocked_at=1751535000)
    app_context.blocked[hash(user1)] = user1

    user2 = User(ja5t=["4442"], blocked_at=1751535005)
    app_context.blocked[hash(user2)] = user2

    user3 = User(ja5t=["4443"], blocked_at=1751535009)
    app_context.blocked[hash(user3)] = user3

    yield BackgroundReleaseUsersMonitoring(context=app_context)


async def test_block_time_no_passed(app_context, lifespan):
    app_context.time = 1751535000
    app_context.app_config._time = 10

    await lifespan.run(testing=True)

    assert len(app_context.blocked) == 3
    assert app_context.blockers["ipset"].release_called == 0


async def test_release_one_user(app_context, lifespan):
    app_context.time = 1751535004
    app_context.app_config._time = 3

    await lifespan.run(testing=True)

    assert len(app_context.blocked) == 2
    assert app_context.blockers["ipset"].release_called == 1


async def test_release_two_users(app_context, lifespan):
    app_context.time = 1751535009
    app_context.app_config._time = 3

    await lifespan.run(testing=True)

    assert len(app_context.blocked) == 1
    assert app_context.blockers["ipset"].release_called == 2


async def test_release_all_users(app_context, lifespan):
    app_context.time = 1751535013
    app_context.app_config._time = 3

    await lifespan.run(testing=True)

    assert len(app_context.blocked) == 0
    assert app_context.blockers["ipset"].release_called == 3
