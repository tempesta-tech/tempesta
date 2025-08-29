import unittest

from defender.lifespan import BackgroundReleaseUsersMonitoring
from defender.context import AppContext
from blockers.base import BaseBlocker
from utils.datatypes import User
from utils.access_log import ClickhouseAccessLog
from config import AppConfig

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class FakeBlocker(BaseBlocker):
    def __init__(self):
        self.release_called = 0

    @staticmethod
    def name() -> str:
        return 'ipset'

    def prepare(self):
        return

    def block(self, user: User):
        return

    def release(self, user: User):
        self.release_called += 1

    def info(self) -> dict[int, User]:
        return {2: User(ja5t=['4444'])}

    def load(self) -> dict[int, User]:
        return {1: User(ja5t=['3333'])}


class FrozenTimeAppContext(AppContext):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.time = 0

    @property
    def utc_now(self) -> int:
        return self.time


class FlexibleTimeAppConfig(AppConfig):

    def __init__(self, *args, **kwargs):
        super(FlexibleTimeAppConfig, self).__init__(*args, **kwargs)

        self._time = 0

    @property
    def blocking_time_sec(self):
        return self._time


class TestBackgroundMonitorReleaseUsers(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.access_log = ClickhouseAccessLog()
        self.context = FrozenTimeAppContext(
            blockers={FakeBlocker.name(): FakeBlocker()},
            clickhouse_client=self.access_log,
            app_config=FlexibleTimeAppConfig(blocking_types={'ipset'})
        )
        user1 = User(ja5t=['4441'], blocked_at=1751535000)
        self.context.blocked[hash(user1)] = user1

        user2 = User(ja5t=['4442'], blocked_at=1751535005)
        self.context.blocked[hash(user2)] = user2

        user3 = User(ja5t=['4443'], blocked_at=1751535009)
        self.context.blocked[hash(user3)] = user3

        self.lifespan = BackgroundReleaseUsersMonitoring(context=self.context)

    async def test_block_time_no_passed(self):
        self.context.time = 1751535000
        self.context.app_config._time = 10

        await self.lifespan.run(testing=True)

        assert len(self.context.blocked) == 3
        assert self.context.blockers['ipset'].release_called == 0

    async def test_release_one_user(self):
        self.context.time = 1751535004
        self.context.app_config._time = 3

        await self.lifespan.run(testing=True)

        assert len(self.context.blocked) == 2
        assert self.context.blockers['ipset'].release_called == 1

    async def test_release_two_users(self):
        self.context.time = 1751535009
        self.context.app_config._time = 3

        await self.lifespan.run(testing=True)

        assert len(self.context.blocked) == 1
        assert self.context.blockers['ipset'].release_called == 2

    async def test_release_all_users(self):
        self.context.time = 1751535013
        self.context.app_config._time = 3

        await self.lifespan.run(testing=True)

        assert len(self.context.blocked) == 0
        assert self.context.blockers['ipset'].release_called == 3
