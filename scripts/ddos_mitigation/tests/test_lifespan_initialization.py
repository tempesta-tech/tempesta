import os
import unittest
from defender.lifespan import Initialization
from blockers.base import BaseBlocker
from defender.context import AppContext
from clickhouse_connect.driver.httpclient import DatabaseError

from utils.datatypes import User
from utils.user_agents import UserAgentsManager
from utils.access_log import ClickhouseAccessLog
from config import AppConfig

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class FakeBlocker(BaseBlocker):
    def __init__(self):
        self.prepare_called = False

    @staticmethod
    def name() -> str:
        return 'ipset'

    def prepare(self):
        self.prepare_called = True

    def block(self, user: User):
        return

    def release(self, user: User):
        return

    def info(self) -> dict[int, User]:
        return {2: User(ja5t=['4444'])}

    def load(self) -> dict[int, User]:
        return {1: User(ja5t=['3333'])}


class FakeBlocker2(FakeBlocker):
    @staticmethod
    def name() -> str:
        return 'ja5t'


class TestLifespanInitialization(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.access_log = ClickhouseAccessLog()
        await self.access_log.connect()

        await self.access_log.user_agents_table_drop()
        await self.access_log.persistent_users_table_drop()

        self.user_agent_empty_file_path = "/tmp/test_user_agents_loading_0"
        self.user_agent_file_path = "/tmp/test_user_agents_loading"

        with open(self.user_agent_empty_file_path, "w") as f:
            f.write("")

        with open(self.user_agent_file_path, "w") as f:
            f.write('user1\nuser2\nuser3\n')

        self.context = AppContext(
            blockers={
                FakeBlocker.name(): FakeBlocker(),
                FakeBlocker2.name(): FakeBlocker2()
            },
            clickhouse_client=self.access_log,
            app_config=AppConfig(blocking_types={'ipset'}),
            user_agent_manager=UserAgentsManager(
                clickhouse_client=self.access_log,
                config_path=self.user_agent_empty_file_path
            ))
        self.lifespan = Initialization(context=self.context)

    def tearDown(self):
        if os.path.exists(self.user_agent_file_path):
            os.remove(self.user_agent_file_path)

        if os.path.exists(self.user_agent_empty_file_path):
            os.remove(self.user_agent_empty_file_path)

    def test_active_blockers(self):
        assert len(self.context.active_blockers) == 1

    async def test_clickhouse_connection(self):
        with self.assertRaises(DatabaseError):
            await self.context.clickhouse_client.user_agents_all()

        await self.lifespan.run()
        await self.context.clickhouse_client.user_agents_all()

    async def test_blockers_loading(self):
        assert len(self.context.blocked) == 0
        assert self.context.blockers['ipset'].prepare_called is False

        await self.lifespan.run()

        assert self.context.blockers['ipset'].prepare_called is True
        assert len(self.context.blocked) == 1

    async def test_tables_creation(self):
        with self.assertRaises(DatabaseError):
            await self.access_log.user_agents_all()

        with self.assertRaises(DatabaseError):
            await self.access_log.persistent_users_all()

        await self.lifespan.run()

        result = await self.access_log.user_agents_all()
        assert len(result.result_rows) == 0

        result = await self.access_log.persistent_users_all()
        assert len(result.result_rows) == 0

    async def test_user_agents_loading(self):
        self.context.user_agent_manager.config_path = self.user_agent_file_path
        await self.lifespan.run()

        result = await self.access_log.user_agents_all()
        assert len(result.result_rows) == 3

    async def test_user_agents_loading_skip(self):
        self.context.app_config.allowed_user_agents_file_path = False
        await self.lifespan.run()

        result = await self.access_log.user_agents_all()
        assert len(result.result_rows) == 0
