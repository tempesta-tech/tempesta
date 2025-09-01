import os

import pytest
from clickhouse_connect.driver.httpclient import DatabaseError

from blockers.base import BaseBlocker
from config import AppConfig
from core.context import AppContext
from core.lifespan import Initialization
from utils.datatypes import User
from utils.user_agents import UserAgentsManager

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@pytest.fixture(autouse=True)
async def user_agent_empty_file_path() -> str:
    path = "/tmp/test_user_agents_loading_0"
    open(path, "w").close()

    yield path

    if os.path.exists(path):
        os.remove(path)


@pytest.fixture(autouse=True)
async def user_agent_file_path() -> str:
    path = "/tmp/test_user_agents_loading"

    with open(path, "w") as f:
        f.write("user1\nuser2\nuser3\n")

    yield path

    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
async def app_context(access_log, user_agent_empty_file_path) -> AppContext:
    await access_log.conn.query("drop table user_agents")
    await access_log.conn.query("drop table persistent_users")

    class FakeBlocker(BaseBlocker):
        def __init__(self):
            self.prepare_called = False

        @staticmethod
        def name() -> str:
            return "ipset"

        def prepare(self):
            self.prepare_called = True

        def block(self, user: User):
            return

        def release(self, user: User):
            return

        def info(self) -> dict[int, User]:
            return {2: User(ja5t=["4444"])}

        def load(self) -> dict[int, User]:
            return {1: User(ja5t=["3333"])}

    class FakeBlocker2(FakeBlocker):
        @staticmethod
        def name() -> str:
            return "ja5t"

    context = AppContext(
        blockers={
            FakeBlocker.name(): FakeBlocker(),
            FakeBlocker2.name(): FakeBlocker2(),
        },
        clickhouse_client=access_log,
        app_config=AppConfig(blocking_types={"ipset"}),
        user_agent_manager=UserAgentsManager(
            clickhouse_client=access_log,
            config_path=user_agent_empty_file_path,
        ),
    )
    yield context

    await access_log.user_agents_table_create()
    await access_log.persistent_users_table_create()


@pytest.fixture
async def lifespan(access_log, app_context) -> Initialization:
    lifespan = Initialization(context=app_context)
    yield lifespan


def test_active_blockers(app_context):
    assert len(app_context.active_blockers) == 1


async def test_clickhouse_connection(app_context, lifespan):
    with pytest.raises(DatabaseError):
        await app_context.clickhouse_client.user_agents_all()

    await lifespan.run()
    await app_context.clickhouse_client.user_agents_all()


async def test_blockers_loading(app_context, lifespan):
    assert len(app_context.blocked) == 0
    assert app_context.blockers["ipset"].prepare_called is False

    await lifespan.run()

    assert app_context.blockers["ipset"].prepare_called is True
    assert len(app_context.blocked) == 1


async def test_tables_creation(access_log, app_context, lifespan):
    with pytest.raises(DatabaseError):
        await access_log.user_agents_all()

    with pytest.raises(DatabaseError):
        await access_log.persistent_users_all()

    await lifespan.run()

    result = await access_log.user_agents_all()
    assert len(result.result_rows) == 0

    result = await access_log.persistent_users_all()
    assert len(result.result_rows) == 0


async def test_user_agents_loading(
    access_log, app_context, lifespan, user_agent_file_path
):
    app_context.user_agent_manager.config_path = user_agent_file_path
    await lifespan.run()

    result = await access_log.user_agents_all()
    assert len(result.result_rows) == 3


async def test_user_agents_loading_skip(access_log, app_context, lifespan):
    app_context.app_config.allowed_user_agents_file_path = False
    await lifespan.run()

    result = await access_log.user_agents_all()
    assert len(result.result_rows) == 0
