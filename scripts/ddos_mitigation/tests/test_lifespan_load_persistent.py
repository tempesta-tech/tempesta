import pytest

from config import AppConfig
from core.context import AppContext
from core.lifespan import LoadPersistentUsers

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@pytest.fixture
def app_config():
    class FlexibleTimeAppConfig(AppConfig):

        def __init__(self, *args, **kwargs):
            super(FlexibleTimeAppConfig, self).__init__(*args, **kwargs)

            self._offset_sec = 0
            self._duration_sec = 0

        @property
        def persistent_users_window_offset_sec(self):
            return self._offset_sec

        @property
        def persistent_users_window_duration_sec(self):
            return self._duration_sec

    yield FlexibleTimeAppConfig


@pytest.fixture
def app_context(access_log, app_config):
    class FrozenTimeAppContext(AppContext):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.time = 0

        @property
        def utc_now(self) -> int:
            return self.time

    yield FrozenTimeAppContext(
        clickhouse_client=access_log,
        app_config=app_config(),
    )


@pytest.fixture
async def lifespan(access_log, app_context):
    await access_log.user_agents_table_insert([["UserAgent"], ["UserAgent2"]])
    await access_log.conn.query(
        """
        insert into access_log values
        (cast('1751535005' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
        (cast('1751535006' as DateTime64(3, 'UTC')), '127.0.0.2', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent2', 12, 22, 0),
        (cast('1751535007' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent2', 13, 23, 0),
        (cast('1751535007' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent3', 13, 23, 0),
        (cast('1751535007' as DateTime64(3, 'UTC')), '127.0.0.4', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent4', 13, 23, 0)
        """
    )
    yield LoadPersistentUsers(context=app_context)


async def test_time_frame_before(access_log, app_context, lifespan):
    app_context.time = 1751535005
    app_context.app_config._offset_sec = 5
    app_context.app_config._duration_sec = 3

    await lifespan.run()

    response = await access_log.persistent_users_all()
    assert len(response.result_rows) == 0


async def test_time_frame_after(access_log, app_context, lifespan):
    app_context.time = 1751535010
    app_context.app_config._offset_sec = 2
    app_context.app_config._duration_sec = 2

    await lifespan.run()

    response = await access_log.persistent_users_all()
    assert len(response.result_rows) == 0


async def test_found_users(access_log, app_context, lifespan):
    app_context.time = 1751535010
    app_context.app_config._offset_sec = 10
    app_context.app_config._duration_sec = 10

    await lifespan.run()

    response = await access_log.persistent_users_all()
    assert len(response.result_rows) == 2
    assert {str(row[0]) for row in response.result_rows} == {
        "127.0.0.3",
        "127.0.0.4",
    }
