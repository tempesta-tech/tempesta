import unittest
from defender.lifespan import AfterInitialization
from defender.context import AppContext

from utils.access_log import ClickhouseAccessLog
from config import AppConfig

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


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


class FrozenTimeAppContext(AppContext):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.time = 0

    @property
    def utc_now(self) -> int:
        return self.time


class TestLifespanAfterInitialization(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.access_log = ClickhouseAccessLog()
        await self.access_log.connect()
        await self.access_log.user_agents_table_truncate()
        await self.access_log.persistent_users_table_truncate()

        await self.access_log.user_agents_table_insert(
            [['UserAgent'], ['UserAgent2']]
        )
        await self.access_log.conn.query(
            """
            insert into access_log values
            (cast('1751535005' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751535006' as DateTime64(3, 'UTC')), '127.0.0.2', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent2', 12, 22, 0),
            (cast('1751535007' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent2', 13, 23, 0),
            (cast('1751535007' as DateTime64(3, 'UTC')), '127.0.0.3', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent3', 13, 23, 0),
            (cast('1751535007' as DateTime64(3, 'UTC')), '127.0.0.4', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent4', 13, 23, 0)
            """
        )

        self.context = FrozenTimeAppContext(
            clickhouse_client=self.access_log,
            app_config=FlexibleTimeAppConfig(),
        )
        self.lifespan = AfterInitialization(context=self.context)

    async def asyncTearDown(self):
        await self.access_log.user_agents_table_truncate()
        await self.access_log.persistent_users_table_truncate()

    async def test_time_frame_before(self):
        self.context.time = 1751535005
        self.context.app_config._offset_sec = 5
        self.context.app_config._duration_sec = 3

        await self.lifespan.run()

        response = await self.access_log.persistent_users_all()
        assert len(response.result_rows) == 0

    async def test_time_frame_after(self):
        self.context.time = 1751535010
        self.context.app_config._offset_sec = 2
        self.context.app_config._duration_sec = 2

        await self.lifespan.run()

        response = await self.access_log.persistent_users_all()
        assert len(response.result_rows) == 0

    async def test_found_users(self):
        self.context.time = 1751535010
        self.context.app_config._offset_sec = 10
        self.context.app_config._duration_sec = 10

        await self.lifespan.run()

        response = await self.access_log.persistent_users_all()
        assert len(response.result_rows) == 2
        assert {str(row[0]) for row in response.result_rows} == {'127.0.0.3', '127.0.0.4'}
