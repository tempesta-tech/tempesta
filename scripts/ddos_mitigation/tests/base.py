import unittest

from config import AppConfig
from utils.access_log import ClickhouseAccessLog

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class BaseTestCaseWithFilledDB(unittest.IsolatedAsyncioTestCase):
    async def create_records(self):
        await self.access_log.conn.query(
            """
            insert into access_log values 
            (cast('1751535000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 11, 21, 0),
            (cast('1751536000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 200, 0, 10, 'default', '/', '/', 'UserAgent', 12, 22, 0),
            (cast('1751537000' as DateTime64(3, 'UTC')), '127.0.0.1', 0, 1, 400, 0, 10, 'default', '/', '/', 'UserAgent', 13, 23, 0)
            """
        )

    async def asyncSetUp(self):
        self.app_config = AppConfig(clickhouse_database="test_db")
        self.access_log = ClickhouseAccessLog()

        await self.access_log.connect()
        await self.access_log.conn.query("create database  if not exists  test_db ")
        await self.access_log.conn.close()

        self.access_log = ClickhouseAccessLog(database="test_db")
        await self.access_log.connect()
        await self.access_log.conn.query(
            """
            CREATE TABLE IF NOT EXISTS access_log (
                timestamp DateTime64(3, 'UTC'),
                address IPv6,
                method UInt8,
                version UInt8,
                status UInt16,
                response_content_length UInt32,
                response_time UInt32,
                vhost String,
                uri String,
                referer String,
                user_agent String,
                ja5t UInt64,
                ja5h UInt64,
                dropped_events UInt64,
                PRIMARY KEY(timestamp)
            );
            """
        )
        await self.access_log.user_agents_table_create()
        await self.access_log.persistent_users_table_create()
        await self.access_log.user_agents_table_truncate()
        await self.access_log.persistent_users_table_truncate()

        await self.create_records()

    async def asyncTearDown(self):
        await self.access_log.conn.query("drop database if exists test_db")
