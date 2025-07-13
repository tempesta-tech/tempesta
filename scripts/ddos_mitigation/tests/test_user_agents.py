import os
import unittest

from user_agents import UserAgentsManager
from access_log import ClickhouseAccessLog

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestUserAgentManager(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = ClickhouseAccessLog()
        await self.client.connect()
        await self.client.conn.query("drop database if exists test_db")

        await self.client.conn.query("create database test_db")
        await self.client.conn.close()

        self.client = ClickhouseAccessLog(database="test_db")
        await self.client.connect()

        self.path_to_config = "/tmp/tmp-user-agents"
        self.manager = UserAgentsManager(
            config_path=self.path_to_config,
            clickhouse_client=self.client,
        )

        with open(self.path_to_config, "w") as f:
            f.write(
                "UserAgent\n"
                "  2222aaaaaaa   \n"
            )

    async def asyncTearDown(self):
        os.remove(self.path_to_config)
        await self.client.conn.query("drop database test_db")

    def test_read_config(self):
        self.manager.read_from_file()
        self.assertEqual(self.manager.user_agents, {'UserAgent', '2222aaaaaaa'})

    async def test_export_user_agents(self):
        await self.client.user_agents_table_create()

        self.manager.user_agents = {'Hello', 'Kitty'}
        await self.manager.export_to_db()

        result = await self.client.user_agents_all()
        self.assertEqual(result.result_rows, [('Hello', ), ('Kitty', )])
