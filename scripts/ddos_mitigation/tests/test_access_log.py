import math
from decimal import Decimal
from ipaddress import IPv4Address

from tests.base import BaseTestCaseWithFilledDB

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestClickhouseClient(BaseTestCaseWithFilledDB):
    async def test_create_user_agents_table(self):
        await self.access_log.user_agents_table_create()
        items = await self.access_log.user_agents_all()
        self.assertEqual(len(items.result_rows), 0)

    async def test_insert_into_user_agents_table(self):
        await self.access_log.user_agents_table_insert(
            [["TestUserAgent"], ["HelloKitty"]]
        )
        items = await self.access_log.user_agents_all()
        self.assertEqual(len(items.result_rows), 2)

    async def test_create_persistent_user_table(self):
        await self.access_log.persistent_users_table_create()
        items = await self.access_log.persistent_users_all()
        self.assertEqual(len(items.result_rows), 0)

    async def test_insert_into_persistent_user_table(self):
        await self.access_log.persistent_users_table_insert(
            [["127.0.0.1"], ["fa00::01"]]
        )
        items = await self.access_log.persistent_users_all()
        self.assertEqual(len(items.result_rows), 2)
