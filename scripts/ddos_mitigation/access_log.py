from dataclasses import dataclass

from clickhouse_connect import get_async_client
from clickhouse_connect.driver import AsyncClient

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class ClickhouseAccessLog:
    """
    Extends the ClickHouse client and describes the queries used in the application
    """

    host: str = "127.0.0.1"
    port: int = 8123
    user: str = "default"
    password: str = ""
    table_name: str = "access_log"
    database: str = "__default__"
    conn: AsyncClient = None

    async def connect(self):
        """
        Create a connection to the ClickHouse server
        """
        self.conn = await get_async_client(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database,
        )

    async def user_agents_table_create(self):
        return await self.conn.query(
            """
            create table if not exists user_agents (
                name String,
                PRIMARY KEY(name)
            )
            """
        )

    async def user_agents_table_truncate(self):
        return await self.conn.query(
            """
            truncate table user_agents
            """
        )

    async def user_agents_table_insert(self, values: list[list[str]]):
        return await self.conn.insert(
            table="user_agents", data=values, column_names=["name"]
        )

    async def user_agents_all(self):
        return await self.conn.query(
            """
            SELECT *
            FROM user_agents
            """
        )
