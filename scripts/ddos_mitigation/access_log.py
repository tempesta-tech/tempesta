from dataclasses import dataclass
from decimal import Decimal

from clickhouse_connect import get_async_client
from clickhouse_connect.driver import AsyncClient
from clickhouse_connect.driver.query import QueryResult

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

    async def get_aggregated_clients_for_period(
        self, start_at: int, period_in_seconds: int, legal_response_statuses: set[int]
    ) -> QueryResult:
        """
        Fetch clients that exceed defined thresholds.

        :param start_at: Start time of the analysis frame
        :param period_in_seconds: Duration of the time frame for user activity
        :param legal_response_statuses: white listed response statuses
        :return: A QueryResult of clients.
        """
        statuses = ", ".join(map(str, legal_response_statuses))

        if not statuses:
            statuses = "200"

        return await self.conn.query(
            f"""
            SELECT 
                min(ja5t), 
                min(ja5h),
                address,
                min(user_agent) user_agent,
                count(1) as total_requests,
                avg(response_time) as total_time,
                countIf(status not in ({statuses})) as total_errors
            FROM {self.table_name}
            WHERE 
                timestamp > toDateTime64({start_at}, 3, 'UTC') - INTERVAL {period_in_seconds} SECOND
                AND timestamp <= toDateTime64({start_at}, 3, 'UTC')
            GROUP by address
            """
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
