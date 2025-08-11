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

    async def get_top_risk_clients(
        self,
        start_at: int,
        period_in_seconds: int,
        rps_threshold: Decimal,
        time_threshold: Decimal,
        errors_threshold: Decimal,
        ja5_hashes_limit: int,
        legal_response_statuses: set[int],
    ) -> QueryResult:
        """
        Fetch clients that exceed defined thresholds.

        :param start_at: Start time of the analysis frame
        :param period_in_seconds: Duration of the time frame for user activity
        :param rps_threshold: Average RPS threshold across all users
        :param time_threshold: Average accumulated response time threshold across all users.
        :param errors_threshold: Average error response rate threshold across all users.
        :param ja5_hashes_limit: Number of risky ja5t hashes to return.
        :param legal_response_statuses: white listed response statuses
        :return: A QueryResult of risky clients.
        """
        statuses = ", ".join(map(str, legal_response_statuses))

        if not statuses:
            statuses = "200"

        return await self.conn.query(
            f"""
            WITH aggregated_clients AS (
                SELECT 
                    ja5t, 
                    ja5h,
                    groupUniqArray(address) addresses,
                    min(user_agent) user_agent,
                    count(1) as total_requests,
                    sum(response_time) as total_time,
                    countIf(status not in ({statuses})) as total_errors
                FROM {self.table_name}
                WHERE 
                    timestamp > toDateTime64({start_at}, 3, 'UTC') - INTERVAL {period_in_seconds} SECOND
                    AND timestamp <= toDateTime64({start_at}, 3, 'UTC')
                GROUP by ja5t, ja5h
                HAVING  
                    total_requests >= {rps_threshold}
                    or total_time >= {time_threshold}
                    or total_errors >= {errors_threshold}
            ),
            scored_clients AS (
                SELECT 
                    *,
                    if(total_requests = 0, 1, total_requests) * 
                    if(total_time = 0, 1, total_time) * 
                    if(total_errors = 0, 1, total_errors) as risk_score,
                    ua.name as persistent_user_agent
                FROM aggregated_clients ac
                LEFT JOIN user_agents ua
                    ON ac.user_agent = ua.name
                ORDER BY risk_score DESC
            )
            SELECT
                ja5t,
                ja5h,
                addresses,
                CASE 
                    WHEN total_requests >= {rps_threshold} THEN total_requests
                    WHEN total_time >= {time_threshold} THEN total_time
                    WHEN total_errors >= {errors_threshold} THEN total_errors
                END as value,
                CASE 
                    WHEN total_requests >= {rps_threshold} THEN 0
                    WHEN total_time >= {time_threshold} THEN 1
                    WHEN total_errors >= {errors_threshold} THEN 2
                END as type
            FROM scored_clients
            WHERE persistent_user_agent = ''
            LIMIT {ja5_hashes_limit}
            """
        )

    async def get_request_stats_for_period(
        self, start_at: int, period_in_minutes: int, legal_response_statuses: set[int]
    ) -> QueryResult:
        """
        Calculate average statistics for requests, response time, and requests that finished with errors.

        :param start_at: Start time of the analysis frame
        :param period_in_minutes: Duration of the time frame for user activity
        :param legal_response_statuses: white listed response statuses
        :return:  A QueryResult with stats.
        """
        statuses = ", ".join(map(str, legal_response_statuses))

        if not statuses:
            statuses = "200"

        return await self.conn.query(
            f"""
            SELECT * FROM(
                WITH aggregated_clients AS (
                    SELECT 
                        ja5t, 
                        count(1) as total_requests,
                        sum(response_time) as total_time,
                        countIf(status not in ({statuses})) as total_errors
                    FROM {self.table_name}
                    WHERE 
                        timestamp > toDateTime64({start_at}, 3, 'UTC')
                        and timestamp <= toDateTime64({start_at}, 3, 'UTC') + INTERVAL {period_in_minutes} MINUTE
                    GROUP by ja5t
                )
                SELECT 
                    avg(total_requests) value,
                    0 as type
                FROM aggregated_clients
                    
                UNION ALL
                
                SELECT 
                    avg(total_time) value,
                    1 as type
                FROM aggregated_clients
                
                UNION ALL
                
                SELECT
                    avg(total_errors) value,
                    2 as type
                from aggregated_clients
            ) a
            ORDER BY type
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
