from dataclasses import dataclass
from clickhouse_connect import get_async_client
from clickhouse_connect.driver import AsyncClient


__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class ClickhouseAccessLog:
    """
    Extends the Clickhouse Client and descibes
    queries used in app
    """
    host: str = '192.168.0.104'
    port: int = 8123
    user: str = 'default'
    password: str = '12345'
    database: str = '__default__'
    conn: AsyncClient = None

    async def connect(self):
        """
        Create the connection to the Clickhouse server
        """
        self.conn = await get_async_client(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database,
        )

    async def get_top_risk_clients(
            self,
            time_frame_seconds: int,
            rps_threshold: int,
            time_threshold: int,
            errors_threshold: int,
            time_from: int = 0,
            ja5_hashes_limit: int = 10
    ):
        """
        Fetch clients that rises thresholds

        :param time_frame_seconds: along of time of user activity. Descibe a frame: [time_from; time_from + time_frame_seconds)
        :param rps_threshold: Average RPS threshold by all user
        :param time_threshold: Average accumulated response time threshold by all users
        :param errors_threshold: Average responses with errors threshold by all users
        :param time_from: start of frame
        :param ja5_hashes_limit: amount of returning risky ja5t hashes
        :return: risky clients
        """
        return await self.conn.query(
            f"""
            WITH aggregated_clients AS (
                SELECT 
                    ja5t, 
                    ja5h,
                    groupUniqArray(address) addresses,
                    count(1) as total_requests,
                    sum(response_time) as total_time,
                    countIf(status not in (200, 201)) as total_errors
                FROM test_db.access_log
                WHERE 
                    timestamp > toDateTime64({time_from}, 3, 'UTC') - INTERVAL 60 SECOND
                    AND timestamp <= toDateTime64({time_from}, 3, 'UTC')
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
                    if(total_errors = 0, 1, total_errors) as risk_score
                FROM aggregated_clients
                ORDER BY risk_score DESC
                LIMIT {ja5_hashes_limit}
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
            """
        )

    async def get_stats_for_period(self, start_at: int, period_in_minutes: int):
        return await self.conn.query(
            f"""
            SELECT * FROM(
                WITH aggregated_clients AS (
                    SELECT 
                        ja5t, 
                        count(1) as total_requests,
                        sum(response_time) as total_time,
                        countIf(status not in (200, 201)) as total_errors
                    FROM test_db.access_log
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
