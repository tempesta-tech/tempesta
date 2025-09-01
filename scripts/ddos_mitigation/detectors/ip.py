from detectors.base import SQLBasedDetector

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class IPRPSDetector(SQLBasedDetector):

    @staticmethod
    def name() -> str:
        return "ip_rps"

    def shared_filter(self, prepared_users: str, start_at: int, finish_at: int) -> str:
        return f"""
            WITH prepared_users AS (
                SELECT al.*
                FROM {self._access_log.table_name} al
                LEFT ANTI JOIN user_agents ua
                    ON al.user_agent = ua.name
                LEFT ANTI JOIN persistent_users p
                    ON al.address = p.ip
                WHERE 
                    timestamp >= toDateTime64({start_at}, 3, 'UTC')
                    and timestamp < {finish_at}
            )
            {prepared_users}
        """

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            SELECT 
                groupUniqArray(ja5t) ja5t, 
                groupUniqArray(ja5h) ja5h,
                array(address) address,
                count(1) value
            FROM prepared_users
            GROUP by address
            HAVING  
                value >= {self.threshold}
            LIMIT {self.block_limit_per_check}
            """,
            start_at=start_at,
            finish_at=finish_at,
        )


class IPErrorRequestDetector(IPRPSDetector):

    def __init__(self, *args, allowed_statues: list[int] = (), **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed_statues = allowed_statues

    @staticmethod
    def name() -> str:
        return "ip_errors"

    def get_request(self, start_at, finish_at):
        statuses = ", ".join(list(map(str, self.allowed_statues)))
        return self.shared_filter(
            f"""
            SELECT 
                groupUniqArray(ja5t) ja5t, 
                groupUniqArray(ja5h) ja5h,
                array(address) address,
                countIf(status not in ({statuses})) value
            FROM prepared_users
            GROUP by address
            HAVING  
                value >= {self.threshold}
            LIMIT {self.block_limit_per_check}
            """,
            start_at=start_at,
            finish_at=finish_at,
        )


class IPAccumulativeTimeDetector(IPRPSDetector):

    @staticmethod
    def name() -> str:
        return "ip_accumulative_time"

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            SELECT 
                groupUniqArray(ja5t) ja5t, 
                groupUniqArray(ja5h) ja5h,
                array(address) address,
                sum(response_time) value
            FROM prepared_users
            GROUP by address
            HAVING  
                value >= {self.threshold}
            LIMIT {self.block_limit_per_check}
            """,
            start_at=start_at,
            finish_at=finish_at,
        )
