from detectors.base import SQLBasedDetector

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class IPRPSDetector(SQLBasedDetector):

    @staticmethod
    def name() -> str:
        return "ip_rps"

    @staticmethod
    def shared_filter(prepared_users: str) -> str:
        return f"""
            {prepared_users}
            SELECT
                ja5t,
                ja5h,
                address,
                value
            FROM prepared_users
            WHERE   
                whitelisted_user_agents = ''
                and persistent_users = '' 
            LIMIT 10
        """

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            WITH prepared_users AS (
                SELECT 
                    groupUniqArray(ja5t) ja5t, 
                    groupUniqArray(ja5h) ja5h,
                    [address] address,
                    min(user_agent) user_agent,
                    count(1) as total_requests,
                    ua.name as whitelisted_user_agents,
                    p.ip as persistent_users
                FROM {self.access_log.table_name}
                LEFT JOIN user_agents ua
                    ON user_agent = ua.name
                LEFT JOIN persistent_users p
                    ON address = p.ip
                WHERE 
                    timestamp >= toDateTime64({start_at}, 3, 'UTC')
                    and timestamp < {finish_at}
                GROUP by address
                HAVING  
                    value >= {self.rps_threshold}
            )
            """
        )


class IPErrorRequestDetector(IPRPSDetector):

    @staticmethod
    def name() -> str:
        return "ip_errors"

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            WITH prepared_users AS (
                SELECT 
                    groupUniqArray(ja5t) ja5t, 
                    groupUniqArray(ja5h) ja5h,
                    [address] address,
                    min(user_agent) user_agent,
                    countIf(status not in ({self.statuses})) value,
                    ua.name as whitelisted_user_agents,
                    p.ip as persistent_users
                FROM {self.access_log.table_name}
                LEFT JOIN user_agents ua
                    ON user_agent = ua.name
                LEFT JOIN persistent_users p
                    ON address = p.ip
                WHERE 
                    timestamp >= toDateTime64({start_at}, 3, 'UTC')
                    and timestamp < {finish_at}
                GROUP by address
                HAVING  
                    value >= {self.errors_threshold}
            )
            """
        )


class IPAccumulativeTimeDetector(IPRPSDetector):

    @staticmethod
    def name() -> str:
        return "ip_accumulative_time"

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            WITH prepared_users AS (
                SELECT 
                    groupUniqArray(ja5t) ja5t, 
                    groupUniqArray(ja5h) ja5h,
                    [address] address,
                    min(user_agent) user_agent,
                    sum(response_time) value,
                    ua.name as whitelisted_user_agents,
                    p.ip as persistent_users
                FROM {self.access_log.table_name}
                LEFT JOIN user_agents ua
                    ON user_agent = ua.name
                LEFT JOIN persistent_users p
                    ON address = p.ip
                WHERE 
                    timestamp >= toDateTime64({start_at}, 3, 'UTC')
                    and timestamp < {finish_at}
                GROUP by address
                HAVING  
                    value >= {self.time_threshold}
            )
            """
        )


class Ja5tRPSDetector(IPRPSDetector):
    @staticmethod
    def name() -> str:
        return "ja5t_rps"

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            WITH prepared_users AS (
                SELECT 
                    ja5t ja5t, 
                    groupUniqArray(ja5h) ja5h,
                    groupUniqArray(address) address,
                    min(user_agent) user_agent,
                    count(1) as total_requests,
                    ua.name as whitelisted_user_agents,
                    p.ip as persistent_users
                FROM {self.access_log.table_name}
                LEFT JOIN user_agents ua
                    ON user_agent = ua.name
                LEFT JOIN persistent_users p
                    ON address = p.ip
                WHERE 
                    timestamp >= toDateTime64({start_at}, 3, 'UTC')
                    and timestamp < {finish_at}
                GROUP by ja5t
                HAVING  
                    value >= {self.rps_threshold}
            )
            """
        )


class Ja5tErrorRequestDetector(IPRPSDetector):

    @staticmethod
    def name() -> str:
        return "ja5t_errors"

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            WITH prepared_users AS (
                SELECT 
                    [ja5t] ja5t, 
                    groupUniqArray(ja5h) ja5h,
                    groupUniqArray(address) address,
                    min(user_agent) user_agent,
                    countIf(status not in ({self.statuses})) value,
                    ua.name as whitelisted_user_agents,
                    p.ip as persistent_users
                FROM {self.access_log.table_name}
                LEFT JOIN user_agents ua
                    ON user_agent = ua.name
                LEFT JOIN persistent_users p
                    ON address = p.ip
                WHERE 
                    timestamp >= toDateTime64({start_at}, 3, 'UTC')
                    and timestamp < {finish_at}
                GROUP by ja5t
                HAVING  
                    value >= {self.errors_threshold}
            )
            """
        )


class Ja5tAccumulativeTimeDetector(IPRPSDetector):

    @staticmethod
    def name() -> str:
        return "ja5t_accumulative_time"

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            WITH prepared_users AS (
                SELECT 
                    [ja5t] ja5t, 
                    groupUniqArray(ja5h) ja5h,
                    groupUniqArray(address) address,
                    min(user_agent) user_agent,
                    sum(response_time) value,
                    ua.name as whitelisted_user_agents,
                    p.ip as persistent_users
                FROM {self.access_log.table_name}
                LEFT JOIN user_agents ua
                    ON user_agent = ua.name
                LEFT JOIN persistent_users p
                    ON address = p.ip
                WHERE 
                    timestamp >= toDateTime64({start_at}, 3, 'UTC')
                    and timestamp < {finish_at}
                GROUP by address
                HAVING  
                    value >= {self.time_threshold}
            )
            """
        )
