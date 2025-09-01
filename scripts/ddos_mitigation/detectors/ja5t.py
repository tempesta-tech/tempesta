from detectors.ip import IPRPSDetector

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class Ja5tRPSDetector(IPRPSDetector):
    @staticmethod
    def name() -> str:
        return "ja5t_rps"

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            SELECT 
                array(ja5t) ja5t, 
                groupUniqArray(ja5h) ja5h,
                groupUniqArray(address) address,
                count(1) value
            FROM prepared_users
            GROUP by ja5t
            HAVING  
                value >= {self.threshold}
            LIMIT {self.block_limit_per_check}
            """,
            start_at=start_at,
            finish_at=finish_at,
        )


class Ja5tErrorRequestDetector(IPRPSDetector):
    def __init__(self, *args, allowed_statues: list[int] = (), **kwargs):
        super().__init__(*args, **kwargs)
        self.allowed_statues = allowed_statues

    @staticmethod
    def name() -> str:
        return "ja5t_errors"

    def get_request(self, start_at, finish_at):
        statuses = ", ".join(list(map(str, self.allowed_statues)))
        return self.shared_filter(
            f"""
            SELECT 
                array(ja5t) ja5t, 
                groupUniqArray(ja5h) ja5h,
                groupUniqArray(address) address,
                countIf(status not in ({statuses})) value
            FROM prepared_users
            GROUP by ja5t
            HAVING  
                value >= {self.threshold}
            LIMIT {self.block_limit_per_check}
            """,
            start_at=start_at,
            finish_at=finish_at,
        )


class Ja5tAccumulativeTimeDetector(IPRPSDetector):

    @staticmethod
    def name() -> str:
        return "ja5t_accumulative_time"

    def get_request(self, start_at, finish_at):
        return self.shared_filter(
            f"""
            SELECT 
                array(ja5t) ja5t, 
                groupUniqArray(ja5h) ja5h,
                groupUniqArray(address) address,
                sum(response_time) value
            FROM prepared_users
            GROUP by ja5t
            HAVING  
                value >= {self.threshold}
            LIMIT {self.block_limit_per_check}
            """,
            start_at=start_at,
            finish_at=finish_at,
        )
