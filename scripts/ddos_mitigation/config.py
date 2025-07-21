from decimal import Decimal
from typing import Literal

from pydantic_settings import BaseSettings

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class AppConfig(BaseSettings):
    training_mode: Literal["off", "historical", "real"] = "off"
    training_mode_duration_min: int = 10

    path_to_ja5t_config: str = "/etc/tempesta/ja5t/blocked.conf"
    path_to_ja5h_config: str = "/etc/tempesta/ja5h/blocked.conf"

    clickhouse_host: str = "192.168.0.104"
    clickhouse_port: int = 8123
    clickhouse_user: str = "default"
    clickhouse_password: str = ""
    clickhouse_database: str = "default"

    persistent_users_max_amount: int = 100
    persistent_users_window_offset_min: int = 60
    persistent_users_window_duration_min: int = 60
    persistent_users_total_requests: Decimal = 1
    persistent_users_total_time: Decimal = 1

    default_requests_threshold: Decimal = 100
    default_time_threshold: Decimal = 40
    default_errors_threshold: Decimal = 5

    stats_window_offset_min: int = 60
    stats_window_duration_min: int = 60
    stats_rps_precision: Decimal = 1
    stats_time_precision: Decimal = 1
    stats_errors_precision: Decimal = 0.1

    detectors: set[Literal["threshold", "geoip"]] = {"threshold"}
    response_statuses_white_list: set[int] = [100, 101, 200, 201, 204, 400, 401, 403]

    blocking_type: set[Literal["ja5t", "ja5h", "ipset", "nftables", "geoip"]] = {"ja5t"}
    blocking_window_duration_sec: int = 10
    blocking_ja5_limit: int = 10
    blocking_ip_limits: int = 10
    blocking_ipset_name: str = "tempesta_blocked_ips"
    blocking_time_min: int = 60
    blocking_release_time_min: int = 1

    detector_geoip_percent_threshold: Decimal = Decimal(95)
    detector_geoip_min_rps: Decimal = Decimal(100)
    detector_geoip_period_seconds: int = 10

    tempesta_executable_path: str = ""
    allowed_user_agents_file_path: str = (
        "/etc/tempesta-ddos-defender/allow_user_agents.txt"
    )
    log_level: str = "INFO"

    test_mode: bool = False
    test_unix_time: int = 0

    @classmethod
    def read(cls, path: str) -> str:
        with open(path, "r") as f:
            return f.read()
