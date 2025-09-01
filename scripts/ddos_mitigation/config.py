from decimal import Decimal
from typing import Literal

from pydantic_settings import BaseSettings

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class AppConfig(BaseSettings):
    path_to_ja5t_config: str = "/etc/tempesta/ja5t/blocked.conf"
    path_to_ja5h_config: str = "/etc/tempesta/ja5h/blocked.conf"

    clickhouse_host: str = "192.168.0.104"
    clickhouse_port: int = 8123
    clickhouse_user: str = "default"
    clickhouse_password: str = ""
    clickhouse_table_name: str = "access_log"
    clickhouse_database: str = "default"

    persistent_users_allow: bool = True
    persistent_users_window_offset_min: int = 60
    persistent_users_window_duration_min: int = 60

    detectors: set[
        Literal[
            "ip_rps",
            "ip_time",
            "ip_errors",
            "ja5_rps",
            "ja5_time",
            "ja5_errors",
            "geoip",
        ]
    ] = {"ja5_rps", "ja5_time", "ja5_errors"}

    blocking_types: set[Literal["ja5t", "ja5h", "ipset", "nftables"]] = {"ja5t"}
    blocking_window_duration_sec: int = 10
    blocking_ipset_name: str = "tempesta_blocked_ips"
    blocking_time_min: int = 60
    blocking_release_time_min: int = 1

    training_mode: Literal["off", "historical", "real"] = "off"
    training_mode_duration_min: int = 10

    detector_ip_rps_default_threshold: Decimal = Decimal(10)
    detector_ip_rps_difference_multiplier: Decimal = Decimal(10)
    detector_ip_rps_block_users_per_iteration: Decimal = Decimal(10)

    detector_ip_time_default_threshold: Decimal = Decimal(10)
    detector_ip_time_difference_multiplier: Decimal = Decimal(10)
    detector_ip_time_block_users_per_iteration: Decimal = Decimal(10)

    detector_ip_errors_default_threshold: Decimal = Decimal(10)
    detector_ip_errors_difference_multiplier: Decimal = Decimal(10)
    detector_ip_errors_block_users_per_iteration: Decimal = Decimal(10)
    detector_ip_errors_allowed_statuses: list[int] = [
        100,
        101,
        200,
        201,
        204,
        300,
        301,
        302,
        303,
        304,
        305,
        307,
        308,
        400,
        401,
        403,
    ]

    detector_ja5_rps_default_threshold: Decimal = Decimal(10)
    detector_ja5_rps_difference_multiplier: Decimal = Decimal(10)
    detector_ja5_rps_block_users_per_iteration: Decimal = Decimal(10)

    detector_ja5_time_default_threshold: Decimal = Decimal(10)
    detector_ja5_time_difference_multiplier: Decimal = Decimal(10)
    detector_ja5_time_block_users_per_iteration: Decimal = Decimal(10)

    detector_ja5_errors_default_threshold: Decimal = Decimal(10)
    detector_ja5_errors_difference_multiplier: Decimal = Decimal(10)
    detector_ja5_errors_block_users_per_iteration: Decimal = Decimal(10)
    detector_ja5_errors_allowed_statuses: list[int] = [
        100,
        101,
        200,
        201,
        204,
        300,
        301,
        302,
        303,
        304,
        305,
        307,
        308,
        400,
        401,
        403,
    ]

    detector_geoip_rps_default_threshold: Decimal = Decimal(10)
    detector_geoip_difference_multiplier: Decimal = Decimal(10)
    detector_geoip_block_users_per_iteration: Decimal = Decimal(10)
    detector_geoip_path_allowed_cities_list: str = (
        "/etc/tempesta-webshield/allowed_cities.txt"
    )
    detector_geoip_path_to_db: str = "/etc/tempesta-webshield/city.db"

    tempesta_executable_path: str = ""
    tempesta_config_path: str = ""
    allowed_user_agents_file_path: str = (
        "/etc/tempesta-webshield/allow_user_agents.txt"
    )
    log_level: str = "INFO"

    @classmethod
    def read(cls, path: str) -> str:
        with open(path, "r") as f:
            return f.read()

    @property
    def training_mode_duration_sec(self) -> int:
        return self.training_mode_duration_min * 60

    @property
    def persistent_users_window_offset_sec(self) -> int:
        return self.persistent_users_window_offset_min * 60

    @property
    def persistent_users_window_duration_sec(self) -> int:
        return self.persistent_users_window_duration_min * 60

    @property
    def blocking_release_time_sec(self) -> int:
        return self.blocking_release_time_min * 60

    @property
    def blocking_time_sec(self) -> int:
        return self.blocking_time_min * 60
