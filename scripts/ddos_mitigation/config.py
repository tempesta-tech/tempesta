from typing import Literal
from pydantic_settings import BaseSettings


class AppConfig(BaseSettings):
    training_mode: Literal['off', 'historical', 'real'] = 'off'

    path_to_ja5t_config: str = '/etc/tempesta/ja5t/blocked.conf'
    path_to_ja5h_config: str = '/etc/tempesta/ja5h/blocked.conf'

    clickhouse_host: str = '192.168.0.104'
    clickhouse_port: int = 8123
    clickhouse_user: str = 'default'
    clickhouse_password: str = ''
    clickhouse_database: str = 'default'

    normal_users_max_amount: int = 100
    normal_users_find_minutes_ago: int = 60
    normal_users_find_time_frame_minutes: int = 60
    normal_users_total_requests: int = 1
    normal_users_total_time: int = 1

    default_requests_threshold: int = 100
    default_time_threshold: int = 40
    default_errors_threshold: int = 5

    stats_find_minutes_ago: int = 60
    stats_find_time_frame_minutes: int = 60

    blocking_type: set[Literal['ja5t', 'ja5h', 'ipset', 'nftables']] = {'ja5t'}
    blocking_time_slice: int = 60
    blocking_ja5_limit: int = 10
    blocking_ip_limits: int = 10
    blocking_ipset_name: str = 'tempesta_blocked_ips'
    blocking_use_ip: bool = False
    blocking_default_time_minutes: int = 60
    blocking_release_time_minutes: int = 1

    tempesta_executable_path: str = ''
