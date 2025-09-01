#!/usr/bin/python3
import asyncio
import logging

import blockers
from cli import CommandLineArgs
from config import AppConfig
from core.context import AppContext
from core.executor import run_app
from detectors.geoip import GeoIPDetector
from detectors.ip import (
    IPAccumulativeTimeDetector,
    IPErrorRequestDetector,
    IPRPSDetector,
)
from detectors.ja5t import (
    Ja5tAccumulativeTimeDetector,
    Ja5tErrorRequestDetector,
    Ja5tRPSDetector,
)
from utils.access_log import ClickhouseAccessLog
from utils.ja5_config import Ja5Config
from utils.logger import logger
from utils.user_agents import UserAgentsManager

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


if __name__ == "__main__":
    logger.info("Starting Tempesta WebShield")

    args = CommandLineArgs.parse_args()
    app_config = AppConfig(_env_file=args.config)
    logger.setLevel(getattr(logging, args.log_level or app_config.log_level, "INFO"))

    clickhouse_client = ClickhouseAccessLog(
        host=app_config.clickhouse_host,
        port=app_config.clickhouse_port,
        user=app_config.clickhouse_user,
        password=app_config.clickhouse_password,
        table_name=app_config.clickhouse_table_name,
        database=app_config.clickhouse_database,
    )
    context = AppContext(
        blockers={
            blockers.Ja5tBlocker.name(): blockers.Ja5tBlocker(
                config=Ja5Config(file_path=app_config.path_to_ja5t_config),
                tempesta_executable_path=app_config.tempesta_executable_path,
                tempesta_config_path=app_config.tempesta_config_path,
            ),
            blockers.Ja5hBlocker.name(): blockers.Ja5hBlocker(
                config=Ja5Config(file_path=app_config.path_to_ja5h_config),
                tempesta_executable_path=app_config.tempesta_executable_path,
                tempesta_config_path=app_config.tempesta_config_path,
            ),
            blockers.IpSetBlocker.name(): blockers.IpSetBlocker(
                blocking_ip_set_name=app_config.blocking_ipset_name,
            ),
            blockers.NFTBlocker.name(): blockers.NFTBlocker(
                blocking_table_name=app_config.blocking_ipset_name,
            ),
        },
        detectors={
            IPRPSDetector.name(): IPRPSDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_ip_rps_default_threshold,
                difference_multiplier=app_config.detector_ip_rps_difference_multiplier,
                block_users_per_iteration=app_config.detector_ip_rps_block_users_per_iteration,
            ),
            IPAccumulativeTimeDetector.name(): IPAccumulativeTimeDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_ip_time_default_threshold,
                difference_multiplier=app_config.detector_ip_time_difference_multiplier,
                block_users_per_iteration=app_config.detector_ip_time_block_users_per_iteration,
            ),
            IPErrorRequestDetector.name(): IPErrorRequestDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_ip_errors_default_threshold,
                difference_multiplier=app_config.detector_ip_errors_difference_multiplier,
                block_users_per_iteration=app_config.detector_ip_errors_block_users_per_iteration,
                allowed_statues=app_config.detector_ip_errors_allowed_statuses,
            ),
            Ja5tRPSDetector.name(): Ja5tRPSDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_ja5_rps_default_threshold,
                difference_multiplier=app_config.detector_ja5_rps_difference_multiplier,
                block_users_per_iteration=app_config.detector_ja5_rps_block_users_per_iteration,
            ),
            Ja5tAccumulativeTimeDetector.name(): Ja5tAccumulativeTimeDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_ja5_time_default_threshold,
                difference_multiplier=app_config.detector_ja5_time_difference_multiplier,
                block_users_per_iteration=app_config.detector_ja5_time_block_users_per_iteration,
            ),
            Ja5tErrorRequestDetector.name(): Ja5tErrorRequestDetector(
                access_log=clickhouse_client,
                default_threshold=app_config.detector_ja5_errors_default_threshold,
                difference_multiplier=app_config.detector_ja5_errors_difference_multiplier,
                block_users_per_iteration=app_config.detector_ja5_errors_block_users_per_iteration,
                allowed_statues=app_config.detector_ja5_errors_allowed_statuses,
            ),
            GeoIPDetector.name(): GeoIPDetector(
                access_log=clickhouse_client,
                # default_threshold=app_config.detector_geoip_rps_default_threshold,
                difference_multiplier=app_config.detector_geoip_difference_multiplier,
                block_users_per_iteration=app_config.detector_geoip_block_users_per_iteration,
                path_to_db=app_config.detector_geoip_path_to_db,
                path_to_allowed_cities_list=app_config.detector_geoip_path_allowed_cities_list,
            ),
        },
        clickhouse_client=clickhouse_client,
        app_config=app_config,
        user_agent_manager=UserAgentsManager(
            clickhouse_client=clickhouse_client,
            config_path=app_config.allowed_user_agents_file_path,
        ),
    )

    if args.verify:
        exit(0)

    asyncio.run(run_app(context))
