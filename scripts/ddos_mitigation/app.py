#!/usr/bin/python3
import asyncio
import logging

from access_log import ClickhouseAccessLog
from blockers import blockers
from cli import CommandLineArgs
from config import AppConfig
from defender import DDOSMonitor
from ja5_config import Ja5Config
from logger import logger
from user_agents import UserAgentsManager

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


if __name__ == "__main__":
    logger.info("Starting DDoS Defender")

    args = CommandLineArgs.parse_args()
    app_config = AppConfig(_env_file=args.config)
    logger.setLevel(getattr(logging, args.log_level or app_config.log_level, "INFO"))

    clickhouse_client = ClickhouseAccessLog(
        host=app_config.clickhouse_host,
        port=app_config.clickhouse_port,
        user=app_config.clickhouse_user,
        password=app_config.clickhouse_password,
        database=app_config.clickhouse_database,
    )
    app = DDOSMonitor(
        blockers={
            blockers.Ja5tBlocker.name(): blockers.Ja5tBlocker(
                config=Ja5Config(file_path=app_config.path_to_ja5t_config),
                tempesta_executable_path=app_config.tempesta_executable_path,
            ),
            blockers.Ja5hBlocker.name(): blockers.Ja5hBlocker(
                config=Ja5Config(file_path=app_config.path_to_ja5h_config),
                tempesta_executable_path=app_config.tempesta_executable_path,
            ),
            blockers.IpSetBlocker.name(): blockers.IpSetBlocker(
                blocking_ip_set_name=app_config.ipset_blocking_ipset_name,
            ),
            blockers.NFTBlocker.name(): blockers.NFTBlocker(
                blocking_table_name=app_config.ipset_blocking_ipset_name,
            ),
        },
        clickhouse_client=clickhouse_client,
        app_config=app_config,
        user_agent_manager=UserAgentsManager(
            clickhouse_client=clickhouse_client,
            config_path=app_config.allowed_user_agents_file_path,
        ),
    )
    asyncio.run(app.run())
