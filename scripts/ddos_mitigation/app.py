import asyncio

from access_log import ClickhouseAccessLog
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
    app_config = AppConfig.parse_file(args.config)
    clickhouse_client = ClickhouseAccessLog(
        host=app_config.clickhouse_host,
        port=app_config.clickhouse_port,
        user=app_config.clickhouse_user,
        password=app_config.clickhouse_password,
        database=app_config.clickhouse_database,
    )
    app = DDOSMonitor(
        clickhouse_client=clickhouse_client,
        ja5t_config=Ja5Config(file_path=app_config.path_to_ja5t_config),
        ja5h_config=Ja5Config(file_path=app_config.path_to_ja5h_config),
        app_config=app_config,
        user_agent_manager=UserAgentsManager(
            clickhouse_client=app_config.user_agent_manager,
            config_path=app_config.allowed_user_agents_file_path,
        ),
    )
    asyncio.run(app.run())
