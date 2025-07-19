import asyncio
import time
from dataclasses import dataclass, field

from access_log import ClickhouseAccessLog
from blockers.base import BaseBlocker
from config import AppConfig
from datatypes import User
from detectors.base import BaseDetector
from user_agents import UserAgentsManager

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from logger import logger


@dataclass
class DDOSMonitor:
    """
    Manager start two background tasks which periodically block and unblock new users
    """

    # A connected client to Clickhouse Server
    clickhouse_client: ClickhouseAccessLog

    # Initialized application config
    app_config: AppConfig

    # User Agent Config Manager
    user_agent_manager: UserAgentsManager

    # users found as risky and where blocked
    blocked: dict[int, User] = field(default_factory=dict)

    # Available blockers
    blockers: dict[str, BaseBlocker] = field(default_factory=dict)

    # Available detectors
    detectors: dict[str, BaseDetector] = field(default_factory=dict)

    def user_block(self, user: User):
        for blocking_type in self.app_config.blocking_type:
            self.blockers[blocking_type].block(user)
            self.blocked[hash(user)] = user

    def user_release(self, user: User):
        for blocking_type in self.app_config.blocking_type:
            self.blockers[blocking_type].release(user)
            self.blocked.pop(hash(user))

    def user_apply(self):
        for blocking_type in self.app_config.blocking_type:
            self.blockers[blocking_type].apply()

    def user_reset(self):
        for blocking_type in self.app_config.blocking_type:
            self.blockers[blocking_type].reset()
            self.blocked = dict()

    async def risk_clients_block(self, test_unix_time: int = None):
        """
        Retrieve a batch of newly identified risky clients and block them

        :param test_unix_time: used as current time in functional tests
        """

        total_users = 0
        blocked_users = 0
        current_time = test_unix_time or int(time.time())

        for detector in self.detectors.values():
            for blocking_user in await detector.find_users(current_time):
                total_users += 1

                if blocking_user in self.blocked:
                    continue

                blocked_users += 1
                blocking_user.blocked_at = current_time
                self.user_block(blocking_user)

        self.user_apply()

        logger.debug(
            f"Checked risky users. Total found {total_users}. "
            f"Total blocked: {blocked_users}. "
        )

    async def risk_clients_release(self, test_unix_time: int = None):
        """
        Check the blocking time of currently blocked clients and unblock those whose blocking time has expired.

        :param test_unix_time: used as current time in functional tests
        """
        current_time = test_unix_time or int(time.time())
        blocking_seconds = self.app_config.blocking_time_min * 60
        fixed_users_list = list(self.blocked.items())
        total_released = 0

        for key, blocking_user in fixed_users_list:

            if (current_time - blocking_user.blocked_at) < blocking_seconds:
                continue

            total_released += 1
            self.user_release(blocking_user)

        self.user_apply()
        logger.debug(
            f"Checked blocked users ready to release. "
            f"Total found {len(fixed_users_list)}. "
            f"Total released {total_released}"
        )

    async def monitor_new_risk_clients(self):
        """
        Start periodic monitoring of new risky users and block them if necessary
        """
        while True:
            if self.app_config.test_mode:
                return await self.risk_clients_block(
                    test_unix_time=self.app_config.test_unix_time
                )

            asyncio.create_task(self.risk_clients_block())
            await asyncio.sleep(self.app_config.blocking_window_duration_sec)

    async def monitor_release_risk_clients(self):
        """
        Start periodic monitoring of already blocked users and unblock them if necessary.
        """
        while True:
            if self.app_config.test_mode:
                return await self.risk_clients_release(
                    test_unix_time=self.app_config.test_unix_time
                )

            asyncio.create_task(self.risk_clients_release())
            await asyncio.sleep(self.app_config.blocking_release_time_min * 60)

    async def run(self):
        """
        Prepare blocking mechanisms, perform historical analysis if required,
        and start monitoring for blocking and unblocking users.
        """
        for blocking_type in self.app_config.blocking_type:
            self.blockers[blocking_type].prepare()
            self.blocked.update(self.blockers[blocking_type].load())

        logger.debug("Blockers prepared and loaded")

        if len(self.blocked):
            logger.info(f"Total number of already blocked users: {len(self.blocked)}")

        await self.clickhouse_client.connect()
        logger.debug("Established connection to ClickHouse server.")

        await self.clickhouse_client.user_agents_table_create()
        await self.clickhouse_client.user_agents_table_truncate()

        if self.app_config.allowed_user_agents_file_path:
            self.user_agent_manager.read_from_file()
            await self.user_agent_manager.export_to_db()
            logger.info(
                f"Found protected user agents. Total user agents: "
                f"`{len(self.user_agent_manager.user_agents)}`"
            )

        await asyncio.gather(
            *[
                self.detectors[detector].prepare()
                for detector in self.app_config.detectors
            ]
        )
        logger.info("Detectors prepared.")
        logger.info("Preparation is complete. Starting monitoring.")

        if self.app_config.test_mode:
            return

        await asyncio.gather(
            self.monitor_new_risk_clients(),
            self.monitor_release_risk_clients(),
        )
