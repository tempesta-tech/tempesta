import asyncio
import math
import time
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from typing import Generator

from access_log import ClickhouseAccessLog
from blockers.base import BaseBlocker
from config import AppConfig
from datatypes import AverageStats, User
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

    # current rpm threshold
    requests_threshold: Decimal = 0

    # current errors per seconds threshold
    errors_threshold: Decimal = 0

    # current accumulative average per minute response time threshold
    time_threshold: Decimal = 0

    # persistent users which are regular and not risky
    known_users: dict[int, User] = field(default_factory=dict)

    # users found as risky and where blocked
    blocked: dict[int, User] = field(default_factory=dict)

    # Available blockers
    blockers: dict[str, BaseBlocker] = field(default_factory=dict)

    def set_known_users(self, users: list[User]):
        """
        Update the storage of regular, non-risky users.

        :param users: List of user records
        """
        self.known_users = {hash(user): user for user in users}

        if self.known_users:
            logger.info(f"Updated known users:  {self.known_users}")

    def set_thresholds(
        self,
        requests_threshold: Decimal,
        time_threshold: Decimal,
        errors_threshold: Decimal,
    ):
        """
        Update the current threshold values.

        :param requests_threshold: Threshold for requests per minute
        :param time_threshold:  Threshold for accumulated response time
        :param errors_threshold: Threshold for requests with errors per minute
        """
        self.requests_threshold = requests_threshold
        self.time_threshold = time_threshold
        self.errors_threshold = errors_threshold
        logger.info(
            f"Updated live thresholds to: requests={self.requests_threshold}, "
            f"time={self.time_threshold}, "
            f"errors={self.errors_threshold}"
        )

    async def persistent_users_load(
        self,
        start_at: int,
        period_in_seconds: int,
        requests_amount: Decimal,
        time_amount: Decimal,
        users_amount: int,
    ) -> list[User]:
        """
        Analyze user activity over a given period and mark a number of users as "known" (persistent)
        based on either the number of requests or total usage time.

        :param start_at: Start time of the analysis period
        :param period_in_seconds: Duration of the analysis period in seconds
        :param requests_amount: Minimum number of requests required to consider a user as known
        :param time_amount: Minimum total response time required to consider a user as known
        :param users_amount: Maximum number of users to mark as known
        :return: List of users marked as known
        """
        response = await self.clickhouse_client.get_top_risk_clients(
            period_in_seconds=period_in_seconds,
            rps_threshold=requests_amount,
            time_threshold=time_amount,
            errors_threshold=Decimal(99999),
            ja5_hashes_limit=users_amount,
            start_at=start_at,
        )
        return [
            User(
                ja5t=user[0],
                ja5h=user[1],
                ipv4=user[2],
            )
            for user in response.result_rows
        ]

    async def average_stats_load(
        self, start_at: int, period_in_minutes: int
    ) -> AverageStats:
        """
        Get average statistics for all user activity over a given period.
        The results can be used later as default thresholds.

        :param start_at: Start time of the analysis period
        :param period_in_minutes: Duration of the analysis period in minutes
        :return: Statistics for the specified period
        """
        response = await self.clickhouse_client.get_request_stats_for_period(
            start_at=start_at, period_in_minutes=period_in_minutes
        )

        total_seconds = Decimal(period_in_minutes) * Decimal(60)
        requests = Decimal(self.app_config.default_requests_threshold)
        times = Decimal(self.app_config.default_time_threshold)
        errors = Decimal(self.app_config.default_errors_threshold)

        if not math.isnan(response.result_rows[0][0]):
            requests = Decimal(response.result_rows[0][0]) / total_seconds

        if not math.isnan(response.result_rows[1][0]):
            times = Decimal(response.result_rows[1][0]) / total_seconds

        if not math.isnan(response.result_rows[2][0]):
            errors = Decimal(response.result_rows[2][0]) / total_seconds

        return AverageStats(
            requests=requests.quantize(
                Decimal("0.01") * self.app_config.stats_rps_multiplier, ROUND_HALF_UP
            ),
            time=times.quantize(
                Decimal("0.01") * self.app_config.stats_time_multiplier, ROUND_HALF_UP
            ),
            errors=errors.quantize(
                Decimal("0.01") * self.app_config.stats_errors_multiplier, ROUND_HALF_UP
            ),
        )

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

    async def risk_clients_fetch(
        self,
        start_at: int,
        period_in_seconds: int,
        requests_threshold: Decimal,
        time_threshold: Decimal,
        errors_threshold: Decimal,
        hashes_limit: int,
    ) -> list[User]:
        """
        Load risky clients who exceed the current thresholds during a specified time period.

        :param start_at: Start time of the analysis period
        :param period_in_seconds: Duration of the analysis period in seconds
        :param requests_threshold:  Minimum number of requests to be considered risky
        :param time_threshold: Minimum accumulated response time to be considered risky
        :param errors_threshold: Minimum number of errors to be considered risky
        :param hashes_limit: Maximum number of risky clients to return

        :return: List of risky client
        """
        response = await self.clickhouse_client.get_top_risk_clients(
            period_in_seconds=period_in_seconds,
            rps_threshold=requests_threshold,
            time_threshold=time_threshold,
            errors_threshold=errors_threshold,
            ja5_hashes_limit=hashes_limit,
            start_at=start_at,
        )
        return [
            User(
                ja5t=hex(item[0])[2:],
                ja5h=hex(item[1])[2:],
                ipv4=item[2],
                value=item[3],
                type=item[4],
            )
            for item in response.result_rows
        ]

    async def risk_clients_block(self, test_unix_time: int = None):
        """
        Retrieve a batch of newly identified risky clients and block them

        :param test_unix_time: used as current time in functional tests
        """
        current_time = test_unix_time or int(time.time())
        risk_clients = await self.risk_clients_fetch(
            start_at=current_time,
            period_in_seconds=self.app_config.blocking_window_duration_sec,
            requests_threshold=self.requests_threshold,
            time_threshold=self.time_threshold,
            errors_threshold=self.errors_threshold,
            hashes_limit=self.app_config.blocking_ja5_limit,
        )
        users_to_block = self.compare_users(
            new_users=risk_clients,
            already_blocked=self.blocked,
            exclude_users=self.known_users,
        )
        total_users = 0

        for blocking_user in users_to_block:
            total_users += 1
            blocking_user.blocked_at = current_time
            self.user_block(blocking_user)

        self.user_apply()

        logger.debug(f"Checked risky users. Total found {total_users}")

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

    @staticmethod
    def compare_users(
        new_users: list[User],
        already_blocked: dict[int, User],
        exclude_users: dict[int, User] = (),
    ) -> Generator[User, None, None]:
        """
        Perform an intersection of user sets to determine which users need to be blocked.

        :param new_users: Users who have exceeded the defined limits.
        :param already_blocked: Users who are already blocked.
        :param exclude_users: Persistent users to exclude from blocking.

        :return: List of new users that need to be blocked.
        """
        for user in new_users:
            if user in already_blocked:
                continue

            if user in exclude_users:
                continue

            yield user

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
        logger.info(f"Training mode set to `{self.app_config.training_mode.upper()}`")

        await self.clickhouse_client.user_agents_table_create()
        await self.clickhouse_client.user_agents_table_truncate()

        if self.app_config.allowed_user_agents_file_path:
            self.user_agent_manager.read_from_file()
            await self.user_agent_manager.export_to_db()
            logger.info(
                f"Found protected user agents. Total user agents: `{len(self.user_agent_manager.user_agents)}`"
            )

        if self.app_config.training_mode == "real":
            logger.info(
                f"Starting to collect client activity for: {self.app_config.training_mode_duration_min} min."
            )
            await asyncio.sleep(self.app_config.training_mode_duration_min * 60)
            logger.info("Data collection is complete")

        if self.app_config.blocking_type in {"real", "historical"}:
            logger.info("Analyzing user activity for the period")
            known_users = await self.persistent_users_load(
                start_at=int(time.time())
                - self.app_config.persistent_users_window_offset_min * 60,
                period_in_seconds=self.app_config.persistent_users_window_duration_min
                * 60,
                requests_amount=self.app_config.persistent_users_total_requests,
                time_amount=self.app_config.persistent_users_total_time,
                users_amount=self.app_config.persistent_users_total_users,
            )
            self.set_known_users(users=known_users)

            average_stats = await self.average_stats_load(
                start_at=int(time.time()) - self.app_config.stats_window_offset_min,
                period_in_minutes=self.app_config.stats_window_duration_min,
            )
            self.set_thresholds(
                requests_threshold=average_stats.requests,
                time_threshold=average_stats.time,
                errors_threshold=average_stats.errors,
            )
        else:
            self.set_thresholds(
                requests_threshold=self.app_config.default_requests_threshold,
                time_threshold=self.app_config.default_time_threshold,
                errors_threshold=self.app_config.default_errors_threshold,
            )

        logger.info("Preparation is complete. Starting monitoring.")

        if self.app_config.test_mode:
            return

        await asyncio.gather(
            self.monitor_new_risk_clients(),
            self.monitor_release_risk_clients(),
        )
