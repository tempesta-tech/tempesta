import asyncio
import math
import time
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal

from access_log import ClickhouseAccessLog
from config import AppConfig
from datatypes import AverageStats, User
from detectors.base import BaseDetector
from logger import logger


@dataclass
class ThresholdDetector(BaseDetector):
    clickhouse_client: ClickhouseAccessLog
    app_config: AppConfig

    # current rpm threshold
    requests_threshold: Decimal = 0

    # current errors per seconds threshold
    errors_threshold: Decimal = 0

    # current accumulative average per minute response time threshold
    time_threshold: Decimal = 0

    start_at: int = 0

    # persistent users which are regular and not risky
    known_users: dict[int, User] = field(default_factory=dict)

    # minutes multipliers
    seconds_in_minute: int = 60

    @staticmethod
    def name() -> str:
        return "threshold"

    @staticmethod
    def compare_users(
        new_users: list[User],
        exclude_users: dict[int, User] = (),
    ) -> list[User]:
        """
        Perform an intersection of user sets to determine which users need to be blocked.

        :param new_users: Users who have exceeded the defined limits.
        :param exclude_users: Persistent users to exclude from blocking.

        :return: List of new users that need to be blocked.
        """
        result = []
        for user in new_users:
            if user in exclude_users:
                continue

            result.append(user)

        return result

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

        total_seconds = Decimal(period_in_minutes) * Decimal(self.seconds_in_minute)
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

    async def prepare(self):
        logger.info(f"Training mode set to `{self.app_config.training_mode.upper()}`")

        if self.app_config.training_mode == "real":
            logger.info(
                f"Starting to collect client activity for:"
                f" {self.app_config.training_mode_duration_min} min."
            )
            await asyncio.sleep(
                self.app_config.training_mode_duration_min * self.seconds_in_minute
            )
            logger.info("Data collection is complete")

        if self.app_config.blocking_type in {"real", "historical"}:
            logger.info("Analyzing user activity for the period")
            known_users = await self.persistent_users_load(
                start_at=int(time.time())
                - self.app_config.persistent_users_window_offset_min
                * self.seconds_in_minute,
                period_in_seconds=self.app_config.persistent_users_window_duration_min
                * self.seconds_in_minute,
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

    async def find_users(self, current_time: int = None) -> list[User]:
        _current_time = current_time or int(time.time())
        risk_clients = await self.risk_clients_fetch(
            start_at=_current_time,
            period_in_seconds=self.app_config.blocking_window_duration_sec,
            requests_threshold=self.requests_threshold,
            time_threshold=self.time_threshold,
            errors_threshold=self.errors_threshold,
            hashes_limit=self.app_config.blocking_ja5_limit,
        )
        return self.compare_users(
            new_users=risk_clients,
            exclude_users=self.known_users,
        )
