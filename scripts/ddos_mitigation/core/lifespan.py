import abc
import asyncio

from core.context import AppContext
from utils.datatypes import User
from utils.logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class BaseState(abc.ABC):
    def __init__(self, context: AppContext):
        self.context = context

    @abc.abstractmethod
    async def run(self, testing: bool = False) -> None:
        """
        Execute commands
        """


class Initialization(BaseState):
    def _initialize_blockers(self):
        for blocking_type in self.context.app_config.blocking_types:
            self.context.blockers[blocking_type].prepare()
            self.context.blocked.update(self.context.blockers[blocking_type].load())

        logger.debug("Blockers prepared and loaded")

        if len(self.context.blocked):
            logger.info(
                f"Total number of already blocked users: {len(self.context.blocked)}"
            )

    async def _establish_clickhouse_connection(self):
        await self.context.clickhouse_client.connect()
        logger.debug("Established connection to ClickHouse server.")

        await self.context.clickhouse_client.user_agents_table_create()
        await self.context.clickhouse_client.user_agents_table_truncate()
        await self.context.clickhouse_client.persistent_users_table_create()
        await self.context.clickhouse_client.persistent_users_table_truncate()
        logger.debug("Prepared tables.")

    async def _load_whitelisted_user_agents(self):
        if not self.context.app_config.allowed_user_agents_file_path:
            return

        self.context.user_agent_manager.read_from_file()
        await self.context.user_agent_manager.export_to_db()
        logger.info(
            f"Found protected user agents. Total user agents: "
            f"`{len(self.context.user_agent_manager.user_agents)}`"
        )

    async def run(self, **__) -> None:
        self._initialize_blockers()
        await self._establish_clickhouse_connection()
        await self._load_whitelisted_user_agents()


class LoadPersistentUsers(BaseState):
    async def _load_persistent_users(self, start_at: int, finish_at: int):
        await self.context.clickhouse_client.conn.query(
            f"""
            WITH filtered_our_user_agents as (
                SELECT 
                    address
                FROM {self.context.clickhouse_client.table_name} al
                LEFT ANTI JOIN user_agents ua
                    on al.user_agent = ua.name
                WHERE 
                    timestamp >= toDateTime64({start_at}, 3, 'UTC')
                    AND timestamp < toDateTime64({finish_at}, 3, 'UTC')
            )
            INSERT INTO persistent_users (ip)
            SELECT address
            FROM filtered_our_user_agents
            GROUP by address
            """
        )

    def _get_persistent_users_frame(self) -> tuple[int, int]:
        now = self.context.utc_now
        start_at = now - self.context.app_config.persistent_users_window_offset_sec
        finish_at = (
            start_at + self.context.app_config.persistent_users_window_duration_sec
        )
        return start_at, finish_at

    async def run(self, **__):
        start_at, finish_at = self._get_persistent_users_frame()
        await self._load_persistent_users(
            start_at=start_at,
            finish_at=finish_at,
        )


class HistoricalModeTraining(BaseState):
    async def _update_thresholds(self, start_at: int, finish_at: int):
        coroutines = []
        detectors = self.context.active_detectors

        for detector in detectors:
            coroutines.append(
                detector.fetch_for_period(start_at=start_at, finish_at=finish_at)
            )

        users = await asyncio.gather(*coroutines)

        for detector, users in zip(detectors, users):
            values = [item.value for item in users]
            arithmetic_mean = detector.arithmetic_mean(values)
            standard_deviation = detector.standard_deviation(
                values=values,
                arithmetic_mean=arithmetic_mean,
            )
            detector.threshold = arithmetic_mean + standard_deviation

    async def run(self, **__):
        now = self.context.utc_now
        await self._update_thresholds(
            start_at=now - self.context.app_config.training_mode_duration_sec,
            finish_at=now,
        )


class RealModeTraining(HistoricalModeTraining):

    async def _collect_data(self):
        await asyncio.sleep(self.context.app_config.training_mode_duration_sec)

    async def run(self, **__):
        await self._collect_data()
        await super().run()


class BackgroundRiskyUsersMonitoring(BaseState):
    def __block_users(self, blocking_users_bulks: list[list[User]], current_time: int):
        total_users = 0
        blocked_users = 0

        for bulk in blocking_users_bulks:
            for blocking_user in bulk:
                total_users += 1

                if blocking_user in self.context.blocked:
                    continue

                blocked_users += 1
                blocking_user.blocked_at = current_time
                self.context.user_block(blocking_user)

        self.context.user_apply()

        logger.debug(
            f"Checked risky users. Total found {total_users}. "
            f"Total blocked: {blocked_users}. "
        )

    async def _update_threshold_and_block_users(self):
        """
        Retrieve a batch of newly identified risky clients and block them
        """

        current_time = self.context.utc_now
        detectors = self.context.active_detectors

        users_bulks = await asyncio.gather(
            *[
                detector.find_users(
                    current_time=current_time,
                    interval=self.context.app_config.blocking_window_duration_sec,
                )
                for detector in detectors
            ]
        )

        blocking_users_bulks = []

        for detector, user_bulk in zip(detectors, users_bulks):
            users_before, users_after = user_bulk
            detector.update_threshold(users_after)
            blocking_users_bulks.append(
                detector.validate_model(
                    users_before=users_before,
                    users_after=users_after,
                )
            )

        self.__block_users(
            blocking_users_bulks=blocking_users_bulks, current_time=current_time
        )

    async def run(self, testing: bool = False) -> None:
        """
        Start periodic monitoring of new risky users and block them if necessary
        """
        if testing:
            return await self._update_threshold_and_block_users()

        while True:
            asyncio.create_task(self._update_threshold_and_block_users())
            await asyncio.sleep(self.context.app_config.blocking_window_duration_sec)


class BackgroundReleaseUsersMonitoring(BaseState):

    async def _risk_clients_release(self):
        """
        Check the blocking time of currently blocked clients and unblock those whose blocking time has expired.
        """
        current_time = self.context.utc_now
        blocking_seconds = self.context.app_config.blocking_time_sec
        fixed_users_list = list(self.context.blocked.items())
        total_released = 0

        for key, blocking_user in fixed_users_list:
            time_has_been_blocked = current_time - blocking_user.blocked_at

            if time_has_been_blocked < blocking_seconds:

                continue

            total_released += 1
            self.context.user_release(blocking_user)

        self.context.user_apply()

        logger.debug(
            f"Checked blocked users ready to release. "
            f"Total found {len(fixed_users_list)}. "
            f"Total released {total_released}"
        )

    async def run(self, testing: bool = False) -> None:
        """
        Start periodic monitoring of already blocked users and unblock them if necessary.
        """
        if testing:
            return await self._risk_clients_release()

        while True:
            asyncio.create_task(self._risk_clients_release())
            await asyncio.sleep(self.context.app_config.blocking_release_time_sec)
