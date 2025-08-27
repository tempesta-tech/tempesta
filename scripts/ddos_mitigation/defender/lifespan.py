import abc
import asyncio
import time
from defender.context import AppContext
from utils.datatypes import User
from detectors.base import BaseDetector
from utils.logger import logger



class BaseState(abc.ABC):
    def __init__(self, context: AppContext):
        self.context = context

    @abc.abstractmethod
    async def run(self):
        pass


class Initialization(BaseState):
    def _initialize_blockers(self):
        for blocking_type in self.context.app_config.blocking_types:
            self.context.blockers[blocking_type].prepare()
            self.context.blocked.update(self.context.blockers[blocking_type].load())

        logger.debug("Blockers prepared and loaded")

        if len(self.context.blocked):
            logger.info(f"Total number of already blocked users: {len(self.context.blocked)}")

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

    async def run(self):
        self._initialize_blockers()
        await self._establish_clickhouse_connection()
        await self._load_whitelisted_user_agents()


class AfterInitialization(BaseState):
    async def _load_persistent_users(self, start_at: int, finish_at: int) -> list[User]:
        result = await self.context.clickhouse_client.conn.query(
            f"""
            SELECT 
                min(ja5t), 
                min(ja5h),
                [address],
                min(user_agent) user_agent
            FROM {self.context.clickhouse_client.table_name}
            WHERE 
                timestamp >= toDateTime64({start_at}, 3, 'UTC')
                AND timestamp < toDateTime64({finish_at}, 3, 'UTC')
            GROUP by address
            """
        )
        return [
            User(
                ja5t=user[0],
                ja5h=user[1],
                ipv4=user[2],
            )
            for user in result.result_rows
        ]

    async def _set_persistent_users(self, users: list[User]):
        await self.context.clickhouse_client.persistent_users_table_insert(
            values=[[str(user.ipv4)] for user in users],
        )

    def _get_persistent_users_frame(self) -> tuple[int, int]:
        now = self.context.utc_now
        start_at = now - self.context.app_config.persistent_users_window_offset_sec
        finish_at = start_at + self.context.app_config.persistent_users_window_duration_sec
        return start_at, finish_at

    async def run(self):
        start_at, finish_at = self._get_persistent_users_frame()
        users = await self._load_persistent_users(
            start_at=start_at,
            finish_at=finish_at,
        )
        await self._set_persistent_users(users)


class HistoricalModeTraining(BaseState):
    async def _collect_data(self):
        """
        data is already collected
        :return:
        """

    async def _update_thresholds(self, start_at: int, finish_at: int):
        coroutines = []
        detectors = self.context.active_detectors

        for detector in detectors:
            coroutines.append(detector.fetch_for_period(
                start_at=start_at, finish_at=finish_at
            ))

        users = await asyncio.gather(*coroutines)

        for detector, users in zip(detectors, users):
            values = [item.value for item in users]
            arithmetic_mean = detector.arithmetic_mean(values)
            standard_deviation = detector.standard_deviation(
                values=values,
                arithmetic_mean=arithmetic_mean,
            )
            detector.threshold = arithmetic_mean + standard_deviation

    async def run(self):
        await self._collect_data()

        now = self.context.utc_now
        await self._update_thresholds(
            start_at=now,
            finish_at=now + self.context.app_config.training_mode_duration_sec,
        )


class RealModeTraining(HistoricalModeTraining):

    async def _collect_data(self):
        await asyncio.sleep(self.context.app_config.training_mode_duration_sec)


class BackgroundMonitoring(BaseState):
    @staticmethod
    def __update_threshold(detector: BaseDetector, users: list[User]):
        values = [user.value for user in users]
        arithmetic_mean = detector.arithmetic_mean(values)
        standard_deviation = detector.standard_deviation(
            values=values, arithmetic_mean=arithmetic_mean
        )
        detector.threshold = arithmetic_mean * standard_deviation

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

    async def _update_threshold_and_block_users(self, test_unix_time: int = None):
        """
        Retrieve a batch of newly identified risky clients and block them

        :param test_unix_time: used as current time in functional tests
        """

        current_time = test_unix_time or self.context.utc_now
        detectors = self.context.active_detectors

        users_bulks = await asyncio.gather(*[
            detector.find_users(
                current_time=current_time,
                interval=self.context.app_config.blocking_window_duration_sec
            )
            for detector in detectors
        ])
        list(map(
            lambda group: self.__update_threshold(group[0], group[1][1]),
            zip(detectors, users_bulks)
        ))
        blocking_users_bulks = list(map(
            lambda group: group[0].validate_model(users_before=group[1][0], users_after=group[1][1]),
            zip(detectors, users_bulks)
        ))

        self.__block_users(
            blocking_users_bulks=blocking_users_bulks,
            current_time=current_time
        )

    async def _risk_clients_release(self, test_unix_time: int = None):
        """
        Check the blocking time of currently blocked clients and unblock those whose blocking time has expired.

        :param test_unix_time: used as current time in functional tests
        """
        current_time = test_unix_time or int(time.time())
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
    async def _monitor_new_risk_clients(self):
        """
        Start periodic monitoring of new risky users and block them if necessary
        """
        while True:
            if self.context.app_config.test_mode:
                return await self._update_threshold_and_block_users(
                    test_unix_time=self.context.app_config.test_unix_time
                )

            asyncio.create_task(self._update_threshold_and_block_users())
            await asyncio.sleep(self.context.app_config.blocking_window_duration_sec)

    async def _monitor_release_risk_clients(self):
        """
        Start periodic monitoring of already blocked users and unblock them if necessary.
        """
        while True:
            if self.context.app_config.test_mode:
                return await self._risk_clients_release(
                    test_unix_time=self.context.app_config.test_unix_time
                )

            asyncio.create_task(self._risk_clients_release())
            await asyncio.sleep(self.context.app_config.blocking_release_time_sec)

    async def run(self):

        await asyncio.gather(
            self._monitor_new_risk_clients(),
            self._monitor_release_risk_clients(),
        )
