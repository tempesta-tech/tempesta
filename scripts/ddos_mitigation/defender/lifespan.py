import abc
import asyncio
import time
from defender.context import DDOSMonitorContext
from logger import logger



class BaseState(abc.ABC):
    def __init__(self, context: DDOSMonitorContext):
        self.context = context

    @abc.abstractmethod
    async def run(self):
        pass


class Initialization(BaseState):
    async def run(self):
        for blocking_type in self.context.app_config.blocking_types:
            self.context.blockers[blocking_type].prepare()
            self.context.blocked.update(self.context.blockers[blocking_type].load())

        logger.debug("Blockers prepared and loaded")

        if len(self.context.blocked):
            logger.info(f"Total number of already blocked users: {len(self.context.blocked)}")

        await self.context.clickhouse_client.connect()
        logger.debug("Established connection to ClickHouse server.")

        await self.context.clickhouse_client.user_agents_table_create()
        await self.context.clickhouse_client.user_agents_table_truncate()

        if not self.context.app_config.allowed_user_agents_file_path:
            return

        self.context.user_agent_manager.read_from_file()
        await self.context.user_agent_manager.export_to_db()
        logger.info(
            f"Found protected user agents. Total user agents: "
            f"`{len(self.context.user_agent_manager.user_agents)}`"
        )


class RealModeTraining(BaseState):

    async def _collect_data(self):
        await asyncio.sleep(1)

    async def _update_thresholds(self):
        pass

    async def run(self):
        await self._collect_data()
        await self._update_thresholds()


class HistoricalModeTraining(RealModeTraining):
    ...


class BackgroundMonitoring(BaseState):

    async def _risk_clients_block(self, test_unix_time: int = None):
        """
        Retrieve a batch of newly identified risky clients and block them

        :param test_unix_time: used as current time in functional tests
        """

        total_users = 0
        blocked_users = 0
        current_time = test_unix_time or int(time.time())

        for detector in self.context.app_config.detectors:
            for blocking_user in await self.context.detectors[detector].find_users(
                    current_time
            ):
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

    async def _risk_clients_release(self, test_unix_time: int = None):
        """
        Check the blocking time of currently blocked clients and unblock those whose blocking time has expired.

        :param test_unix_time: used as current time in functional tests
        """
        current_time = test_unix_time or int(time.time())
        blocking_seconds = self.context.app_config.blocking_time_min * 60
        fixed_users_list = list(self.context.blocked.items())
        total_released = 0

        for key, blocking_user in fixed_users_list:

            if (current_time - blocking_user.blocked_at) < blocking_seconds:
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
                return await self._risk_clients_block(
                    test_unix_time=self.context.app_config.test_unix_time
                )

            asyncio.create_task(self._risk_clients_block())
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
            await asyncio.sleep(self.context.app_config.blocking_release_time_min * 60)

    async def run(self):

        await asyncio.gather(
            self._monitor_new_risk_clients(),
            self._monitor_release_risk_clients(),
        )
