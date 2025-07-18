import os
import time
from decimal import Decimal

from clickhouse_connect.driverc.dataconv import IPv4Address

from blockers import blockers
from config import AppConfig
from defender import DDOSMonitor, User
from ja5_config import Ja5Config
from tests.base import BaseTestCaseWithFilledDB
from user_agents import UserAgentsManager

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestMitigation(BaseTestCaseWithFilledDB):
    async def asyncSetUp(self):
        await super().asyncSetUp()

        self.ja5t_config_path = "/tmp/test_ja5t_config"
        self.ja5h_config_path = "/tmp/test_ja5h_config"
        self.fake_tempesta_executable = "/tmp/test_fake_tempesta_executable"
        self.user_agents_fake_config = "/tmp/test_user_agents_fake_config"

        open(self.ja5t_config_path, "w").close()
        open(self.ja5h_config_path, "w").close()
        open(self.fake_tempesta_executable, "w").close()
        open(self.user_agents_fake_config, "w").close()

        self.ja5t_config = Ja5Config(self.ja5t_config_path)
        self.ja5h_config = Ja5Config(self.ja5h_config_path)

        self.monitor = DDOSMonitor(
            blockers={
                blockers.Ja5tBlocker.name(): blockers.Ja5tBlocker(
                    config=Ja5Config(file_path=self.ja5t_config_path),
                ),
                blockers.Ja5hBlocker.name(): blockers.Ja5hBlocker(
                    config=Ja5Config(file_path=self.ja5h_config_path),
                ),
                blockers.IpSetBlocker.name(): blockers.IpSetBlocker(
                    blocking_ip_set_name=self.app_config.blocking_ipset_name,
                ),
                blockers.NFTBlocker.name(): blockers.NFTBlocker(
                    blocking_table_name=self.app_config.blocking_ipset_name,
                ),
            },
            clickhouse_client=self.access_log,
            app_config=AppConfig(),
            user_agent_manager=UserAgentsManager(
                clickhouse_client=self.access_log, config_path=""
            ),
        )

    async def asyncTearDown(self):
        await super().asyncTearDown()

        self.monitor.user_reset()

        os.remove(self.ja5t_config_path)
        os.remove(self.ja5h_config_path)
        os.remove(self.fake_tempesta_executable)
        os.remove(self.user_agents_fake_config)

    def test_hash_risk_user_function(self):
        risk_user_1 = User(ja5t="1")
        risk_user_2 = User(ja5t="2")
        risk_user_3 = User(ja5t="2")

        self.assertEqual(hash(risk_user_2), hash(risk_user_3))
        self.assertNotEqual(hash(risk_user_1), hash(risk_user_3))

    def test_set_thresholds(self):
        self.monitor.set_thresholds(
            requests_threshold=Decimal(1),
            time_threshold=Decimal(2),
            errors_threshold=Decimal(3),
        )
        self.assertEqual(self.monitor.requests_threshold, 1)
        self.assertEqual(self.monitor.time_threshold, 2)
        self.assertEqual(self.monitor.errors_threshold, 3)

    async def test_set_known_users(self):
        risk_user = User(ja5t="1")
        self.monitor.set_known_users([risk_user])
        self.assertEqual(len(self.monitor.known_users), 1)
        self.assertIn(hash(risk_user), self.monitor.known_users)

    async def test_persistent_users_load(self):
        result = await self.monitor.persistent_users_load(
            start_at=1751535000,
            period_in_seconds=10,
            requests_amount=Decimal(1),
            time_amount=Decimal(1),
            users_amount=1,
        )
        self.assertEqual(
            result,
            [
                User(
                    ja5t="11",
                    ja5h="21",
                    ipv4=[IPv4Address("127.0.0.1")],
                    value=None,
                    type=None,
                    blocked_at=None,
                )
            ],
        )

    async def test_average_stats_load(self):
        result = await self.monitor.average_stats_load(
            start_at=1751535000, period_in_minutes=1
        )
        self.assertEqual(
            result.requests, self.monitor.app_config.default_requests_threshold
        )
        self.assertEqual(result.time, self.monitor.app_config.default_time_threshold)
        self.assertEqual(
            result.errors, self.monitor.app_config.default_errors_threshold
        )

        result = await self.monitor.average_stats_load(
            start_at=1751534999, period_in_minutes=1
        )
        self.assertEqual(result.requests, Decimal("0.02"))
        self.assertEqual(result.time, Decimal("0.17"))
        self.assertEqual(result.errors, Decimal("0.0"))

    async def test_risk_clients_fetch(self):
        result = await self.monitor.risk_clients_fetch(
            start_at=1751535000,
            period_in_seconds=10,
            requests_threshold=Decimal(1),
            time_threshold=Decimal(10),
            errors_threshold=Decimal(1),
            hashes_limit=10,
        )
        self.assertEqual(
            result,
            [
                User(
                    ja5t="b",
                    ja5h="15",
                    ipv4=[IPv4Address("127.0.0.1")],
                    value=1,
                    type=0,
                )
            ],
        )

    def test_compare_users(self):
        generator = self.monitor.compare_users(
            new_users=[User(ja5t="11")], already_blocked=dict(), exclude_users=dict()
        )
        self.assertEqual(list(generator), [User(ja5t="11")])

    async def test_risk_clients_block(self):
        async def fake_db_response(*_, **__):

            class Response:
                result_rows = [(11, 12, "127.0.0.1", 1, 0)]

            return Response

        self.monitor.clickhouse_client.get_top_risk_clients = fake_db_response

        await self.monitor.risk_clients_block()
        self.assertEqual(len(self.monitor.blocked), 1)

    async def test_risk_clients_block_empty_list(self):
        async def fake_db_response(*_, **__):

            class Response:
                result_rows = []

            return Response

        self.monitor.clickhouse_client.get_top_risk_clients = fake_db_response

        await self.monitor.risk_clients_block()
        self.assertEqual(len(self.monitor.blocked), 0)

    async def test_risk_clients_release(self):
        blocked_at = int(time.time())
        blocked_at -= self.monitor.app_config.blocking_time_min * 60
        # to be sure
        blocked_at -= 1

        self.monitor.user_block(User(ja5t="11"))
        self.monitor.blocked[hash(User(ja5t="11"))].blocked_at = blocked_at

        await self.monitor.risk_clients_release()
        self.assertEqual(len(self.monitor.blocked), 0)

    async def test_risk_clients_release_empty_list(self):
        await self.monitor.risk_clients_release()
        self.assertEqual(len(self.monitor.blocked), 0)

    async def test_run(self):
        self.monitor.blockers["ja5t"].tempesta_executable_path = (
            self.fake_tempesta_executable
        )
        self.monitor.blockers["ja5h"].tempesta_executable_path = (
            self.fake_tempesta_executable
        )

        self.monitor.user_agent_manager.config_path = self.user_agents_fake_config

        self.monitor.app_config.clickhouse_database = "test_db"
        self.monitor.app_config.test_mode = True
        self.monitor.app_config.test_unix_time = 1751535001
        self.monitor.app_config.blocking_window_duration_sec = 10

        await self.monitor.run()
        self.monitor.set_thresholds(
            requests_threshold=Decimal(0),
            time_threshold=Decimal(0),
            errors_threshold=Decimal(0),
        )

        await self.monitor.monitor_new_risk_clients()
        self.assertEqual(len(self.monitor.blocked), 1)

        await self.monitor.monitor_release_risk_clients()
        self.assertEqual(len(self.monitor.blocked), 1)

        self.monitor.app_config.test_unix_time = 1751535001
        self.monitor.app_config.test_unix_time = (
            +self.monitor.app_config.blocking_time_min * 60
        )

        await self.monitor.monitor_release_risk_clients()
        self.assertEqual(len(self.monitor.blocked), 1)
