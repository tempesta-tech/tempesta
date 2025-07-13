import asyncio
import math
import subprocess
import time
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from ipaddress import IPv4Address
from typing import Generator, Optional

from access_log import ClickhouseAccessLog
from config import AppConfig
from ja5_config import Ja5Config, Ja5Hash
from user_agents import UserAgentsManager

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from logger import logger


@dataclass
class AverageStats:
    requests: Decimal
    time: Decimal
    errors: Decimal


@dataclass
class User:
    ja5t: Optional[int] = None
    ja5h: Optional[int] = None
    ipv4: list[IPv4Address] = ()
    value: Optional[int] = None
    type: Optional[int] = None
    blocked_at: Optional[int] = None

    def __hash__(self):
        return hash(f"ja5t={self.ja5t}/ja5h={self.ja5h}")

    def __eq__(self, other):
        return hash(self) == hash(other)


@dataclass
class DDOSMonitor:
    """
    Manager start two background tasks which periodically block and unblock new users
    """

    # A connected client to Clickhouse Server
    clickhouse_client: ClickhouseAccessLog

    # Loaded ja5t config from path
    ja5t_config: Ja5Config

    # Loaded ja5h config from path
    ja5h_config: Ja5Config

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

    @staticmethod
    def run_in_shell(cmd: str) -> subprocess.CompletedProcess:
        """
        Run command in a shell and return its output

        :param cmd: command to run
        :return: output of command
        """

        return subprocess.run(cmd, shell=True, capture_output=True, text=True)

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

    def ja5t_mark_as_blocked(self, ja5t_hashes: list[int]):
        """
        Update the internal dictionary of blocked users with new JA5T hashes,
        without actually blocking the users.

        :param ja5t_hashes: List of JA5T hashes.
        """
        for hash_value in ja5t_hashes:
            user = User(ja5t=hash_value)
            self.blocked[hash(user)] = user

    def jat5t_block(self, ja5t_value: int):
        """
        Block a specific JA5T hash using Tempesta FW

        :param ja5t_value: JA5T hash of the client
        """
        if self.ja5t_config.exists(ja5t_value):
            return None

        self.ja5t_config.add(Ja5Hash(value=ja5t_value, packets=0, connections=0))

        new_blocking_user = User(ja5t=ja5t_value)
        self.blocked[hash(new_blocking_user)] = new_blocking_user

    def ja5t_release(self, ja5t_value: int):
        """
        Release the JA5T hash in Tempesta FW, lifting the block.

        :param ja5t_value: JA5T hash of the client
        """
        if not self.ja5t_config.exists(ja5t_value):
            return None

        self.ja5t_config.remove(ja5t_value)

        blocking_user_hash = hash(User(ja5t=ja5t_value))
        self.blocked.pop(blocking_user_hash)

    def ja5h_mark_as_blocked(self, ja5h_hashes: list[int]):
        """
        Update the internal dictionary of blocked users with new JA5H hashes,
        without actually blocking the users.

        :param ja5h_hashes: List of JA5H hashes.
        """
        for hash_value in ja5h_hashes:
            user = User(ja5h=hash_value)
            self.blocked[hash(user)] = user

    def ja5h_block(self, ja5h_value: int):
        """
        Block a specific JA5H hash using Tempesta FW

        :param ja5h_value: JA5H hash of the client
        """
        if self.ja5h_config.exists(ja5h_value):
            return None

        self.ja5h_config.add(
            Ja5Hash(
                value=ja5h_value,
                packets=0,
                connections=0,
            )
        )

        new_blocking_user = User(ja5h=ja5h_value)
        self.blocked[hash(new_blocking_user)] = new_blocking_user

    def ja5h_release(self, ja5h_value: int):
        """
        Release the JA5H hash in Tempesta FW, lifting the block.

        :param ja5h_value: JA5H hash of the client
        """
        if not self.ja5h_config.exists(ja5h_value):
            return None

        self.ja5h_config.remove(ja5h_value)

        blocking_user_hash = hash(User(ja5h=ja5h_value))
        self.blocked.pop(blocking_user_hash)

    def ipset_prepare(self):
        """
        Prepare IP sets and iptables for user blocking. Create the required rules and IP sets.
        """
        result = self.run_in_shell("which ipset")

        if result.returncode != 0:
            raise ValueError("IPSET is not installed")

        result = self.run_in_shell(f"ipset list {self.app_config.blocking_ipset_name}")

        if result.returncode != 0:
            if "not permitted" in result.stderr:
                raise PermissionError(
                    "Insufficient permissions to use the `ipset` command. "
                    "Please run the application with root privileges."
                )

            if "name does not exist" in result.stderr:
                result = self.run_in_shell(
                    f"ipset create {self.app_config.blocking_ipset_name} hash:ip"
                )

                if result.returncode != 0:
                    raise ValueError(
                        f"Cannot create IP set using ipset: {result.stderr}"
                    )

        result = self.run_in_shell("iptables -L -v -n")

        if self.app_config.blocking_ipset_name not in result.stdout:
            result = self.run_in_shell(
                f"iptables -I INPUT -m set --match-set {self.app_config.blocking_ipset_name} "
                f"src -j DROP "
            )
            if result.returncode != 0:
                raise ValueError(f"Cannot add IPSet group to iptables: {result.stderr}")

    def ipset_reset(self):
        """
        Remove iptables rules and IP set configuration created by the application.
        """
        result = self.run_in_shell(
            f"iptables -D INPUT -m set --match-set {self.app_config.blocking_ipset_name} "
            f"src -j DROP "
        )

        if result.returncode != 0:
            raise ValueError(f"Cannot remove IPSet group from iptables:{result.stderr}")

        # wait until itables become updated
        time.sleep(0.1)
        result = self.run_in_shell(
            f"ipset destroy {self.app_config.blocking_ipset_name}"
        )

        if result.returncode != 0:
            raise ValueError(f"Cannot remove IPSet group:{result.stderr}")

    def ipset_block(self, ips: list[str]):
        """
        Block users based on the provided list of IP addresses

        :param ips: List of user IP addresses to block
        """
        for ip in ips:
            result = self.run_in_shell(
                f"ipset add {self.app_config.blocking_ipset_name} {ip}"
            )

            if result.returncode != 0:
                if "already added" in result.stderr:
                    logger.error(f"{ip} is already added")
                else:
                    logger.error(f"{ip} can not be added: {result.stderr}")

    def ipset_release(self, ips: list[str]):
        """
        Release users based on the provided list of IP addresses.

        :param ips: List of user IP addresses to unblock
        """
        for ip in ips:
            result = self.run_in_shell(
                f"ipset del {self.app_config.blocking_ipset_name} {ip}"
            )

            if result.returncode != 0:
                if "not added" in result.stderr:
                    logger.error(f"{ip} is missing in ipset")
                else:
                    logger.error(f"{ip} can not be released: {result.stderr}")

    def ipset_info(self) -> bytes:
        """
        Retrieve current information about the IP sets.

        :return: Standard output containing the IP set descriptions
        """
        return self.run_in_shell(
            f"ipset list {self.app_config.blocking_ipset_name}"
        ).stdout

    def nftables_prepare(self):
        """
        Prepare the NFTable table, set, and chain to block users.
        """
        result = self.run_in_shell("which nft")

        if result.returncode != 0:
            raise ValueError("nftables is not installed")

        result = self.run_in_shell(
            f"nft list table inet {self.app_config.blocking_ipset_name}_table"
        )

        if result.returncode != 0 and "No such file or directory" in result.stderr:
            result = self.run_in_shell(
                f"nft add table inet {self.app_config.blocking_ipset_name}_table"
            )

            if result.returncode != 0:
                raise ValueError(f"Cannot add new table to nft: {result.stderr}")

        elif result.returncode != 0:
            raise ValueError(f"Cannot list nft table: {result.stderr}")

        result = self.run_in_shell(
            f"nft list set inet {self.app_config.blocking_ipset_name}_table "
            f"{self.app_config.blocking_ipset_name}"
        )

        if result.returncode != 0 and "No such file or directory" in result.stderr:
            result = self.run_in_shell(
                f"nft add set inet {self.app_config.blocking_ipset_name}_table "
                f"{self.app_config.blocking_ipset_name} {{ type ipv4_addr\; flags interval\; }}"
            )

            if result.returncode != 0:
                raise ValueError(f"Cannot add new set to nft: {result.stderr}")

        elif result.returncode != 0:
            raise ValueError(f"Cannot list nft set: {result.stderr}")

        result = self.run_in_shell(
            f"nft list chain inet {self.app_config.blocking_ipset_name}_table input"
        )

        if result.returncode != 0 and "No such file or directory" in result.stderr:
            result = self.run_in_shell(
                f"nft add chain inet {self.app_config.blocking_ipset_name}_table "
                f"input {{ type filter hook input priority 0\; }}"
            )

            if result.returncode != 0:
                raise ValueError(f"Cannot add chain to nft: {result.stderr}")

        elif result.returncode != 0:
            raise ValueError(f"Cannot list nft chain: {result.stderr}")

        result = self.run_in_shell(
            f"nft list chain inet {self.app_config.blocking_ipset_name}_table input | grep "
            f"saddr @{self.app_config.blocking_ipset_name} drop"
        )

        if result.returncode != 0:
            result = self.run_in_shell(
                f"nft add rule inet {self.app_config.blocking_ipset_name}_table "
                f"input ip saddr @{self.app_config.blocking_ipset_name} drop"
            )

            if result.returncode != 0:
                raise ValueError(f"Cannot add rule to nft: {result.stderr}")

    def nftables_reset(self):
        """
        Delete the NFTable configuration created by the application
        """
        result = self.run_in_shell(
            f"nft flush table inet {self.app_config.blocking_ipset_name}_table"
        )

        if result.returncode != 0:
            raise ValueError(f"Cannot flush nft table: {result.stderr}")

        result = self.run_in_shell(
            f"nft delete table inet {self.app_config.blocking_ipset_name}_table"
        )

        if result.returncode != 0:
            raise ValueError(f"Cannot delete nft table: {result.stderr}")

    def nftables_block(self, ips: list[str]):
        """
        Block users based on the provided list of IP addresses

        :param ips: List of user IP addresses to block
        """
        for ip in ips:
            result = self.run_in_shell(
                f"nft add element inet {self.app_config.blocking_ipset_name}_table "
                f"{self.app_config.blocking_ipset_name} {{ {ip} }}"
            )

            if result.returncode != 0:
                logger.error(f"Cannot block ip by nft: {result.stderr}")

    def nftables_release(self, ips: list[str]):
        """
        Release users based on the provided list of IP addresses.

        :param ips: List of user IP addresses to unblock
        """
        for ip in ips:
            result = self.run_in_shell(
                f"nft delete element inet {self.app_config.blocking_ipset_name}_table "
                f"{self.app_config.blocking_ipset_name} {{ {ip} }}"
            )

            if result.returncode != 0:
                logger.error(f"Cannot release ip by nft: {result.stderr}")

    def nftables_info(self):
        """
        Retrieve current information about the blocking table.

        :return: Standard output containing the blocking table descriptions
        """
        return self.run_in_shell(
            f"nft list table inet {self.app_config.blocking_ipset_name}_table"
        ).stdout

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
            requests=requests.quantize(Decimal("0.01"), ROUND_HALF_UP),
            time=times.quantize(Decimal("0.01"), ROUND_HALF_UP),
            errors=errors.quantize(Decimal("0.01"), ROUND_HALF_UP),
        )

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
            User(ja5t=item[0], ja5h=item[1], ipv4=item[2], value=item[3], type=item[4])
            for item in response.result_rows
        ]

    async def risk_clients_block(self):
        """
        Retrieve a batch of newly identified risky clients and block them
        """
        risk_clients = await self.risk_clients_fetch(
            start_at=int(time.time()),
            period_in_seconds=self.app_config.blocking_time_min,
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

        for blocking_user in users_to_block:
            if "ja5t" in self.app_config.blocking_type:
                self.jat5t_block(blocking_user.ja5t)

            if "ja5h" in self.app_config.blocking_type:
                self.ja5h_block(blocking_user.ja5h)

            if "ipset" in self.app_config.blocking_type:
                self.ipset_block([str(ip) for ip in blocking_user.ipv4])

            if "nftables" in self.app_config.blocking_type:
                self.nftables_block([str(ip) for ip in blocking_user.ipv4])

            logger.warning(
                f"Blocked user {blocking_user} by {self.app_config.blocking_type}"
            )

        self.tempesta_dump_config_and_reload()

    async def risk_clients_release(self):
        """
        Check the blocking time of currently blocked clients and unblock those whose blocking time has expired.
        """
        current_time = int(time.time())
        blocking_seconds = self.app_config.blocking_time_min * 60

        fixed_users_list = list(self.blocked.items())
        for key, blocking_user in fixed_users_list:

            if (current_time - blocking_user.blocked_at) < blocking_seconds:
                continue

            if "ja5t" in self.app_config.blocking_type:
                self.ja5t_release(blocking_user.ja5t)

            if "ja5h" in self.app_config.blocking_type:
                self.ja5h_release(blocking_user.ja5h)

            if "ipset" in self.app_config.blocking_type:
                self.ipset_release([str(ip) for ip in blocking_user.ipv4])

            if "nftables" in self.app_config.blocking_type:
                self.nftables_release([str(ip) for ip in blocking_user.ipv4])

            logger.warning(
                f"Released user {blocking_user} by {self.app_config.blocking_type}"
            )

        self.tempesta_dump_config_and_reload()

    def tempesta_reload(self):
        """
        Reload the Tempesta FW configuration to apply updated JA5T and JA5H rules.
        """
        if self.app_config.tempesta_executable_path:
            result = self.run_in_shell(
                f"{self.app_config.tempesta_executable_path} --reload"
            )

            if result.returncode != 0:
                raise ValueError(f"tempesta could not be reloaded: {result.stderr}")

            return

        result = self.run_in_shell("service tempesta --reload")

        if result.returncode != 0:
            raise ValueError(f"tempesta could not be reloaded: {result.stderr}")

    def tempesta_dump_config_and_reload(self):
        """
        Check configs of ja5t and ja5h. Dump one if was changed and reload Tempesta FW configuration.
        """
        need_to_reload_tempesta = False

        if "ja5t" in self.app_config.blocking_type and self.ja5t_config.need_dump:
            self.ja5t_config.dump()
            need_to_reload_tempesta = True

        if "ja5h" in self.app_config.blocking_type and self.ja5h_config.need_dump:
            self.ja5h_config.dump()
            need_to_reload_tempesta = True

        if need_to_reload_tempesta:
            self.tempesta_reload()

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
            asyncio.create_task(self.risk_clients_block())
            await asyncio.sleep(self.app_config.blocking_time_slice)

    async def monitor_release_risk_clients(self):
        """
        Start periodic monitoring of already blocked users and unblock them if necessary.
        """
        while True:
            asyncio.create_task(self.risk_clients_release())
            await asyncio.sleep(self.app_config.blocking_release_time_minutes)

    async def run(self):
        """
        Prepare blocking mechanisms, perform historical analysis if required,
        and start monitoring for blocking and unblocking users.
        """
        self.ja5t_config.load()
        self.ja5h_config.load()
        logger.debug("JA5T and JA5H configurations loaded")

        self.ja5t_mark_as_blocked(list(self.ja5t_config.hashes))
        self.ja5h_mark_as_blocked(list(self.ja5h_config.hashes))

        if len(self.blocked):
            logger.info(
                f"Total number of already blocked users in JA5 configurations: {len(self.blocked)}"
            )

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

        if self.app_config.blocking_mode in {"real", "historical"}:
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
        await asyncio.gather(
            self.monitor_new_risk_clients(),
            self.monitor_release_risk_clients(),
        )
