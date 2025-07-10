from ja5_config import Ja5Config, Ja5Hash
import time
from ipaddress import IPv4Address
from decimal import Decimal, ROUND_HALF_UP
import subprocess
import asyncio
from dataclasses import dataclass
from typing import Generator, Optional
from config import AppConfig
from access_log import ClickhouseAccessLog
import math


@dataclass
class AverageStats:
    requests: Decimal
    time: Decimal
    errors: Decimal


@dataclass
class RiskUser:
    ja5t: Optional[int] = None
    ja5h: Optional[int] = None
    ipv4: list[IPv4Address] = ()
    value: Optional[int] = None
    type: Optional[int] = None
    blocked_at: Optional[int] = None

    def __hash__(self):
        return hash(f'ja5t={self.ja5t}/ja5h={self.ja5h}')

    def __eq__(self, other):
        return hash(self) == hash(other)


class DDOSMonitor:
    def __init__(
            self,
            clickhouse_client: ClickhouseAccessLog,
            ja5t_config: Ja5Config,
            ja5h_config: Ja5Config,
            app_config: AppConfig
    ):
        self.clickhouse_client = clickhouse_client
        self.ja5t_config = ja5t_config
        self.ja5h_config = ja5h_config
        self.app_config = app_config

        self.requests_threshold = None
        self.errors_threshold = None
        self.time_threshold = None

        self.known_users: dict[int, RiskUser] = {}
        self.blocked: dict[int, RiskUser] = {}

    @staticmethod
    def run_in_shell(cmd: str) -> subprocess.CompletedProcess:
        """
        Run command in a shell and return its output

        :param cmd: command to run
        :return: output of command
        """

        return subprocess.run(cmd, shell=True, capture_output=True, text=True)

    def set_known_users(self, users: list[RiskUser]):
        self.known_users = {hash(user): user for user in users}

    def set_thresholds(self, requests_threshold: int, time_threshold: int, errors_threshold: int):
        self.requests_threshold = requests_threshold
        self.time_threshold = time_threshold
        self.errors_threshold = errors_threshold

    def load_blocked_users_from_ja5t_hashes(self, ja5t_hashes: list[int]):
        for hash_value in ja5t_hashes:
            user = RiskUser(ja5t=hash_value)
            self.blocked[hash(user)] = user

    def load_blocked_users_from_ja5h_hashes(self, ja5h_hashes: list[int]):
        for hash_value in ja5h_hashes:
            user = RiskUser(ja5h=hash_value)
            self.blocked[hash(user)] = user

    def block_by_ja5t(self, ja5t_value: int):
        if self.ja5t_config.exists(ja5t_value):
            return None

        self.ja5t_config.add(Ja5Hash(
            value=ja5t_value,
            packets=0,
            connections=0
        ))

        new_blocking_user = RiskUser(ja5t=ja5t_value)
        self.blocked[hash(new_blocking_user)] = new_blocking_user

    def unblock_by_ja5t(self, ja5t_value: int):
        if not self.ja5t_config.exists(ja5t_value):
            return None

        self.ja5t_config.remove(ja5t_value)

        blocking_user_hash = hash(RiskUser(ja5t=ja5t_value))
        self.blocked.pop(blocking_user_hash)

    def block_by_ja5h(self, ja5h_value: int):
        if self.ja5h_config.exists(ja5h_value):
            return None

        self.ja5h_config.add(Ja5Hash(
            value=ja5h_value,
            packets=0,
            connections=0,
        ))

        new_blocking_user = RiskUser(ja5h=ja5h_value)
        self.blocked[hash(new_blocking_user)] = new_blocking_user

    def unblock_by_ja5h(self, ja5h_value: int):
        if not self.ja5h_config.exists(ja5h_value):
            return None

        self.ja5h_config.remove(ja5h_value)

        blocking_user_hash = hash(RiskUser(ja5h=ja5h_value))
        self.blocked.pop(blocking_user_hash)

    def prepare_ipset(self):
        result = self.run_in_shell('which ipset')

        if result.returncode != 0:
            raise ValueError('ipset is not installed')

        result = self.run_in_shell(f'ipset list {self.app_config.blocking_ipset_name}')

        if result.returncode != 0:
            if 'not permitted' in result.stderr:
                raise PermissionError(
                    'Does not have permission to use ipset command. '
                    'Please, run app with root permissions.'
                )

            if 'name does not exist' in result.stderr:
                result = self.run_in_shell(f'ipset create {self.app_config.blocking_ipset_name} hash:ip')

                if result.returncode != 0:
                    raise ValueError(f'cant not create set of ips with ipset: {result.stderr}')

        result = self.run_in_shell('iptables -L -v -n')

        if self.app_config.blocking_ipset_name not in result.stdout:
            result = self.run_in_shell(
                f'iptables -I INPUT -m set --match-set {self.app_config.blocking_ipset_name} '
                f'src -j DROP '
            )
            if result.returncode != 0:
                raise ValueError(f'cant add ipset group to the iptables: {result.stderr}')

    def reset_ipset(self):
        result = self.run_in_shell(
            f'iptables -D INPUT -m set --match-set {self.app_config.blocking_ipset_name} '
            f'src -j DROP '
        )

        if result.returncode != 0:
            raise ValueError(f'cant remove ipset group from the iptables: {result.stderr}')

        # wait until itables become updated
        time.sleep(0.1)
        result = self.run_in_shell(f'ipset destroy {self.app_config.blocking_ipset_name}')

        if result.returncode != 0:
            raise ValueError(f'cant remove ipset group: {result.stderr}')

    def get_ipset_info(self):
        return self.run_in_shell(f'ipset list {self.app_config.blocking_ipset_name}').stdout

    def block_by_ip_with_ipset(self, ips: list[str]):
        for ip in ips:
            result = self.run_in_shell(f'ipset add {self.app_config.blocking_ipset_name} {ip}')

            if result.returncode != 0:
                if 'already added' in result.stderr:
                    print('ip already added')
                else:
                    print(result.stderr)

    def unblock_by_ip_with_ipset(self, ips: list[str]):
        for ip in ips:
            result = self.run_in_shell(f'ipset del {self.app_config.blocking_ipset_name} {ip}')

            if result.returncode != 0:
                if 'not added' in result.stderr:
                    print('ip already added')
                else:
                    print(result.stderr)

    def prepare_nftables(self):
        result = self.run_in_shell('which nft')

        if result.returncode != 0:
            raise ValueError('nftables is not installed')

        result = self.run_in_shell(f'nft list table inet {self.app_config.blocking_ipset_name}_table')

        if result.returncode != 0 and 'No such file or directory' in result.stderr:
            result = self.run_in_shell(f'nft add table inet {self.app_config.blocking_ipset_name}_table')

            if result.returncode != 0:
                raise ValueError(f'nftable - cant add new table: {result.stderr}')

        elif result.returncode != 0:
            raise ValueError(f'unexpected error {result.stderr}')

        result = self.run_in_shell(
            f'nft list set inet {self.app_config.blocking_ipset_name}_table '
            f'{self.app_config.blocking_ipset_name}'
        )

        if result.returncode != 0 and 'No such file or directory' in result.stderr:
            result = self.run_in_shell(
                f'nft add set inet {self.app_config.blocking_ipset_name}_table '
                f'{self.app_config.blocking_ipset_name} {{ type ipv4_addr\; flags interval\; }}')

            if result.returncode != 0:
                raise ValueError(f'nftable - cant add new set: {result.stderr}')

        elif result.returncode != 0:
            raise ValueError(f'unexpected error {result.stderr}')

        result = self.run_in_shell(
            f'nft list chain inet {self.app_config.blocking_ipset_name}_table input'
        )

        if result.returncode != 0 and 'No such file or directory' in result.stderr:
            result = self.run_in_shell(
                f'nft add chain inet {self.app_config.blocking_ipset_name}_table '
                f'input {{ type filter hook input priority 0\; }}'
            )

            if result.returncode != 0:
                raise ValueError(f'nftable - cant add new chain: {result.stderr}')

        elif result.returncode != 0:
            raise ValueError(f'unexpected error {result.stderr}')

        result = self.run_in_shell(
            f'nft list chain inet {self.app_config.blocking_ipset_name}_table input | grep '
            f'saddr @{self.app_config.blocking_ipset_name} drop'
        )

        if result.returncode != 0:
            result = self.run_in_shell(
                f'nft add rule inet {self.app_config.blocking_ipset_name}_table '
                f'input ip saddr @{self.app_config.blocking_ipset_name} drop'
            )

            if result.returncode != 0:
                raise ValueError(f'nftable - cant add new rule: {result.stderr}')

    def reset_nftables(self):
        result = self.run_in_shell(f'nft flush table inet {self.app_config.blocking_ipset_name}_table')

        if result.returncode != 0:
            raise ValueError(f'nftable - cant flush table: {result.stderr}')

        result = self.run_in_shell(f'nft delete table inet {self.app_config.blocking_ipset_name}_table')

        if result.returncode != 0:
            raise ValueError(f'nftable - cant delete table: {result.stderr}')

    def block_by_ip_with_nftables(self, ips: list[str]):
        for ip in ips:
            result = self.run_in_shell(
                f'nft add element inet {self.app_config.blocking_ipset_name}_table '
                f'{self.app_config.blocking_ipset_name} {{ {ip} }}'
            )

            if result.returncode != 0:
                print(f'can not add ip to blocking = {result.stderr}')

    def unblock_by_ip_with_nftables(self, ips: list[str]):
        for ip in ips:
            result = self.run_in_shell(
                f'nft delete element inet {self.app_config.blocking_ipset_name}_table '
                f'{self.app_config.blocking_ipset_name} {{ {ip} }}'
            )

            if result.returncode != 0:
                print(f'can not remove ip from blocking = {result.stderr}')

    def get_info_about_nftables(self):
        return self.run_in_shell(f'nft list table inet {self.app_config.blocking_ipset_name}_table').stdout

    async def load_last_real_users(
            self,
            start_at: int,
            time_long: int,
            requests_amount: int,
            time_amount: int,
            users_amount: int,
    ) -> list[RiskUser]:
        response = await self.clickhouse_client.get_top_risk_clients(
            time_frame_seconds=time_long,
            rps_threshold=requests_amount,
            time_threshold=time_amount,
            errors_threshold=99999,
            ja5_hashes_limit=users_amount,
            time_from=start_at,
        )
        return [RiskUser(
            ja5t=user[0],
            ja5h=user[1],
            ipv4=user[2],
        ) for user in response.result_rows]

    async def get_stats_for_period(self, time_from: int, period_in_minutes: int) -> AverageStats:
        response = await self.clickhouse_client.get_stats_for_period(
            start_at=time_from,
            period_in_minutes=period_in_minutes
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
            requests=requests.quantize(Decimal('0.01'), ROUND_HALF_UP),
            time=times.quantize(Decimal('0.01'), ROUND_HALF_UP),
            errors=errors.quantize(Decimal('0.01'), ROUND_HALF_UP),
        )

    async def get_risk_clients(
            self,
            time_from: int,
            time_frame_seconds: int,
            requests_threshold: int,
            time_threshold: int,
            errors_threshold: int,
            hashes_limit: int
    ) -> list[RiskUser]:
        response = await self.clickhouse_client.get_top_risk_clients(
            time_frame_seconds=time_frame_seconds,
            rps_threshold=requests_threshold,
            time_threshold=time_threshold,
            errors_threshold=errors_threshold,
            ja5_hashes_limit=hashes_limit,
            time_from=time_from,
        )
        return [RiskUser(
            ja5t=item[0],
            ja5h=item[1],
            ipv4=item[2],
            value=item[3],
            type=item[4]
        ) for item in response.result_rows]

    def tempesta_apply_config(self):
        if self.app_config.tempesta_executable_path:
            result = self.run_in_shell(f'{self.app_config.tempesta_executable_path} --reload')

            if result.returncode != 0:
                raise ValueError(f'tempesta could not be reloaded: {result.stderr}')

            return

        result = self.run_in_shell('service tempesta --reload')

        if result.returncode != 0:
            raise ValueError(f'tempesta could not be reloaded: {result.stderr}')

    @staticmethod
    def compare_users(
            new_users: list[RiskUser],
            already_blocked: dict[int, RiskUser],
            exclude_users: dict[int, RiskUser] = ()
    ) -> Generator[RiskUser, None, None]:
        for user in new_users:
            if user in already_blocked:
                continue

            if user in exclude_users:
                continue

            yield user

    async def find_new_risk_users(self):
        risk_clients = await self.get_risk_clients(
            time_from=int(time.time()),
            time_frame_seconds=self.app_config.blocking_time_slice,
            requests_threshold=self.requests_threshold,
            time_threshold=self.time_threshold,
            errors_threshold=self.errors_threshold,
            hashes_limit=self.app_config.blocking_ja5_limit,
        )
        users_to_block = self.compare_users(
            new_users=risk_clients,
            already_blocked=self.blocked,
            exclude_users=self.known_users
        )

        for blocking_user in users_to_block:
            if 'ja5t' in self.app_config.blocking_type:
                self.block_by_ja5t(blocking_user.ja5t)

            if 'ja5h' in self.app_config.blocking_type:
                self.block_by_ja5h(blocking_user.ja5h)

            if 'ipset' in self.app_config.blocking_type:
                self.block_by_ip_with_ipset([str(ip) for ip in blocking_user.ipv4])

            if 'nftables' in self.app_config.blocking_type:
                self.block_by_ip_with_nftables([str(ip) for ip in blocking_user.ipv4])

        need_to_reload_tempesta = False

        if 'ja5t' in self.app_config.blocking_type and self.ja5t_config.need_dump:
            self.ja5t_config.dump()
            need_to_reload_tempesta = True

        if 'ja5h' in self.app_config.blocking_type and self.ja5h_config.need_dump:
            self.ja5h_config.dump()
            need_to_reload_tempesta = True

        if need_to_reload_tempesta:
            self.tempesta_apply_config()

    async def release_blocked_users(self):
        current_time = int(time.time())
        blocking_seconds = self.app_config.blocking_default_time_minutes * 60

        fixed_users_list = list(self.blocked.items())
        for key, blocking_user in fixed_users_list:

            if (current_time - blocking_user.blocked_at) < blocking_seconds:
                continue

            if 'ja5t' in self.app_config.blocking_type:
                self.unblock_by_ja5t(blocking_user.ja5t)

            if 'ja5h' in self.app_config.blocking_type:
                self.unblock_by_ja5h(blocking_user.ja5h)

            if 'ipset' in self.app_config.blocking_type:
                self.unblock_by_ip_with_ipset([str(ip) for ip in blocking_user.ipv4])

            if 'nftables' in self.app_config.blocking_type:
                self.unblock_by_ip_with_nftables([str(ip) for ip in blocking_user.ipv4])

        need_to_reload_tempesta = False

        if 'ja5t' in self.app_config.blocking_type and self.ja5t_config.need_dump:
            self.ja5t_config.dump()
            need_to_reload_tempesta = True

        if 'ja5h' in self.app_config.blocking_type and self.ja5h_config.need_dump:
            self.ja5h_config.dump()
            need_to_reload_tempesta = True

        if need_to_reload_tempesta:
            self.tempesta_apply_config()

    async def monitor_new_risk_clients(self):
        while True:
            asyncio.create_task(self.find_new_risk_users())
            await asyncio.sleep(self.app_config.blocking_time_slice)

    async def monitor_unblock_risk_clients(self):
        while True:
            asyncio.create_task(self.tempesta_apply_config())
            await asyncio.sleep(self.app_config.blocking_release_time_minutes)

    async def run(self):
        self.ja5t_config.load()
        self.ja5h_config.load()

        self.load_blocked_users_from_ja5t_hashes(list(self.ja5t_config.hashes))
        self.load_blocked_users_from_ja5h_hashes(list(self.ja5h_config.hashes))

        await self.clickhouse_client.connect()

        if self.app_config.training_mode == 'real':
            await asyncio.sleep(self.app_config.normal_users_find_minutes_ago * 60)

        if self.app_config.blocking_mode in {'real', 'historical'}:
            known_users = await self.load_last_real_users(
                start_at=int(time.time()) - self.app_config.normal_users_find_minutes_ago * 60,
                time_long=self.app_config.normal_users_find_timeframe_minutes * 60,
                requests_amount=self.app_config.normal_users_total_request,
                time_amount=self.app_config.normal_users_total_time,
                users_amount=self.app_config.normal_users_max_amount,
            )
            self.set_known_users(users=known_users)

            average_stats = await self.get_stats_for_period(
                time_from=int(time.time()) - self.app_config.stats_find_minutes_ago,
                period_in_minutes=self.app_config.stats_find_time_frame_minutes
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

        await asyncio.gather(
            self.find_new_risk_users(),
            self.release_blocked_users(),
        )
