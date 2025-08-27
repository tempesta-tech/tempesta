import re
import time
from ipaddress import IPv4Address

from blockers.base import BaseBlocker
from utils.datatypes import User
from utils.logger import logger
from utils.shell import ConditionalError, run_in_shell

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class NFTBlocker(BaseBlocker):
    def __init__(self, blocking_table_name: str):
        self.blocking_table_name = blocking_table_name

    @staticmethod
    def name() -> str:
        return "nftables"

    def prepare(self):
        run_in_shell("which nft", error="nftables is not installed")

        try:
            run_in_shell(
                f"nft list table inet {self.blocking_table_name}_table",
                conditional_error="No such file or directory",
                error="Cannot list nft table",
            )
        except ConditionalError:
            run_in_shell(
                f"nft add table inet {self.blocking_table_name}_table",
                error="Cannot add new table to nft",
            )

        try:
            run_in_shell(
                f"nft list set inet {self.blocking_table_name}_table "
                f"{self.blocking_table_name}",
                conditional_error="No such file or directory",
                error="Cannot list nft set",
            )
        except ConditionalError:
            run_in_shell(
                f"nft add set inet {self.blocking_table_name}_table "
                f'{self.blocking_table_name} "{{ type ipv4_addr; flags interval; }}"',
                error="Cannot add new set to nft",
            )

        try:
            run_in_shell(
                f"nft list chain inet {self.blocking_table_name}_table input",
                conditional_error="No such file or directory",
                error="Cannot list nft chain",
            )
        except ConditionalError:
            run_in_shell(
                f"nft add chain inet {self.blocking_table_name}_table "
                f'input "{{ type filter hook input priority 0; }}"',
                error="Cannot add chain to nft",
            )

        try:
            run_in_shell(
                f"nft list chain inet {self.blocking_table_name}_table input | grep "
                f"saddr @{self.blocking_table_name} drop"
            )
        except ValueError:
            run_in_shell(
                f"nft add rule inet {self.blocking_table_name}_table "
                f"input ip saddr @{self.blocking_table_name} drop",
                error="Cannot add rule to nft",
            )

    def reset(self):
        run_in_shell(
            f"nft flush table inet {self.blocking_table_name}_table",
            error="Cannot flush nft table",
        )
        run_in_shell(
            f"nft delete table inet {self.blocking_table_name}_table",
            error="Cannot delete nft table",
        )

    def block(self, user: User):
        for ip in user.ipv4:
            result = run_in_shell(
                f"nft add element inet {self.blocking_table_name}_table "
                f'{self.blocking_table_name} "{{ {ip} }}"',
                error=f"Cannot block {ip} by nft",
                raise_error=False,
            )

            if result.returncode == 0:
                logger.warning(f"Blocked user {ip} by nft")

    def release(self, user: User):
        for ip in user.ipv4:
            result = run_in_shell(
                f"nft delete element inet {self.blocking_table_name}_table "
                f'{self.blocking_table_name} "{{ {ip} }}"',
                error=f"Cannot release {ip} by nft",
            )

            if result.returncode == 0:
                logger.warning(f"Cannot release {ip} by nft: ")

    def info(self) -> list[User]:
        try:
            data = run_in_shell(
                f"nft list table inet {self.blocking_table_name}_table"
            ).stdout
        except ValueError:
            data = ""

        matched = re.findall(
            r".*elements = {(?P<ips>.*).*}.*}.*chain", data, flags=re.DOTALL
        )

        if not matched:
            return []

        ips = matched[0].split(",")
        ips = [i.strip() for i in ips]
        return [
            User(ipv4=[IPv4Address(ip)], blocked_at=int(time.time()))
            for ip in ips
            if ip is not None
        ]

    def load(self) -> dict[int, User]:
        return {hash(user): user for user in self.info()}
