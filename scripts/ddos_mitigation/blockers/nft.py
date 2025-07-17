from ipaddress import IPv4Address

from blockers.base import BaseBlocker
from datatypes import User
from utils import run_in_shell
from logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class NFTBlocker(BaseBlocker):
    def __init__(self, blocking_table_name: str):
        self.blocking_table_name = blocking_table_name

    @staticmethod
    def name() -> str:
        return 'nftables'

    def prepare(self):
        result = run_in_shell("which nft")

        if result.returncode != 0:
            raise ValueError("nftables is not installed")

        result = run_in_shell(
            f"nft list table inet {self.blocking_table_name}_table"
        )

        if result.returncode != 0 and "No such file or directory" in result.stderr:
            result = run_in_shell(
                f"nft add table inet {self.blocking_table_name}_table"
            )

            if result.returncode != 0:
                raise ValueError(f"Cannot add new table to nft: {result.stderr}")

        elif result.returncode != 0:
            raise ValueError(f"Cannot list nft table: {result.stderr}")

        result = run_in_shell(
            f"nft list set inet {self.blocking_table_name}_table "
            f"{self.blocking_table_name}"
        )

        if result.returncode != 0 and "No such file or directory" in result.stderr:
            result = run_in_shell(
                f"nft add set inet {self.blocking_table_name}_table "
                f'{self.blocking_table_name} "{{ type ipv4_addr; flags interval; }}"'
            )

            if result.returncode != 0:
                raise ValueError(f"Cannot add new set to nft: {result.stderr}")

        elif result.returncode != 0:
            raise ValueError(f"Cannot list nft set: {result.stderr}")

        result = run_in_shell(
            f"nft list chain inet {self.blocking_table_name}_table input"
        )

        if result.returncode != 0 and "No such file or directory" in result.stderr:
            result = run_in_shell(
                f"nft add chain inet {self.blocking_table_name}_table "
                f'input "{{ type filter hook input priority 0; }}"'
            )

            if result.returncode != 0:
                raise ValueError(f"Cannot add chain to nft: {result.stderr}")

        elif result.returncode != 0:
            raise ValueError(f"Cannot list nft chain: {result.stderr}")

        result = run_in_shell(
            f"nft list chain inet {self.blocking_table_name}_table input | grep "
            f"saddr @{self.blocking_table_name} drop"
        )

        if result.returncode != 0:
            result = run_in_shell(
                f"nft add rule inet {self.blocking_table_name}_table "
                f"input ip saddr @{self.blocking_table_name} drop"
            )

            if result.returncode != 0:
                raise ValueError(f"Cannot add rule to nft: {result.stderr}")

    def reset(self):
        result = run_in_shell(
            f"nft flush table inet {self.blocking_table_name}_table"
        )

        if result.returncode != 0:
            raise ValueError(f"Cannot flush nft table: {result.stderr}")

        result = run_in_shell(
            f"nft delete table inet {self.blocking_table_name}_table"
        )

        if result.returncode != 0:
            raise ValueError(f"Cannot delete nft table: {result.stderr}")

    def block(self, user: User):
        for ip in user.ipv4:
            result = run_in_shell(
                f"nft add element inet {self.blocking_table_name}_table "
                f'{self.blocking_table_name} "{{ {ip} }}"'
            )

            if result.returncode != 0:
                logger.error(f"Cannot block ip by nft: {result.stderr}")
            else:
                logger.warning(f"Blocked user {ip} by nft")

    def release(self, user: User):
        for ip in user.ipv4:
            result = run_in_shell(
                f"nft delete element inet {self.blocking_table_name}_table "
                f'{self.blocking_table_name} "{{ {ip} }}"'
            )

            if result.returncode != 0:
                logger.error(f"Cannot release ip by nft: {result.stderr}")
            else:
                logger.warning(f"Released user {ip} by nft")

    def info(self) -> list[User]:
        data = run_in_shell(
            f"nft list table inet {self.blocking_table_name}_table | grep elements"
        ).stdout
        elements = data.split('{ ')

        if len(elements) < 2:
            return []

        elements = elements[1][:-3]
        ips = elements.split(', ')
        return [User(ipv4=[IPv4Address(ip)]) for ip in ips if ip is not None]

    def load(self) -> dict[int, User]:
        return {hash(user): user for user in self.info()}
