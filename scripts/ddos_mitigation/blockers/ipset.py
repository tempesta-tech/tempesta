import time
from ipaddress import IPv4Address
from blockers.base import BaseBlocker
from datatypes import User
from utils import run_in_shell
from logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class IpSetBlocker(BaseBlocker):
    def __init__(self, blocking_ip_set_name: str):
        self.blocking_ip_set_name = blocking_ip_set_name

    @staticmethod
    def name() -> str:
        return 'ipset'

    def load(self) -> dict[int, User]:
        return {hash(user): user for user in self.info()}

    def prepare(self):
        result = run_in_shell("which ipset")

        if result.returncode != 0:
            raise ValueError("IPSET is not installed")

        result = run_in_shell(f"ipset list {self.blocking_ip_set_name}")

        if result.returncode != 0:
            if "not permitted" in result.stderr:
                raise PermissionError(
                    "Insufficient permissions to use the `ipset` command. "
                    "Please run the application with root privileges."
                )

            if "name does not exist" in result.stderr:
                result = run_in_shell(
                    f"ipset create {self.blocking_ip_set_name} hash:ip"
                )

                if result.returncode != 0:
                    raise ValueError(
                        f"Cannot create IP set using ipset: {result.stderr}"
                    )

        result = run_in_shell("iptables -L -v -n")

        if self.blocking_ip_set_name not in result.stdout:
            result = run_in_shell(
                f"iptables -I INPUT -m set --match-set {self.blocking_ip_set_name} "
                f"src -j DROP "
            )
            if result.returncode != 0:
                raise ValueError(f"Cannot add IPSet group to iptables: {result.stderr}")

    def reset(self):
        result = run_in_shell(
            f"iptables -D INPUT -m set --match-set {self.blocking_ip_set_name} "
            f"src -j DROP "
        )

        if result.returncode != 0:
            raise ValueError(f"Cannot remove IPSet group from iptables:{result.stderr}")

        # wait until itables become updated
        time.sleep(0.1)
        result = run_in_shell(
            f"ipset destroy {self.blocking_ip_set_name}"
        )

        if result.returncode != 0:
            raise ValueError(f"Cannot remove IPSet group:{result.stderr}")

    def block(self, user: User):
        for ip in user.ipv4:
            result = run_in_shell(
                f"ipset add {self.blocking_ip_set_name} {ip}"
            )

            if result.returncode != 0:
                if "already added" in result.stderr:
                    logger.error(f"{ip} is already added")
                else:
                    logger.error(f"{ip} can not be added: {result.stderr}")
            else:
                logger.warning(f"Blocked user {ip} by ipset")

    def release(self, user: User):
        for ip in user.ipv4:
            result = run_in_shell(
                f"ipset del {self.blocking_ip_set_name} {ip}"
            )

            if result.returncode != 0:
                if "not added" in result.stderr:
                    logger.error(f"{ip} is missing in ipset")
                else:
                    logger.error(f"{ip} can not be released: {result.stderr}")
            else:
                logger.warning(f"Released user {ip} by ipset")

    def info(self) -> list[User]:
        data = run_in_shell(
            f"ipset list {self.blocking_ip_set_name}"
        ).stdout
        members = data.split("Members:\n")[1]
        ips = members.split("\n")
        return [User(ipv4=[IPv4Address(ip)]) for ip in ips[:-1]]
