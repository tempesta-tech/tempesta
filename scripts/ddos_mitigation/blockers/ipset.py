import time
from ipaddress import IPv4Address

from blockers.base import BaseBlocker
from utils.datatypes import User
from utils.logger import logger
from utils.shell import ConditionalError, run_in_shell

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class IpSetBlocker(BaseBlocker):
    def __init__(self, blocking_ip_set_name: str):
        self.blocking_ip_set_name = blocking_ip_set_name

    @staticmethod
    def name() -> str:
        return "ipset"

    def load(self) -> dict[int, User]:
        return {hash(user): user for user in self.info()}

    def prepare(self):
        run_in_shell("which ipset", error="IPSET is not installed")

        try:
            run_in_shell(
                f"ipset list {self.blocking_ip_set_name}",
                error="Cannot list ipset",
                conditional_error="name does not exist",
            )
        except ConditionalError:
            run_in_shell(
                f"ipset create {self.blocking_ip_set_name} hash:ip",
                error="Cannot create IP set using ipset",
            )

        result = run_in_shell("iptables -L -v -n")

        if self.blocking_ip_set_name not in result.stdout:
            run_in_shell(
                f"iptables -I INPUT -m set --match-set {self.blocking_ip_set_name} "
                f"src -j DROP ",
                error="Cannot add IPSet group to iptables",
            )

    def reset(self):
        run_in_shell(
            f"iptables -D INPUT -m set --match-set {self.blocking_ip_set_name} "
            f"src -j DROP ",
            error="Cannot remove IPSet group from iptables",
        )

        # wait until itables become updated
        time.sleep(0.1)
        run_in_shell(
            f"ipset destroy {self.blocking_ip_set_name}",
            error="Cannot remove IPSet group",
        )

    def block(self, user: User):
        for ip in user.ipv4:
            result = run_in_shell(
                f"ipset add {self.blocking_ip_set_name} {ip}",
                error=f"{ip} could not be blocked",
                raise_error=False,
            )

            if result.returncode == 0:
                logger.warning(f"Blocked user {ip} by ipset")

    def release(self, user: User):
        for ip in user.ipv4:
            result = run_in_shell(
                f"ipset del {self.blocking_ip_set_name} {ip}",
                error=f"{ip} could not be released",
                raise_error=False,
            )

            if result.returncode == 0:
                logger.warning(f"Released user {ip} by ipset")

    def info(self) -> list[User]:
        data = run_in_shell(f"ipset list {self.blocking_ip_set_name}").stdout
        members = data.split("Members:\n")[1]
        ips = members.split("\n")
        return [
            User(ipv4=[IPv4Address(ip)], blocked_at=int(time.time())) for ip in ips[:-1]
        ]
