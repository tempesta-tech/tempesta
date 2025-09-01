from dataclasses import dataclass
from decimal import Decimal
from ipaddress import IPv4Address
from typing import Optional

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class AverageStats:
    requests: Decimal
    time: Decimal
    errors: Decimal


@dataclass
class User:
    ja5t: list[str] = None
    ja5h: list[str] = None
    ipv4: list[IPv4Address] = ()
    value: Optional[Decimal] = None
    type: Optional[int] = None
    blocked_at: Optional[int] = None

    def __hash__(self):
        return hash(f"ja5t={self.ja5t}/ja5h={self.ja5h}/ip={self.ipv4}")

    def __eq__(self, other):
        return hash(self) == hash(other)
