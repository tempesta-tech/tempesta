import abc
import asyncio
import math
from decimal import Decimal

from datatypes import User
from access_log import ClickhouseAccessLog

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class BaseDetector(metaclass=abc.ABCMeta):
    def __init__(
            self,
            access_log: ClickhouseAccessLog,
            default_threshold: Decimal,
            persistent_users: list[User] = ()
    ):
        self.access_log = access_log
        self.threshold = default_threshold
        self.persistent_users = persistent_users

    @staticmethod
    @abc.abstractmethod
    def name() -> str:
        """
        Name of the detector. Should be used in the config.
        """

    async def prepare(self):
        """
        Made some preparation, training, etc.
        """

    @abc.abstractmethod
    async def fetch_for_period(self, start_at: int, finish_at: int) -> list[User]:
        """

        :param start_at:
        :param finish_at:
        :return:
        """

    async def find_users(self, current_time: int, interval: int) -> [list[User], list[User]]:
        """
        Performed analysis and identified risky users.

        :param current_time: used as the current time in functional tests
        :param interval: used as the current time in functional tests
        :return: list of risky users
        """
        return await asyncio.gather(
            self.fetch_for_period(start_at=current_time - 2*interval, finish_at=current_time - interval),
            self.fetch_for_period(start_at=current_time - interval, finish_at=current_time),
        )

    @abc.abstractmethod
    async def compare_results(self, users_before: list[User], users_after: list[User]) -> list[User]:
        """

        :param users_before:
        :param users_after:
        :return:
        """

    @staticmethod
    def arithmetic_mean(values: list[Decimal]) -> Decimal:
        """

        :return:
        """
        return sum(values) / Decimal(len(values))

    def standard_deviation(self, values: list[Decimal]) -> Decimal:
        """

        :return:
        """
        avg = self.arithmetic_mean(values)
        deviation = sum(map(lambda val: math.pow(val - avg, Decimal(2)), values))
        deviation /= len(values)
        return Decimal(math.sqrt(deviation))


class SQLBasedDetector(BaseDetector):
    @abc.abstractmethod
    def get_request(self, start_at: int, finish_at: int) -> str:
        """

        :param start_at:
        :param finish_at:
        :return:
        """

    async def fetch_for_period(self, start_at: int, finish_at: int) -> list[User]:
        """

        :param start_at:
        :param finish_at:
        :return:
        """
        response = await self.access_log.conn.query(
            self.get_request(start_at, finish_at)
        )

        return [User(
            ja5t=user[0],
            ja5h=user[1],
            ipv4=user[2],
            value=user[3],
            type=user[4]
        ) for user in response.result_rows]

