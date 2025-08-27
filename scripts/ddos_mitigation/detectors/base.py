import abc
import asyncio
import math
from decimal import Decimal
from clickhouse_connect.driver import AsyncClient
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
            difference_multiplier: Decimal,
    ):
        self._access_log = access_log
        self._threshold = default_threshold
        self._difference_multiplier = difference_multiplier

    @property
    def db(self) -> AsyncClient:
        return self._access_log.conn

    @property
    def threshold(self) -> Decimal:
        return self._threshold

    @threshold.setter
    def threshold(self, threshold: Decimal):
        self._threshold = threshold

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

    def validate_model(self, users_before: list[User], users_after: list[User]) -> list[User]:
        """

        :param users_before:
        :param users_after:
        :return:
        """
        comparing_table = dict()
        users_to_block = []

        for user in users_before:
            comparing_table[user.ipv4] = user.value

        for user in users_after:
            if user.ipv4 not in comparing_table:
                continue

            multiplier = user.value / comparing_table[user.ipv4]

            if multiplier < self._difference_multiplier:
                continue

            users_to_block.append(user)

        return users_to_block

    @staticmethod
    def arithmetic_mean(values: list[Decimal]) -> Decimal:
        """

        :return:
        """
        return sum(values) / Decimal(len(values))

    @staticmethod
    def standard_deviation(
            values: list[Decimal],
            arithmetic_mean: Decimal
    ) -> Decimal:
        """

        :return:
        """
        deviation = sum(map(lambda val: math.pow(val - arithmetic_mean, Decimal(2)), values))
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
        response = await self.db.query(
            self.get_request(start_at, finish_at)
        )

        return [User(
            ja5t=user[0],
            ja5h=user[1],
            ipv4=user[2],
            value=user[3],
            type=user[4]
        ) for user in response.result_rows]
