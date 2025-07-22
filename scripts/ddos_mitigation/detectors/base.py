import abc

from datatypes import User

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class BaseDetector(metaclass=abc.ABCMeta):
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
    async def find_users(self, current_time: int = None) -> list[User]:
        """
        Performed analysis and identified risky users.

        :param current_time: used as the current time in functional tests
        :return: list of risky users
        """
