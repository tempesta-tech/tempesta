import abc

from datatypes import User


class BaseDetector(metaclass=abc.ABCMeta):
    @staticmethod
    @abc.abstractmethod
    def name() -> str:
        """
        Name of the detector. Should be used in config
        """

    async def prepare(self):
        """
        Made some prepatation, training, etc
        """

    async def find_users(self, current_time: int = None) -> list[User]:
        """
        Made a analyzes and find risky users

        :param current_time: used as current time in functional tests
        :return: list of risky users
        """
