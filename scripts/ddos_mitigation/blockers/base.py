import abc

from utils.datatypes import User

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class PreparationError(Exception):
    """
    Stop the app from executing due to an unprocessable error.
    """


class BaseBlocker(metaclass=abc.ABCMeta):

    @staticmethod
    @abc.abstractmethod
    def name() -> str:
        """
        Name of the blocker. Should be used in the `blocking_types` config variable.
        """

    def prepare(self):
        """
        Made some preparations to make the blocking mechanism available.
        Created some OS changes, etc.
        """

    def reset(self):
        """
        Remove all preparations, roll back all OS changes, etc
        """

    def load(self) -> dict[int, User]:
        """
        Load users who are already blocked.
        """

    @abc.abstractmethod
    def block(self, user: User):
        """
        Block the user to prevent their abnormal activity.
        """

    @abc.abstractmethod
    def release(self, user: User):
        """
        Unblock the user to restore their access to the resource.
        """

    def apply(self):
        """
        Apply blocking rules. Some blockers may block immediately
        without calling this method, but others — like ja5t — apply
        rules only after multiple config changes.
        """

    @abc.abstractmethod
    def info(self) -> list[User]:
        """
        List of currently blocked users.
        """
