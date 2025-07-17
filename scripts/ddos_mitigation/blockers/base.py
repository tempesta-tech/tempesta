import abc

from datatypes import User

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class PreperationError(Exception):
    """
    Stop app exucting because of unprocessable error
    """


class BaseBlocker(metaclass=abc.ABCMeta):

    @staticmethod
    @abc.abstractmethod
    def name() -> str:
        """
        Name of the blocker. Should be using in config blocking_type variable
        """

    def prepare(self):
        """
        Made some preparations to become blocking
        mechanism available. Create some OS changes, etc
        """

    def reset(self):
        """
        Remove all preperations, rollback all OS changes, etc.
        """

    def load(self) -> dict[int, User]:
        """
        Load already blocked users
        """

    @abc.abstractmethod
    def block(self, user: User):
        """
        Block user to prevent his abnormal acitivty
        """

    @abc.abstractmethod
    def release(self, user: User):
        """
        Unblock user to give him back the access to resource
        """

    def apply(self):
        """
        Apply blocking rules. Some blockers may block immiately without calling this method.
        But some blockers, like ja5t better apply rules after multiple config changes
        """

    @abc.abstractmethod
    def info(self) -> list[User]:
        """
        List of currently blocked users
        """
