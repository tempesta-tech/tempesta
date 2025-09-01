import datetime
from dataclasses import dataclass, field

from blockers.base import BaseBlocker
from config import AppConfig
from detectors.base import BaseDetector
from utils.access_log import ClickhouseAccessLog
from utils.datatypes import User
from utils.user_agents import UserAgentsManager

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class AppContext:
    """
    Manager start two background tasks which periodically block and unblock new users
    """

    # A connected client to Clickhouse Server
    clickhouse_client: ClickhouseAccessLog

    # Initialized application config
    app_config: AppConfig

    # User Agent Config Manager
    user_agent_manager: UserAgentsManager = None

    # users found as risky and where blocked
    blocked: dict[int, User] = field(default_factory=dict)

    # Initialized blockers
    blockers: dict[str, BaseBlocker] = field(default_factory=dict)

    # Initialized detectors
    detectors: dict[str, BaseDetector] = field(default_factory=dict)

    @property
    def active_blockers(self) -> list[BaseBlocker]:
        result = []

        for blocking_type in self.app_config.blocking_types:
            result.append(self.blockers[blocking_type])

        return result

    @property
    def active_detectors(self) -> list[BaseDetector]:
        result = []

        for detector in self.app_config.detectors:
            result.append(self.detectors[detector])

        return result

    @property
    def utc_now(self) -> int:
        return int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp())

    def user_block(self, user: User):
        for blocking_type in self.app_config.blocking_types:
            self.blockers[blocking_type].block(user)
            self.blocked[hash(user)] = user

    def user_release(self, user: User):
        for blocking_type in self.app_config.blocking_types:
            self.blockers[blocking_type].release(user)
            self.blocked.pop(hash(user))

    def user_apply(self):
        for blocking_type in self.app_config.blocking_types:
            self.blockers[blocking_type].apply()

    def user_reset(self):
        for blocking_type in self.app_config.blocking_types:
            self.blockers[blocking_type].reset()
            self.blocked = dict()
