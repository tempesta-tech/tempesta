from dataclasses import dataclass, field

from access_log import ClickhouseAccessLog
from blockers.base import BaseBlocker
from config import AppConfig
from datatypes import User
from detectors.base import BaseDetector
from user_agents import UserAgentsManager

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
    user_agent_manager: UserAgentsManager

    # users found as risky and where blocked
    blocked: dict[int, User] = field(default_factory=dict)

    # Available blockers
    blockers: dict[str, BaseBlocker] = field(default_factory=dict)

    # Available detectors
    detectors: dict[str, BaseDetector] = field(default_factory=dict)

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
