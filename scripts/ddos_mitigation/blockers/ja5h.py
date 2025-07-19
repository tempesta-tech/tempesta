import time

from blockers.ja5t import Ja5tBlocker
from datatypes import User
from ja5_config import Ja5Hash
from logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class Ja5hBlocker(Ja5tBlocker):

    @staticmethod
    def name() -> str:
        return "ja5h"

    def load(self) -> list[User]:
        self.config.load()
        already_blocked = []

        for hash_value in list(self.config.hashes):
            already_blocked.append(User(ja5h=hash_value, blocked_at=int(time.time())))

        return already_blocked

    def block(self, user: User):
        if self.config.exists(user.ja5h):
            return None

        self.config.add(Ja5Hash(value=user.ja5h, packets=0, connections=0))
        logger.warning(f"Blocked user {user} by ja5h")

    def release(self, user: User):
        if not self.config.exists(user.ja5h):
            return None

        self.config.remove(user.ja5h)

    def info(self) -> list[User]:
        return [User(ja5h=ja5_hash.value) for ja5_hash in self.config.hashes.values()]
