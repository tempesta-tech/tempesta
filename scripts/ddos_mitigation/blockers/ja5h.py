import time

from blockers.ja5t import Ja5tBlocker
from utils.datatypes import User
from utils.ja5_config import Ja5Hash
from utils.logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class Ja5hBlocker(Ja5tBlocker):

    @staticmethod
    def name() -> str:
        return "ja5h"

    def load(self) -> dict[int, User]:
        self.config.load()
        current_time = int(time.time())
        result = dict()

        for hash_value in self.config.hashes:
            user = User(ja5h=[hash_value], blocked_at=current_time)
            result[hash(user)] = user

        return result

    def block(self, user: User):
        if self.config.exists(user.ja5h[0]):
            return None

        self.config.add(Ja5Hash(value=user.ja5h[0], packets=0, connections=0))
        logger.warning(f"Blocked user {user} by ja5h")

    def release(self, user: User):
        if not self.config.exists(user.ja5h[0]):
            return None

        self.config.remove(user.ja5h[0])

    def info(self) -> list[User]:
        return [User(ja5h=[ja5_hash.value]) for ja5_hash in self.config.hashes.values()]
