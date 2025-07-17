import time
import os
from blockers.base import BaseBlocker, PreperationError
from datatypes import User
from ja5_config import Ja5Config, Ja5Hash
from logger import logger
from utils import run_in_shell

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class Ja5tBlocker(BaseBlocker):
    def __init__(self, config: Ja5Config, tempesta_executable_path: str = None):
        self.config = config
        self.tempesta_executable_path = tempesta_executable_path

    @staticmethod
    def name() -> str:
        return 'ja5t'

    def __tempesta_app_exists(self) -> bool:
        if self.tempesta_executable_path and os.path.isfile(self.tempesta_executable_path):
            return True

        result = run_in_shell('service tempesta status')

        return result.returncode == 0

    def prepare(self):
        if not self.__tempesta_app_exists():
            raise PreperationError('Tempesta executable not found')

        try:
            self.config.verify_file()

        except (FileNotFoundError, PermissionError) as e:
            raise PreperationError(e)

    def load(self) -> list[User]:
        self.config.load()
        already_blocked = []

        for hash_value in list(self.config.hashes):
            already_blocked.append(User(ja5t=hash_value, blocked_at=int(time.time())))

        return already_blocked

    def block(self, user: User):
        if self.config.exists(user.ja5t):
            return None

        self.config.add(Ja5Hash(value=user.ja5t, packets=0, connections=0))
        logger.warning(f"Blocked user {user} by ja5t")

    def release(self, user: User):
        if not self.config.exists(user.ja5t):
            return None

        self.config.remove(user.ja5t)

    def apply(self):
        if not self.config.need_dump:
            return

        self.config.dump()

        if self.tempesta_executable_path:
            result = run_in_shell(f"{self.tempesta_executable_path} --reload")

            if result.returncode != 0:
                logger.error(f"Tempesta FW could not be reloaded: {result.stderr}")

            return

        result = run_in_shell("service tempesta --reload")

        if result.returncode != 0:
            logger.error(f"Tempesta FW could not be reloaded: {result.stderr}")

    def info(self) -> list[User]:
        return [
            User(ja5t=ja5_hash.value)
            for ja5_hash in self.config.hashes.values()
        ]
