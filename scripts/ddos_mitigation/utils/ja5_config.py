import os
import re
from dataclasses import dataclass
from typing import Dict

from utils.logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class Ja5Hash:
    value: str
    connections: int
    packets: int


class Ja5Config:
    """
    Tempesta JA5 Config Manager
    """

    hash_pattern = re.compile(
        r"[\t\s]*hash*"
        r"[\t\s]*(?P<hash>\w+)[\t\s]+"
        r"(?P<connections>\d+)[\t\s]+"
        r"(?P<packets>\d+)[\t\s]*;[\t\s]*"
    )

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.hashes: Dict[str, Ja5Hash] = {}
        self.need_dump: bool = False

    @staticmethod
    def format_line(ja5_hash: Ja5Hash) -> str:
        """
        Create a string representation of a JA5 hash.

        :param ja5_hash: JA5 hash value.
        :return: Formatted string representation of the JA5 hash.
        """
        return f"hash {ja5_hash.value} {ja5_hash.connections} {ja5_hash.packets};\n"

    def verify_file(self):
        """
        Check whether the file exists and has the correct permissions.
        """
        if not os.path.isfile(self.file_path):
            logger.error(f"File `{self.file_path}` does not exist")
            raise FileNotFoundError

        if not os.access(self.file_path, os.W_OK):
            logger.error(
                f"File `{self.file_path}` is not writable. App does not have enough permissions."
            )
            raise PermissionError

    def load(self):
        """
        Parse the JA5 configuration file and store the loaded hashes.
        """
        with open(self.file_path, "r") as f:
            for line in f.readlines():
                result = re.match(self.hash_pattern, line)

                if not result:
                    logger.warning(f"Could not parse hash: `{line}`")
                    continue

                hash_value = result.group("hash")
                self.hashes[hash_value] = Ja5Hash(
                    value=result.group("hash"),
                    connections=result.group("connections"),
                    packets=result.group("packets"),
                )

    def dump(self):
        """
        Dump the local storage of JA5 hashes into the configuration file.
        """
        with open(self.file_path, "w") as f:
            for value in self.hashes.values():
                f.write(self.format_line(value))

        self.need_dump = False

    def exists(self, ja5_hash: str) -> bool:
        """
        Check if a JA5 hash exists in local storage.

        :param ja5_hash: JA5 hash value.
        :return: True if the hash exists, False otherwise.
        """
        return ja5_hash in self.hashes

    def add(self, ja5_hash: Ja5Hash):
        """
        Add a new JA5 hash to local storage.

        :param ja5_hash: JA5 hash value.
        """
        self.hashes[ja5_hash.value] = ja5_hash
        self.need_dump = True

    def remove(self, ja5_hash: str):
        """
        Remove a JA5 hash from local storage.

        :param ja5_hash: JA5 hash value.
        """
        self.hashes.pop(ja5_hash)
        self.need_dump = True
