import os
import re
from dataclasses import dataclass
from typing import Dict
from logger import logger


@dataclass
class Ja5Hash:
    value: int
    connections: int
    packets: int


class Ja5Config:
    hash_pattern = re.compile(
        r"[\t\s]*(?P<hash>\w+)[\t\s]+"
        r"(?P<connections>\d+)[\t\s]+"
        r"(?P<packets>\d+)[\t\s]*;[\t\s]*"
    )

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.hashes: Dict[int, Ja5Hash] = {}

        self.verify_file(file_path)
        self.load()

        self.need_dump: bool = False

    @staticmethod
    def format_line(ja5_hash: Ja5Hash) -> str:
        return f'{ja5_hash.value} {ja5_hash.connections} {ja5_hash.packets};\n'

    @staticmethod
    def verify_file(file_path: str):
        if not os.path.isfile(file_path):
            logger.error(f"File `{file_path}` does not exist")
            raise FileNotFoundError

        if not os.access(file_path, os.W_OK):
            logger.error(f"File `{file_path}` is not writable")
            raise PermissionError

    def load(self):
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
                    packets=result.group("packets")
                )

    def dump(self):
        with open(self.file_path, "w") as f:
            for value in self.hashes.values():
                f.write(self.format_line(value))

        self.need_dump = False

    def exists(self, ja5_hash: int) -> bool:
        return ja5_hash in self.hashes

    def add(self, ja5_hash: Ja5Hash):
        self.hashes[ja5_hash.value] = ja5_hash
        self.need_dump = True

    def remove(self, ja5_hash: int):
        self.hashes.pop(ja5_hash)
        self.need_dump = True
