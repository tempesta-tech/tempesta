import os
from dataclasses import dataclass, field

from access_log import ClickhouseAccessLog
from logger import logger


@dataclass
class UserAgentsManager:
    clickhouse_client: ClickhouseAccessLog
    config_path: str
    user_agents: set[str] = field(default_factory=set)

    def read_from_file(self):
        if not os.path.exists(self.config_path):
            logger.error(f'User-Agent config file not found: {self.config_path}')
            exit(1)

        with open(self.config_path, "r") as f:
            for line in f.readlines():
                self.user_agents.add(line.strip())

    async def export_to_db(self):
        if not self.user_agents:
            return

        await self.clickhouse_client.user_agents_table_insert(
            [[i] for i in self.user_agents]
        )
