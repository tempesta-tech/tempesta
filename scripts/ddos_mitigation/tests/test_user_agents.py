import os
import unittest

import pytest

from utils.access_log import ClickhouseAccessLog
from utils.user_agents import UserAgentsManager

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@pytest.fixture
def user_manager(access_log):
    path_to_config = "/tmp/tmp-user-agents"
    manager = UserAgentsManager(
        config_path=path_to_config,
        clickhouse_client=access_log,
    )

    with open(path_to_config, "w") as f:
        f.write("UserAgent\n" "  2222aaaaaaa   \n")

    yield manager

    os.remove(path_to_config)


def test_read_config(user_manager):
    user_manager.read_from_file()
    assert user_manager.user_agents == {"UserAgent", "2222aaaaaaa"}


async def test_export_user_agents(access_log, user_manager):
    user_manager.user_agents = {"Hello", "Kitty"}
    await user_manager.export_to_db()

    result = await access_log.user_agents_all()
    assert result.result_rows == [("Hello",), ("Kitty",)]
