import os

import pytest

from blockers.base import PreparationError
from blockers.ja5h import Ja5hBlocker
from utils.datatypes import User
from utils.ja5_config import Ja5Config, Ja5Hash

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@pytest.fixture
def config_path() -> str:
    return "/tmp/test_ja5h_config"


@pytest.fixture
def blocker(config_path):
    blocker = Ja5hBlocker(Ja5Config(config_path))
    open(config_path, "w").close()

    yield blocker

    os.remove(config_path)


def test_load(blocker, config_path):
    with open(config_path, "w") as f:
        f.write("hash 1111 0 0;\nhash 2222 0 0;\n")

    users = blocker.load()
    assert len(users) == 2
    assert [item.ja5h for item in users.values()] == [["1111"], ["2222"]]


def test_block(blocker):
    user = User(ja5h=["11111"])
    blocker.block(user)
    assert len(blocker.config.hashes) == 1
    assert blocker.config.hashes["11111"].value == "11111"


def test_release(blocker):
    user = User(ja5h=["3333"])
    blocker.config.hashes["3333"] = Ja5Hash(value="3333", connections=0, packets=0)
    blocker.release(user)
    assert len(blocker.config.hashes) == 0


def test_apply(blocker, config_path):
    blocker.block(User(ja5h=["11111"]))
    blocker.apply()

    with open(config_path, "r") as f:
        data = f.read()

    assert data == "hash 11111 0 0;\n"


def test_info(blocker):
    blocker.block(User(ja5h=["11111"]))
    users = blocker.info()
    assert len(users) == 1
    assert users[0].ja5h == ["11111"]


def test_prepare_no_tempesta_service(blocker):
    with pytest.raises(PreparationError) as e:
        blocker.prepare()
        assert "executable not found" in str(e.value)


def test_prepare_no_config(blocker, config_path):
    blocker.tempesta_executable_path = "/tmp/path"
    open(config_path, "w").close()

    with pytest.raises(PreparationError) as e:
        blocker.prepare()
        assert "file not found" in str(e.value)
