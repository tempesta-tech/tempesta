import pytest

from utils.access_log import ClickhouseAccessLog


@pytest.fixture
async def access_log():
    _access_log = ClickhouseAccessLog()

    await _access_log.connect()
    await _access_log.user_agents_table_create()
    await _access_log.persistent_users_table_create()

    yield _access_log

    await _access_log.access_log_truncate()
    await _access_log.user_agents_table_truncate()
    await _access_log.persistent_users_table_truncate()
    await _access_log.conn.close()
