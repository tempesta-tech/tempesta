__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


async def test_create_user_agents_table(access_log):
    await access_log.user_agents_table_create()
    items = await access_log.user_agents_all()
    assert len(items.result_rows) == 0


async def test_insert_into_user_agents_table(access_log):
    await access_log.user_agents_table_insert([["TestUserAgent"], ["HelloKitty"]])
    items = await access_log.user_agents_all()
    assert len(items.result_rows) == 2


async def test_create_persistent_user_table(access_log):
    await access_log.persistent_users_table_create()
    items = await access_log.persistent_users_all()
    assert len(items.result_rows) == 0


async def test_insert_into_persistent_user_table(access_log):
    await access_log.persistent_users_table_insert([["127.0.0.1"], ["fa00::01"]])
    items = await access_log.persistent_users_all()
    assert len(items.result_rows) == 2
