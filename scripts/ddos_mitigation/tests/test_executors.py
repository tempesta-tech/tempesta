from defender.context import AppContext
from defender.executor import run_app
from defender.lifespan import (
    Initialization,
    RealModeTraining,
    HistoricalModeTraining,
    BackgroundRiskyUsersMonitoring,
    BackgroundReleaseUsersMonitoring, AfterInitialization
)
from config import AppConfig
from utils.access_log import ClickhouseAccessLog
from utils.user_agents import UserAgentsManager


async def test_run_app_non_training_mode(monkeypatch):
    counter = 0

    async def fake_coro(*_):
        nonlocal counter
        counter += 1

    monkeypatch.setattr(Initialization, 'run', fake_coro)
    monkeypatch.setattr(AfterInitialization, 'run', fake_coro)
    monkeypatch.setattr(BackgroundReleaseUsersMonitoring, 'run', fake_coro)
    monkeypatch.setattr(BackgroundRiskyUsersMonitoring, 'run', fake_coro)

    await run_app(AppContext(
        clickhouse_client=ClickhouseAccessLog(),
        app_config=AppConfig(),
        user_agent_manager=UserAgentsManager(
            clickhouse_client=ClickhouseAccessLog(),
            config_path=''
        )
    ))
    assert counter == 4


async def test_run_app_real_mode(monkeypatch):
    counter = 0

    async def fake_coro(*_):
        nonlocal counter
        counter += 1

    monkeypatch.setattr(Initialization, 'run', fake_coro)
    monkeypatch.setattr(AfterInitialization, 'run', fake_coro)
    monkeypatch.setattr(RealModeTraining, 'run', fake_coro)
    monkeypatch.setattr(BackgroundReleaseUsersMonitoring, 'run', fake_coro)
    monkeypatch.setattr(BackgroundRiskyUsersMonitoring, 'run', fake_coro)

    await run_app(AppContext(
        clickhouse_client=ClickhouseAccessLog(),
        app_config=AppConfig(training_mode="real"),
        user_agent_manager=UserAgentsManager(
            clickhouse_client=ClickhouseAccessLog(),
            config_path=''
        )
    ))
    assert counter == 5


async def test_run_app_history_mode(monkeypatch):
    counter = 0

    async def fake_coro(*_):
        nonlocal counter
        counter += 1

    monkeypatch.setattr(Initialization, 'run', fake_coro)
    monkeypatch.setattr(AfterInitialization, 'run', fake_coro)
    monkeypatch.setattr(HistoricalModeTraining, 'run', fake_coro)
    monkeypatch.setattr(BackgroundReleaseUsersMonitoring, 'run', fake_coro)
    monkeypatch.setattr(BackgroundRiskyUsersMonitoring, 'run', fake_coro)

    await run_app(AppContext(
        clickhouse_client=ClickhouseAccessLog(),
        app_config=AppConfig(training_mode="historical"),
        user_agent_manager=UserAgentsManager(
            clickhouse_client=ClickhouseAccessLog(),
            config_path=''
        )
    ))
    assert counter == 5
