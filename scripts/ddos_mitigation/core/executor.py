import asyncio

from core.context import AppContext
from core.lifespan import (
    AfterInitialization,
    BackgroundReleaseUsersMonitoring,
    BackgroundRiskyUsersMonitoring,
    HistoricalModeTraining,
    Initialization,
    RealModeTraining,
)

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


async def run_app(context: AppContext):
    await Initialization(context).run()
    await AfterInitialization(context).run()

    training_mode = None

    if context.app_config.training_mode == "real":
        training_mode = RealModeTraining(context)

    elif context.app_config.training_mode == "historical":
        training_mode = HistoricalModeTraining(context)

    if training_mode:
        await training_mode.run()

    steps = [BackgroundRiskyUsersMonitoring, BackgroundReleaseUsersMonitoring]

    await asyncio.gather(*[step(context).run() for step in steps])
