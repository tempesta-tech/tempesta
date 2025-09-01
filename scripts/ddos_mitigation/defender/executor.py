import asyncio

from defender.context import AppContext
from defender.lifespan import (
    Initialization,
    AfterInitialization,
    RealModeTraining,
    HistoricalModeTraining,
    BackgroundRiskyUsersMonitoring,
    BackgroundReleaseUsersMonitoring
)


async def run_app(context: AppContext):
    await Initialization(context).run()
    await AfterInitialization(context).run()

    training_mode = None

    if context.app_config.training_mode == 'real':
        training_mode = RealModeTraining(context)

    elif context.app_config.training_mode == 'historical':
        training_mode = HistoricalModeTraining(context)

    if training_mode:
        await training_mode.run()

    steps = [BackgroundRiskyUsersMonitoring, BackgroundReleaseUsersMonitoring]

    await asyncio.gather(*[
        step(context).run() for step in steps
    ])
