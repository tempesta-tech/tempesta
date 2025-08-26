import asyncio

from defender.context import AppContext
from defender.lifespan import (
    Initialization,
    RealModeTraining,
    HistoricalModeTraining,
    BackgroundMonitoring
)


async def run_app(context: AppContext):
    steps = [Initialization]

    if context.app_config.training == 'real':
        steps.append(RealModeTraining)

    elif context.app_config.training == 'historical':
        steps.append(HistoricalModeTraining)

    steps.append(BackgroundMonitoring)
    await asyncio.gather(*[
        step(context).run() for step in steps
    ])
