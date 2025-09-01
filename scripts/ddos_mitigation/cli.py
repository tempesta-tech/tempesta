import argparse
import os
from dataclasses import dataclass

from utils.logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class CommandLineArgs:
    config: str = "/etc/tempesta-webshield/app.env"
    log_level: str = "INFO"
    verify: bool = False

    @classmethod
    def parse_args(cls) -> "CommandLineArgs":
        """
        Read command line arguments
        :return: key-value arguments
        """
        parser = argparse.ArgumentParser(
            description="WebShield. Analyzes traffic using Tempesta FW access log data stored in ClickHouse",
            epilog="./app.py --config=/etc/tempesta-webshield/config.env",
            add_help=True,
        )
        parser.add_argument(
            "-c",
            "--config",
            type=str,
            default="/etc/tempesta-webshield/app.env",
            help="Path to the config file",
        )
        parser.add_argument(
            "-l",
            "--log-level",
            type=str,
            default="INFO",
            help="Log level",
        )
        parser.add_argument(
            "--verify",
            action="store_true",
            help="Verify config params",
        )
        args = cls(**vars(parser.parse_args()))

        if not os.path.exists(args.config):
            logger.error(f"Config file not found at path: {args.config}")
            exit(1)

        return args
