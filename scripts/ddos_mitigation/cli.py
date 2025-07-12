import argparse
from dataclasses import dataclass

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class CommandLineArgs:
    config: str = "/etc/tempesta-ddos-mitigation/app.env"

    @classmethod
    def parse_args(cls) -> "CommandLineArgs":
        """
        Read command line arguments
        :return: key-value arguments
        """
        parser = argparse.ArgumentParser(
            description="DDoS Defender. Analyzes traffic using Tempesta FW access log data stored in ClickHouse",
            epilog="./app.py --config=/etc/tempesta-ddos-defender/config.env",
            add_help=True,
        )
        parser.add_argument(
            "-c",
            "--config",
            type=str,
            help="Path to the config file",
        )
        return cls(**vars(parser.parse_args()))
