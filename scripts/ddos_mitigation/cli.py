from dataclasses import dataclass
import argparse


@dataclass
class CommandLineArgs:
    config: str = '/etc/tempesta-ddos-mitigation/app.env'

    @classmethod
    def parse_args(cls) -> 'CommandLineArgs':
        """
        Read command line arguments
        :return: key-value arguments
        """
        parser = argparse.ArgumentParser(
            description="Enable DDOS mitigation based on Tempesta FW logging data",
            epilog='./system_verification.py -nh=192.168.0.100 -nni=eth0 -th=192.168.0.101 -tm=00:00:00:00:00:00',
            add_help=True
        )
        parser.add_argument(
            '-c', '--config',
            type=str,
            help="Path to config",
        )
        return cls(**vars(parser.parse_args()))
