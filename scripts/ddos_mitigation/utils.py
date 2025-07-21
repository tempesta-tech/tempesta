import subprocess

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


def run_in_shell(cmd: str) -> subprocess.CompletedProcess:
    """
    Run command in a shell and return its output

    :param cmd: command to run
    :return: output of command
    """

    return subprocess.run(cmd, shell=True, capture_output=True, text=True)
