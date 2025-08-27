import subprocess

from utils.logger import logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class ConditionalError(Exception):
    pass


def run_in_shell(
    cmd: str, error: str = None, conditional_error: str = None, raise_error: bool = True
) -> subprocess.CompletedProcess:
    """
    Run command in a shell and return its output

    :param cmd: command to run
    :param error: error to raise if command fails
    :param conditional_error: raise ConditionalError conditional_error text exists in stderr
    :return: output of command
    """

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode == 0:
        return result

    if conditional_error and conditional_error in result.stderr:
        logger.error(result.stderr)

        if not raise_error:
            return result

        raise ConditionalError(result.stderr)

    if not error:
        logger.error(result.stderr)

        if not raise_error:
            return result

        raise ValueError(result.stderr)

    error_text = f"{error}: {result.stderr}"
    logger.error(error_text)

    if not raise_error:
        return result

    raise ValueError(error_text)
