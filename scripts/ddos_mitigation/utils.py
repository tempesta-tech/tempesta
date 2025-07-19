import subprocess


def run_in_shell(cmd: str) -> subprocess.CompletedProcess:
    """
    Run command in a shell and return its output

    :param cmd: command to run
    :return: output of command
    """

    return subprocess.run(cmd, shell=True, capture_output=True, text=True)
