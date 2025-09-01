import os
import shutil
import subprocess
import sys

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


def test_run_app():
    """
    Just check that there are not errors
    """
    cwd = os.getcwd()
    shutil.copy(f"{cwd}/example.env", "/tmp/config")
    sub = subprocess.run(
        f"{sys.executable} {cwd}/app.py"
        " --config=/tmp/config"
        " --log-level=DEBUG"
        " --verify",
        shell=True,
    )
    assert sub.returncode == 0
