import os
import sys
import shutil
import subprocess


def test_run_app():
    """
    Just check that there are not errors
    """
    cwd = os.getcwd()
    shutil.copy(f'{cwd}/example.env', '/tmp/config')
    sub = subprocess.run(
        f'{sys.executable} {cwd}/app.py' 
        ' --config=/tmp/config' 
        ' --log-level=DEBUG'
        ' --verify',
        shell=True,
    )
    assert sub.returncode == 0
