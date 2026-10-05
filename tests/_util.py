"""Temporary-directory cleanup compatible with Python 3.9 and later."""

import os
import shutil
import stat
import sys


def _retry(func, path, error):
    if not isinstance(error, PermissionError):
        raise error
    os.chmod(path, os.stat(path).st_mode | stat.S_IRWXU)
    func(path)


def _onerror(func, path, exc_info):
    _retry(func, path, exc_info[1])


def rmtree_force(path):
    """Remove a test directory, retrying permission failures once."""
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_retry)
    else:
        shutil.rmtree(path, onerror=_onerror)
