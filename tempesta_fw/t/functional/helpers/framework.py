from __future__ import print_function

class Error(Exception):
    """Base exception class for unrecoverable framework errors.

    Python unittest treats AssertionError as test failure rather than the error.
    Separate exception class is needed to indicate that error happen and
    test framework is not working as expected.
    """
    pass

def assertFalse(expression, msg=''):
    """Raise test framework error if 'expression' is true."""
    if expression:
        raise Error(msg)

def assertTrue(expression, msg=''):
    """Raise test framework error if 'expression' is false."""
    if not expression:
        raise Error(msg)

def bug(msg=''):
    """Raise test framework error."""
    raise Error(msg)
