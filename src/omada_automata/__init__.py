'''Top level module of this package'''
# Classes accessible from import

# Exceptions
from . import exceptions

# Classes
from .account import OmadaCloudAccount
from .essential import EssentialController

# TOTP code generation needs the 'totp' extra (pyotp) - every other
# class/function here is requests-only. Degrade to None rather than
# making the whole package unimportable for callers who don't have
# that extra installed and don't need it (most accounts don't have
# 2FA enabled).
try:
    from .totp import generate_totp_code
except ImportError:
    generate_totp_code = None

# Versions should comply with PEP 440:
# https://www.python.org/dev/peps/pep-0440/
__version__ = "0.1.0"

__all__ = [
    'EssentialController',
    'OmadaCloudAccount',
    'exceptions',
    'generate_totp_code',
]
