"""Argon2id password handling with bounded expensive work."""
from threading import BoundedSemaphore

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError

from .store import SecurityError

_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
_SLOTS = BoundedSemaphore(2)


def hash_password(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise SecurityError('Password must contain 12 to 128 characters')
    with _SLOTS:
        return _HASHER.hash(password)


_DUMMY = hash_password('dummy verification password, never an account')


def verify_password(encoded, password):
    if not isinstance(password, str) or len(password) > 128:
        return False
    with _SLOTS:
        try:
            valid = _HASHER.verify(encoded or _DUMMY, password)
            return bool(encoded) and valid
        except (VerificationError, InvalidHashError):
            return False
