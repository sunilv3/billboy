"""Password hashing — argon2id with transparent legacy verification.

New hashes use argon2id. Existing pbkdf2/scrypt hashes produced by
werkzeug.security.generate_password_hash still verify, and callers should
transparently re-hash them to argon2id on the next successful login
(see needs_rehash).

This module imports nothing from the rest of the app, so it is safe to import
anywhere (no circular-import risk).
"""
from werkzeug.security import (
    check_password_hash as _werkzeug_check,
    generate_password_hash as _werkzeug_hash,
)

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
    _PH = PasswordHasher()  # argon2id with sane library defaults
    ARGON2_AVAILABLE = True
except Exception:  # pragma: no cover - exercised only when dependency missing
    _PH = None
    ARGON2_AVAILABLE = False


def hash_password(password):
    """Return an argon2id hash, or a werkzeug fallback if argon2 is unavailable.

    Production boot enforcement (core.database.enforce_admin_security) refuses
    to start without argon2, so the fallback only applies to dev/CI.
    """
    if ARGON2_AVAILABLE:
        return _PH.hash(password)
    return _werkzeug_hash(password)


def verify_password(stored_hash, password):
    """Constant-time-ish verify against argon2 OR legacy werkzeug hashes."""
    if not stored_hash or password is None:
        return False
    if stored_hash.startswith('$argon2'):
        if not ARGON2_AVAILABLE:
            return False
        try:
            return _PH.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
        except Exception:
            return False
    # Legacy werkzeug hash (pbkdf2:… / scrypt:…)
    try:
        return _werkzeug_check(stored_hash, password)
    except Exception:
        return False


def needs_rehash(stored_hash):
    """True if the stored hash is legacy (non-argon2) or uses outdated params."""
    if not stored_hash:
        return True
    if not stored_hash.startswith('$argon2'):
        return True
    if ARGON2_AVAILABLE:
        try:
            return _PH.check_needs_rehash(stored_hash)
        except Exception:
            return False
    return False
