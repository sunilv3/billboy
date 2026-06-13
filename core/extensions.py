"""Shared Flask extensions (initialized by create_app)."""

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    Limiter = None
    get_remote_address = None
    LIMITER_AVAILABLE = False

limiter = None  # Replaced with real Limiter instance by create_app()


def _rate_limit(rate):
    """Decorator that applies a rate limit when the limiter is active, otherwise no-ops."""
    def decorator(f):
        if limiter is not None:
            return limiter.limit(rate)(f)
        return f
    return decorator


def check_rate_limit(rate):
    """Apply rate limit at call time instead of decoration time.

    Use this for dynamic rate limiting where the limiter may not be
    available when the module is first imported.
    """
    if limiter is not None:
        limiter.limit(rate)
    return None
