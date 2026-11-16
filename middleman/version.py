"""
Single source of truth for the proxy version.

Every BlacklistRule and AccessEntry stores the version that created it
(``created_by_version``) and every log line carries it, so whoever reads the
data can tell which behaviour produced it (see CHANGELOG.md) and decide whether
to act on it or accept it as part of an older flow.
"""

__version__ = "2.0.0"

# Stamped on rows that existed before version tracking was introduced (2.0.0).
# Such rows may have been created without validation and, for access entries,
# with a client IP taken from an unverified X-Forwarded-For header.
LEGACY_VERSION = "pre-2.0.0"


def current_version() -> str:
    """Default for ``created_by_version`` fields (a callable, for migrations)."""
    return __version__
