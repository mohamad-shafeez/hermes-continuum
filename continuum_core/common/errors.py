"""Exception types used at module boundaries.

Errors are deliberately small and message-safe: callers may show them to users,
so they must never contain credentials or raw tool output.
"""

from __future__ import annotations


class ContinuumError(Exception):
    """Base class for expected Continuum failures."""


class StorageError(ContinuumError):
    """The plugin-owned database could not be read or written safely."""


class PolicyError(ContinuumError):
    """A deterministic policy rule could not be evaluated."""


class CheckpointError(ContinuumError):
    """A checkpoint is invalid, unsupported, tampered with, or undecryptable."""
