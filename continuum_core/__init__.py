"""Hermes Continuum core.

The package is intentionally importable without a running Hermes process.  Host
specific imports live only in ``continuum_core.runtime`` and
``continuum_core.adapters``; the storage, policy, memory and checkpoint modules
are plain Python and can be tested in isolation.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
