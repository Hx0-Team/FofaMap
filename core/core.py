"""Compatibility import for applications that used ``core.core.FofaClient``."""

from core.client import FofaClient

__all__ = ["FofaClient"]
