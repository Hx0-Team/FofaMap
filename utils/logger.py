"""Application logging; stderr keeps MCP stdio stdout protocol-clean."""

from __future__ import annotations

import logging
import sys


class _Logger:
    def __init__(self) -> None:
        self._logger = logging.getLogger("fofamap")
        if not self._logger.handlers:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            self._logger.addHandler(handler)
        self._logger.setLevel(logging.INFO)

    def info(self, message: object) -> None:
        self._logger.info(message)

    def warning(self, message: object) -> None:
        self._logger.warning(message)

    def error(self, message: object) -> None:
        self._logger.error(message)

    def ai(self, message: object) -> None:
        self._logger.info("[agent] %s", message)

    def set_enabled(self, enabled: bool) -> None:
        """Honor config/system.logger without touching MCP stdout."""
        self._logger.disabled = not enabled
        self._logger.setLevel(logging.INFO if enabled else logging.CRITICAL + 1)


logger = _Logger()
