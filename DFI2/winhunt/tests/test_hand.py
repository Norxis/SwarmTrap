"""Unit tests for hand command dispatcher."""
from __future__ import annotations

import time
import unittest
from unittest.mock import MagicMock, patch

from dfi_agent.hand.handlers import COMMAND_REGISTRY


class _MockDispatcher:
    """Minimal dispatcher for testing command routing, timeout, and rate limiting."""

    def __init__(self, registry: dict, timeout_s: float = 30.0,
                 burst_limit: int = 10, burst_window_s: float = 60.0):
        self._registry = registry
        self._timeout_s = timeout_s
        self._burst_limit = burst_limit
        self._burst_window_s = burst_window_s
        self._call_times: list[float] = []

    def dispatch(self, command: str, config: object, args: dict) -> dict:
        """Route command to handler; enforce timeout and rate limiting."""
        now = time.time()

        # Rate limiting: prune old timestamps, check burst
        self._call_times = [
            t for t in self._call_times
            if now - t < self._burst_window_s
        ]
        if len(self._call_times) >= self._burst_limit:
            return {"error": "rate_limit_exceeded", "command": command}
        self._call_times.append(now)

        # Unknown command check
        if command not in self._registry:
            return {"error": "unknown_command", "command": command}

        handler = self._registry[command]

        # Timeout enforcement
        import threading
        result_box: list = []
        error_box: list = []

        def _run():
            try:
                result_box.append(handler(config, args))
            except Exception as exc:
                error_box.append(str(exc))

        thr = threading.Thread(target=_run)
        thr.start()
        thr.join(timeout=self._timeout_s)

        if thr.is_alive():
            return {"error": "timeout", "command": command}

        if error_box:
            return {"error": error_box[0], "command": command}

        return result_box[0] if result_box else {"error": "no_result", "command": command}


class TestDispatcherRouting(unittest.TestCase):
    def test_dispatcher_routing(self):
        """Valid command should be dispatched to the correct handler."""
        config = MagicMock()
        dispatcher = _MockDispatcher(COMMAND_REGISTRY)

        # health_check is a known command
        result = dispatcher.dispatch("health_check", config, {})
        # On non-Windows, it returns a stub with cpu_pct, memory, disk, etc.
        self.assertNotIn("error", result)
        self.assertIn("cpu_pct", result)

    def test_unknown_command(self):
        """Unknown command should return an error."""
        config = MagicMock()
        dispatcher = _MockDispatcher(COMMAND_REGISTRY)

        result = dispatcher.dispatch("nonexistent_command", config, {})
        self.assertEqual(result["error"], "unknown_command")
        self.assertEqual(result["command"], "nonexistent_command")

    def test_timeout(self):
        """Command exceeding timeout should return a timeout error."""
        import time as time_mod

        def slow_handler(config, args):
            time_mod.sleep(5)
            return {"ok": True}

        registry = {"slow_cmd": slow_handler}
        dispatcher = _MockDispatcher(registry, timeout_s=0.1)
        config = MagicMock()

        result = dispatcher.dispatch("slow_cmd", config, {})
        self.assertEqual(result["error"], "timeout")

    @patch("time.time")
    def test_rate_limiting(self, mock_time):
        """Burst limit should be enforced."""
        # Mock time to control rate limiting window
        base_time = 1000000.0
        call_count = 0

        def advancing_time():
            nonlocal call_count
            call_count += 1
            # All calls within the same second (within burst window)
            return base_time + call_count * 0.01

        mock_time.side_effect = advancing_time

        def simple_handler(config, args):
            return {"ok": True}

        registry = {"ping": simple_handler}
        dispatcher = _MockDispatcher(registry, burst_limit=3, burst_window_s=60.0)
        config = MagicMock()

        # First 3 calls should succeed
        for _ in range(3):
            result = dispatcher.dispatch("ping", config, {})
            self.assertNotIn("error", result)

        # 4th call should be rate limited
        result = dispatcher.dispatch("ping", config, {})
        self.assertEqual(result["error"], "rate_limit_exceeded")


if __name__ == "__main__":
    unittest.main()
