"""Alert manager -- fires alerts on high-confidence classifications."""
from __future__ import annotations

import abc
import json
import logging
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("winhunt.alerting")


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class AlertChannel(abc.ABC):
    """Base class for alert delivery channels."""

    @abc.abstractmethod
    def send(self, alert_data: dict) -> None:
        """Send an alert through this channel."""


class LogChannel(AlertChannel):
    """Writes alerts to a file as JSON lines."""

    def __init__(self, path: str) -> None:
        self._path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        log.info("LogChannel initialized: %s", path)

    def send(self, alert_data: dict) -> None:
        line = json.dumps(alert_data, separators=(",", ":"), default=str) + "\n"
        try:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            log.exception("failed to write alert to %s", self._path)


class WebhookChannel(AlertChannel):
    """Sends alerts via HTTP POST to a configured URL."""

    def __init__(self, url: str, timeout: int = 10) -> None:
        self._url = url
        self._timeout = timeout
        log.info("WebhookChannel initialized: %s", url)

    def send(self, alert_data: dict) -> None:
        payload = json.dumps(alert_data, separators=(",", ":"), default=str).encode("utf-8")
        req = urllib.request.Request(
            self._url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                log.debug("webhook response: %d", resp.status)
        except urllib.error.URLError:
            log.exception("webhook POST failed: %s", self._url)
        except Exception:
            log.exception("unexpected error sending webhook to %s", self._url)


class AlertManager:
    """Fires alerts on high-confidence classifications.

    Configuration via ``config.standalone.alert_channels`` (list of channel
    dicts) and ``config.standalone.alert_threshold`` (float, default 0.80).

    Channel dict format::

        {"type": "log", "path": "/path/to/alerts.jsonl"}
        {"type": "webhook", "url": "https://hook.example.com/alert"}
    """

    def __init__(self, config: Any) -> None:
        self._channels: list[AlertChannel] = []
        self._alert_count = 0

        # Extract standalone config
        standalone = getattr(config, "standalone", None)
        if standalone is None:
            standalone = config if isinstance(config, dict) else {}

        if isinstance(standalone, dict):
            self._threshold = standalone.get("alert_threshold", 0.80)
            channel_defs = standalone.get("alert_channels", [])
        else:
            self._threshold = getattr(standalone, "alert_threshold", 0.80)
            channel_defs = getattr(standalone, "alert_channels", [])

        for ch_def in channel_defs:
            ch_type = ch_def.get("type", "")
            if ch_type == "log":
                path = ch_def.get("path", "")
                if path:
                    self._channels.append(LogChannel(path))
            elif ch_type == "webhook":
                url = ch_def.get("url", "")
                if url:
                    timeout = ch_def.get("timeout", 10)
                    self._channels.append(WebhookChannel(url, timeout))
            else:
                log.warning("unknown alert channel type: %s", ch_type)

        log.info(
            "AlertManager initialized: %d channels, threshold=%.2f",
            len(self._channels), self._threshold,
        )

    @property
    def alert_count(self) -> int:
        return self._alert_count

    @property
    def threshold(self) -> float:
        return self._threshold

    def fire(self, label_result: dict) -> None:
        """Fire alert if label confidence >= threshold.

        Parameters
        ----------
        label_result : dict
            Output from SessionLabeler.label_session() containing at minimum:
            session_id, source_ip, label, label_name, evidence_bits,
            confidence, rule_matched.
        """
        confidence = label_result.get("confidence", 0.0)
        if confidence < self._threshold:
            log.debug(
                "below threshold (%.2f < %.2f): session=%s",
                confidence, self._threshold, label_result.get("session_id", "?"),
            )
            return

        alert_data = {
            "alert_ts": _iso_now(),
            "alert_type": "kill_chain_classification",
            "session_id": label_result.get("session_id", ""),
            "source_ip": label_result.get("source_ip", ""),
            "label": label_result.get("label", 0),
            "label_name": label_result.get("label_name", "UNKNOWN"),
            "evidence_bits": label_result.get("evidence_bits", 0),
            "confidence": confidence,
            "rule_matched": label_result.get("rule_matched", ""),
        }

        self._alert_count += 1
        log.warning(
            "ALERT #%d: %s session=%s src=%s confidence=%.2f",
            self._alert_count,
            alert_data["label_name"],
            alert_data["session_id"],
            alert_data["source_ip"],
            confidence,
        )

        for channel in self._channels:
            try:
                channel.send(alert_data)
            except Exception:
                log.exception("failed to send alert via %s", type(channel).__name__)
