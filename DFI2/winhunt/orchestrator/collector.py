from __future__ import annotations

import asyncio
import base64
import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger("winhunt.collector")

_MAX_RETRY = 3
_RETRY_DELAY = 5


class MeshCollector:
    def __init__(self, config: Any):
        self.config = config
        self._mesh: Any = None

    async def _call(self, candidates: list[str], *args: Any, **kwargs: Any) -> Any:
        if self._mesh is None:
            raise RuntimeError("mesh not connected")
        last_exc: Exception | None = None
        for name in candidates:
            fn = getattr(self._mesh, name, None)
            if fn is None:
                continue
            try:
                out = fn(*args, **kwargs)
                if asyncio.iscoroutine(out):
                    out = await out
                return out
            except TypeError:
                continue
            except Exception as exc:
                last_exc = exc
                continue
        if last_exc:
            raise last_exc
        raise AttributeError(f"no compatible mesh method in: {candidates}")

    async def connect(self) -> None:
        try:
            from meshctrl import MeshCtrl  # type: ignore
        except ImportError as exc:
            raise RuntimeError("meshctrl is required: pip install meshctrl") from exc
        if not self.config.mesh.password:
            raise RuntimeError("MeshCentral password missing. Set WINHUNT_MESH_PASSWORD or config mesh.password")
        self._mesh = MeshCtrl(
            url=self.config.mesh.url,
            user=self.config.mesh.user,
            password=self.config.mesh.password,
        )
        out = self._mesh.connect()
        if asyncio.iscoroutine(out):
            await out
        log.info("connected to MeshCentral %s", self.config.mesh.url)

    async def _ensure_connected(self) -> None:
        """Connect or reconnect if needed."""
        if self._mesh is None:
            await self.connect()
            return
        # Simple health check — try listing devices
        try:
            await self._call(["list_devices", "listDevices", "devices"],
                             group=self.config.mesh.device_group)
        except Exception:
            log.warning("mesh connection lost — reconnecting")
            self._mesh = None
            await self.connect()

    async def list_agents(self) -> list[dict]:
        if self._mesh is None:
            return []
        try:
            devices = await self._call(
                ["list_devices", "listDevices", "devices"],
                group=self.config.mesh.device_group,
            )
            return list(devices or [])
        except Exception as exc:
            log.debug("list_agents error: %s", exc)
            return []

    async def _download_one(self, nodeid: str, remote_path: str, local_path: Path) -> bool:
        if self._mesh is None:
            return False
        try:
            data = await self._call(
                ["download", "download_file", "downloadFile"],
                nodeid=nodeid, path=remote_path,
            )
            if isinstance(data, bytes):
                local_path.write_bytes(data)
            elif isinstance(data, str):
                local_path.write_text(data, encoding="utf-8")
            else:
                return False
            return True
        except Exception as exc:
            log.debug("direct download failed for %s: %s — trying base64 fallback", remote_path, exc)
            return await self._download_one_b64(nodeid, remote_path, local_path)

    async def _run_command(self, nodeid: str, command: str) -> Any:
        return await self._call(
            ["run_command", "runCommand", "terminal"],
            nodeid=nodeid, command=command,
        )

    async def _download_one_b64(self, nodeid: str, remote_path: str, local_path: Path) -> bool:
        # Use PowerShell with proper escaping
        escaped = remote_path.replace("'", "''")
        ps = f"$p='{escaped}';$b=[Convert]::ToBase64String([IO.File]::ReadAllBytes($p));Write-Output $b"
        try:
            out = await self._run_command(
                nodeid=nodeid,
                command=f'powershell -NoProfile -NonInteractive -Command "{ps}"',
            )
            if isinstance(out, (list, tuple)):
                blob = "".join(str(x) for x in out if x).strip()
            else:
                blob = str(out or "").strip()
            if not blob:
                return False
            raw = base64.b64decode(blob)
            local_path.write_bytes(raw)
            return True
        except Exception as exc:
            log.warning("base64 download failed for %s: %s", remote_path, exc)
            return False

    async def _delete_remote(self, nodeid: str, remote_path: str) -> None:
        try:
            await self._call(["delete", "delete_file", "deleteFile"],
                             nodeid=nodeid, path=remote_path)
            return
        except Exception:
            pass
        escaped = remote_path.replace("'", "''")
        ps = f"$p='{escaped}'; Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue"
        try:
            await self._run_command(nodeid=nodeid, command=f'powershell -NoProfile -NonInteractive -Command "{ps}"')
        except Exception as exc:
            log.debug("delete_remote failed for %s: %s", remote_path, exc)

    async def _list_files(self, nodeid: str) -> Any:
        return await self._call(
            ["list_files", "listFiles", "files"],
            nodeid=nodeid, path=self.config.staging_remote_dir,
        )

    @staticmethod
    def _is_ndjson(path: Path, max_lines: int = 100) -> bool:
        """Validate NDJSON by checking first N lines."""
        try:
            count = 0
            with path.open("r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    json.loads(line)
                    count += 1
                    if count >= max_lines:
                        break
            return count > 0
        except Exception:
            return False

    async def poll_downloads(self) -> list[Path]:
        out_files: list[Path] = []
        agents = await self.list_agents()
        for agent in agents:
            nodeid = agent.get("_id") or agent.get("nodeid")
            name = agent.get("name") or str(nodeid)[:12]
            if not nodeid:
                continue
            local_dir = Path(self.config.local_download_dir) / name
            local_dir.mkdir(parents=True, exist_ok=True)
            try:
                files = await self._list_files(nodeid=nodeid)
            except Exception:
                continue
            for fobj in files or []:
                fname = fobj.get("name") if isinstance(fobj, dict) else None
                if not fname or not str(fname).endswith(".ndjson"):
                    continue
                remote = self.config.staging_remote_dir.rstrip("\\/") + "\\" + str(fname)
                local = local_dir / str(fname)
                ok = await self._download_one(nodeid, remote, local)
                if not ok:
                    continue
                if not self._is_ndjson(local):
                    log.warning("invalid NDJSON: %s — skipping", local)
                    local.unlink(missing_ok=True)
                    continue
                await self._delete_remote(nodeid, remote)
                out_files.append(local)
        return out_files

    async def run(self, queue: asyncio.Queue, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            try:
                await self._ensure_connected()
                files = await self.poll_downloads()
                for path in files:
                    await queue.put(path)
            except Exception as exc:
                log.error("collector cycle error: %s", exc)
                await asyncio.sleep(_RETRY_DELAY)
                continue
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=self.config.poll_interval_s)
            except asyncio.TimeoutError:
                continue
