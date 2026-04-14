#!/usr/bin/env python3
"""
DFI MeshCentral Translator v3 — Direct WebSocket + HTTP Callback Hybrid

Architecture:
    WSL (Python asyncio)
      |
      +-- Control WebSocket --- wss://192.168.0.112:443/control.ashx
      |   | (persistent, single connection)
      |   +-- list_nodes()           -> action: "nodes"
      |   +-- exec(cmd, reply=True)  -> action: "runcommands", reply:true
      |   |   Returns full stdout in response (no callback needed)
      |   +-- service_list/restart   -> built on exec()
      |   +-- health/status          -> built on exec()
      |   +-- fleet_exec()           -> parallel exec(), shared WS
      |
      +-- HTTP Callback Server --- aiohttp on 0.0.0.0:9080
          | (only for file transfer -- agents POST/GET over mgmt VLAN)
          +-- file_push()  -> stage bytes on HTTP -> agent GETs -> SHA256 verify
          +-- file_pull()  -> fire-and-forget PS script -> agent POSTs chunks back

Key insight: MeshCentral's runcommands supports reply:true on the control
channel. The server holds the response until the agent completes, then returns
full stdout. This eliminates the need for HTTP callbacks or terminal relay
for command execution.

Protocol for reply:true:
    Client -> Server:  { action: "runcommands", nodeids: [NODE],
                         type: 2, cmds: "Get-Date", reply: true,
                         responseid: "r001" }
    Server holds -- no immediate "OK"
    Agent executes, accumulates stdout+stderr
    Agent -> Server -> Client:  { action: "runcommands",
                                  responseid: "r001", result: "output" }

    type: 1=cmd.exe, 2=PowerShell, 3=Linux shell

Auth: x-meshauth header with base64(user), base64(pass)

File transfer still uses HTTP callback (files can be >100MB, reply:true
holds all output in agent memory).

    pip install websockets aiohttp
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import ssl
import time
import uuid
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

import websockets
from aiohttp import web

log = logging.getLogger("dfi.mesh")


# =====================================================================
# Data Structures
# =====================================================================

class AgentState(IntEnum):
    OFFLINE = 0
    CONNECTED = 1
    READY = 10


@dataclass
class ExecResult:
    """Structured result from remote command execution."""
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    node_id: str = ""
    command: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    @property
    def output(self) -> str:
        """Combined output for display."""
        parts = []
        if self.stdout:
            parts.append(self.stdout)
        if self.stderr:
            parts.append(f"[STDERR] {self.stderr}")
        return "\n".join(parts) if parts else ""


@dataclass
class NodeInfo:
    node_id: str
    name: str
    hostname: str
    os_desc: str
    agent_state: AgentState
    ip: str = ""
    mesh_id: str = ""


@dataclass
class ServiceInfo:
    name: str
    display_name: str
    status: str
    start_type: str


# =====================================================================
# Helpers
# =====================================================================

def _b64(s: str) -> str:
    """Base64-encode a string for x-meshauth header."""
    return base64.b64encode(s.encode()).decode()


def _ssl_noverify() -> ssl.SSLContext:
    """SSL context that skips certificate verification."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# =====================================================================
# Callback Server (for file transfer only)
# =====================================================================

class CallbackServer:
    """
    HTTP server that receives file transfer results from agents.

    Each operation creates a "job" with a cryptographic token.
    The PowerShell wrapper on the agent includes this token when
    POSTing results. No valid token -> 403.

    Endpoints:
        POST /cb/{job_id}?t={token}           Command result (JSON)
        POST /cb/{job_id}/chunk/{n}?t={token}  File chunk (binary)
        POST /cb/{job_id}/done?t={token}       File transfer done (JSON)
        GET  /serve/{job_id}?t={token}         Agent downloads a file

    All jobs auto-expire when awaited (or on timeout).
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 9080):
        self.host = host
        self.port = port
        self._app = web.Application(client_max_size=64 * 1024 * 1024)
        self._app.router.add_post("/cb/{job_id}", self._on_result)
        self._app.router.add_post("/cb/{job_id}/chunk/{n}", self._on_chunk)
        self._app.router.add_post("/cb/{job_id}/done", self._on_done)
        self._app.router.add_get("/serve/{job_id}", self._on_serve)
        self._runner: Optional[web.AppRunner] = None

        self._futures: dict[str, asyncio.Future] = {}
        self._tokens: dict[str, str] = {}
        self._chunks: dict[str, dict[int, bytes]] = {}
        self._staged: dict[str, bytes] = {}

    async def start(self):
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        await web.TCPSite(self._runner, self.host, self.port).start()
        log.info("Callback server on %s:%d", self.host, self.port)

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()

    # -- Job lifecycle ------------------------------------------------

    def new_job(self) -> tuple[str, str]:
        """Create job -> (job_id, token). Caller awaits via wait()."""
        jid = uuid.uuid4().hex[:16]
        tok = secrets.token_urlsafe(32)
        self._futures[jid] = asyncio.get_event_loop().create_future()
        self._tokens[jid] = tok
        return jid, tok

    def new_file_job(self) -> tuple[str, str]:
        jid, tok = self.new_job()
        self._chunks[jid] = {}
        return jid, tok

    def stage_file(self, data: bytes) -> tuple[str, str]:
        """Stage bytes for agent to GET. Returns (job_id, token)."""
        jid = uuid.uuid4().hex[:16]
        tok = secrets.token_urlsafe(32)
        self._staged[jid] = data
        self._tokens[jid] = tok
        return jid, tok

    async def wait(self, jid: str, timeout: float = 60) -> dict:
        """Block until agent POSTs result or timeout."""
        fut = self._futures.get(jid)
        if not fut:
            raise KeyError(f"No such job: {jid}")
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            return {"_error": "timeout", "exit_code": 124}
        finally:
            self._cleanup(jid)

    async def wait_file(self, jid: str, timeout: float = 300) -> bytes:
        """Block until chunked file transfer completes."""
        fut = self._futures.get(jid)
        if not fut:
            raise KeyError(f"No such job: {jid}")
        try:
            meta = await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"File transfer timed out: {jid}")
        finally:
            chunk_map = self._chunks.pop(jid, {})
            self._cleanup(jid)

        if "error" in meta:
            raise IOError(f"Agent error: {meta['error']}")

        n = meta.get("total_chunks", len(chunk_map))
        assembled = b""
        for i in range(n):
            c = chunk_map.get(i)
            if c is None:
                raise IOError(f"Missing chunk {i}/{n}")
            assembled += c

        expected = meta.get("sha256", "")
        if expected:
            actual = hashlib.sha256(assembled).hexdigest().lower()
            if actual != expected.lower():
                raise IOError(f"SHA256 mismatch: {expected} vs {actual}")

        return assembled

    def _cleanup(self, jid: str):
        self._futures.pop(jid, None)
        self._tokens.pop(jid, None)
        self._staged.pop(jid, None)

    def _auth(self, jid: str, req: web.Request) -> bool:
        exp = self._tokens.get(jid)
        if not exp:
            return False
        got = req.query.get("t", "") or req.headers.get("X-DFI-Token", "")
        return secrets.compare_digest(got, exp)

    # -- HTTP handlers ------------------------------------------------

    async def _on_result(self, req: web.Request) -> web.Response:
        jid = req.match_info["job_id"]
        if not self._auth(jid, req):
            return web.Response(status=403)
        fut = self._futures.get(jid)
        if not fut or fut.done():
            return web.Response(status=410)
        try:
            body = await req.json()
        except Exception:
            body = {"stdout": await req.text(), "exit_code": -1}
        fut.set_result(body)
        return web.Response(text="ok")

    async def _on_chunk(self, req: web.Request) -> web.Response:
        jid = req.match_info["job_id"]
        n = int(req.match_info["n"])
        if not self._auth(jid, req):
            return web.Response(status=403)
        if jid not in self._chunks:
            return web.Response(status=410)
        self._chunks[jid][n] = await req.read()
        return web.Response(text="ok")

    async def _on_done(self, req: web.Request) -> web.Response:
        jid = req.match_info["job_id"]
        if not self._auth(jid, req):
            return web.Response(status=403)
        fut = self._futures.get(jid)
        if not fut or fut.done():
            return web.Response(status=410)
        try:
            meta = await req.json()
        except Exception:
            meta = {}
        fut.set_result(meta)
        return web.Response(text="ok")

    async def _on_serve(self, req: web.Request) -> web.Response:
        jid = req.match_info["job_id"]
        if not self._auth(jid, req):
            return web.Response(status=403)
        data = self._staged.pop(jid, None)
        self._tokens.pop(jid, None)
        if data is None:
            return web.Response(status=404)
        return web.Response(body=data,
                            content_type="application/octet-stream")


# =====================================================================
# PowerShell Script Generators (file transfer only)
# =====================================================================

class PSGen:
    """
    Generate self-contained PowerShell scripts for file transfer.

    These scripts are fired via run_command_faf() and POST/GET results
    back to the callback server. No dependencies beyond .NET Framework.

    Note: exec_cmd() is no longer needed -- reply:true on the control
    WebSocket returns stdout directly.
    """

    _PREAMBLE = (
        "[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; "
        "$ProgressPreference='SilentlyContinue'; "
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
    )

    @staticmethod
    def file_pull(remote_path: str, cb_base: str, token: str,
                  chunk_bytes: int = 2 * 1024 * 1024) -> str:
        """
        Script that reads a file in chunks, POSTs each chunk,
        then POSTs /done with sha256 + total_chunks.
        """
        esc_path = remote_path.replace("'", "''")
        return (
            f'powershell -NoP -NonI -EP Bypass -C "'
            f'{PSGen._PREAMBLE}'
            f"$p='{esc_path}'; "
            f"$b='{cb_base}'; $tk='{token}'; "
            f"if(-not(Test-Path $p)){{ "
            f"  $e=@{{error='FILE_NOT_FOUND';path=$p}}|ConvertTo-Json -Compress; "
            f"  Invoke-RestMethod -Uri ($b+'/done?t='+$tk) -Method POST "
            f"    -Body $e -ContentType 'application/json' -TimeoutSec 30; exit "
            f"}}; "
            f"$h=(Get-FileHash $p -Algorithm SHA256).Hash.ToLower(); "
            f"$sz=(Get-Item $p).Length; "
            f"$fs=[System.IO.File]::OpenRead($p); "
            f"$buf=New-Object byte[] {chunk_bytes}; $cn=0; "
            f"while($true){{ "
            f"  $rd=$fs.Read($buf,0,{chunk_bytes}); "
            f"  if($rd -eq 0){{break}}; "
            f"  $ck=$buf[0..($rd-1)]; "
            f"  Invoke-RestMethod -Uri ($b+'/chunk/'+$cn+'?t='+$tk) "
            f"    -Method POST -Body $ck "
            f"    -ContentType 'application/octet-stream' -TimeoutSec 120; "
            f"  $cn++ "
            f"}}; "
            f"$fs.Close(); "
            f"$m=@{{total_chunks=$cn;sha256=$h;size=$sz;path=$p}}|ConvertTo-Json -Compress; "
            f"Invoke-RestMethod -Uri ($b+'/done?t='+$tk) -Method POST "
            f"  -Body $m -ContentType 'application/json' -TimeoutSec 30"
            f'"'
        )

    @staticmethod
    def file_push(remote_path: str, serve_url: str, serve_token: str,
                  expected_sha256: str,
                  confirm_url: str, confirm_token: str) -> str:
        """
        Script that GETs a file from our serve endpoint, writes it,
        verifies SHA256, and POSTs confirmation.
        """
        esc_path = remote_path.replace("'", "''")
        return (
            f'powershell -NoP -NonI -EP Bypass -C "'
            f'{PSGen._PREAMBLE}'
            f"$p='{esc_path}'; "
            f"try{{ "
            f"  $dir=Split-Path $p -Parent; "
            f"  if(-not(Test-Path $dir)){{New-Item $dir -ItemType Directory -Force|Out-Null}}; "
            f"  Invoke-RestMethod -Uri '{serve_url}?t={serve_token}' "
            f"    -OutFile $p -TimeoutSec 300; "
            f"  $h=(Get-FileHash $p -Algorithm SHA256).Hash.ToLower(); "
            f"  $sz=(Get-Item $p).Length; "
            f"  if($h -ne '{expected_sha256}'){{ "
            f"    $e=@{{error='HASH_MISMATCH';expected='{expected_sha256}';actual=$h}}|ConvertTo-Json -Compress; "
            f"    Invoke-RestMethod -Uri '{confirm_url}?t={confirm_token}' "
            f"      -Method POST -Body $e -ContentType 'application/json' -TimeoutSec 30; "
            f"    Remove-Item $p -Force; exit "
            f"  }}; "
            f"  $ok=@{{success=$true;sha256=$h;size=$sz;path=$p}}|ConvertTo-Json -Compress; "
            f"  Invoke-RestMethod -Uri '{confirm_url}?t={confirm_token}' "
            f"    -Method POST -Body $ok -ContentType 'application/json' -TimeoutSec 30 "
            f"}}catch{{ "
            f"  try{{ "
            f"    $e=@{{error=$_.Exception.Message}}|ConvertTo-Json -Compress; "
            f"    Invoke-RestMethod -Uri '{confirm_url}?t={confirm_token}' "
            f"      -Method POST -Body $e -ContentType 'application/json' -TimeoutSec 30 "
            f"  }}catch{{}} "
            f"}}"
            f'"'
        )


# =====================================================================
# Main Translator — Direct WebSocket Control
# =====================================================================

class MeshTranslator:
    """
    Direct WebSocket interface to MeshCentral for DFI.

    Uses a persistent control WebSocket with reply:true for command
    execution (returns full stdout). File transfer uses a lazy-started
    HTTP callback server.
    """

    def __init__(
        self,
        url: str,
        username: str,
        password: str,
        verify_tls: bool = False,
        timeout: float = 60.0,
        max_concurrent: int = 20,
        callback_host: str = "0.0.0.0",
        callback_port: int = 9080,
        callback_external_host: str = None,
        callback_scheme: str = "http",
    ):
        """
        Args:
            url:        MeshCentral base URL (e.g. wss://192.168.0.112:443)
            username:   MeshCentral admin username
            password:   MeshCentral admin password
            verify_tls: Verify server TLS certificate
            timeout:    Default per-command timeout (seconds)
            max_concurrent: Parallel operation limit
            callback_host:  Bind address for file transfer callback server
            callback_port:  Callback server port
            callback_external_host: IP/hostname agents use to POST back
            callback_scheme: "http" or "https"
        """
        # Normalize URL to wss:// WebSocket endpoint
        self._url = url.rstrip("/")
        if self._url.startswith("https://"):
            self._url = "wss://" + self._url[8:]
        elif not self._url.startswith("wss://"):
            self._url = "wss://" + self._url
        self._ws_url = f"{self._url}/control.ashx"

        self._username = username
        self._password = password
        self._verify_tls = verify_tls
        self._timeout = timeout
        self._sem = asyncio.Semaphore(max_concurrent)

        # Callback server config (lazy init)
        self._cb_host = callback_host
        self._cb_port = callback_port
        ext = callback_external_host or callback_host
        self._cb_base = f"{callback_scheme}://{ext}:{callback_port}"
        self._cb: Optional[CallbackServer] = None
        self._cb_started = False

        # WebSocket state
        self._ws = None
        self._pump_task: Optional[asyncio.Task] = None
        self._pending: dict[str, asyncio.Future] = {}
        self._id_counter = 0

        # Node cache
        self._nodes: dict[str, NodeInfo] = {}
        self._cache_ts: float = 0

    def _next_id(self) -> str:
        """Generate unique response ID."""
        self._id_counter += 1
        return f"dfi_{self._id_counter:06d}"

    @property
    def connected(self) -> bool:
        return self._ws is not None and self._ws.state.name == "OPEN"

    @property
    def base_url(self) -> str:
        return self._cb_base

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *a):
        await self.close()

    # -- Connection ---------------------------------------------------

    async def connect(self):
        """Open control WebSocket with auth header, start message pump."""
        ssl_ctx = None if self._verify_tls else _ssl_noverify()
        auth = f"{_b64(self._username)},{_b64(self._password)}"

        self._ws = await websockets.connect(
            self._ws_url,
            ssl=ssl_ctx,
            additional_headers={"x-meshauth": auth},
            max_size=16 * 1024 * 1024,
            ping_interval=30,
            ping_timeout=10,
            close_timeout=5,
        )
        self._pump_task = asyncio.create_task(self._message_pump())

        # Wait for serverinfo + initial node list to arrive
        await asyncio.sleep(2)
        log.info("Connected: ws=%s nodes=%d", self._ws_url, len(self._nodes))

    async def close(self):
        """Close WebSocket and callback server."""
        if self._pump_task and not self._pump_task.done():
            self._pump_task.cancel()
            try:
                await self._pump_task
            except asyncio.CancelledError:
                pass
        if self._ws:
            await self._ws.close()
            self._ws = None
        if self._cb_started and self._cb:
            await self._cb.stop()
            self._cb_started = False

        # Fail any pending futures
        for rid, fut in self._pending.items():
            if not fut.done():
                fut.set_exception(ConnectionError("translator closed"))
        self._pending.clear()

    async def _message_pump(self):
        """Background: route responses to waiting futures, cache nodes."""
        try:
            async for raw in self._ws:
                try:
                    data = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    continue

                action = data.get("action", "")
                rid = data.get("responseid", "")

                # Route to pending future
                if rid and rid in self._pending:
                    fut = self._pending.pop(rid)
                    if not fut.done():
                        fut.set_result(data)
                    continue

                # Cache node list when server pushes it
                if action == "nodes":
                    self._update_node_cache(data)

        except websockets.ConnectionClosed:
            log.warning("WebSocket closed by server")
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error("Message pump error: %s", e)

    def _update_node_cache(self, data: dict):
        """Parse nodes message into NodeInfo cache."""
        nodes = data.get("nodes", {})
        for mesh_id, devs in nodes.items():
            if not isinstance(devs, list):
                continue
            for dev in devs:
                nid = dev.get("_id", "")
                if not nid:
                    continue
                conn = dev.get("conn", 0)
                state = AgentState.CONNECTED if conn else AgentState.OFFLINE

                # Extract IP from various possible fields
                ip = ""
                if isinstance(dev.get("ip"), str):
                    ip = dev["ip"]
                elif isinstance(dev.get("ip"), list) and dev["ip"]:
                    ip = dev["ip"][0]

                self._nodes[nid] = NodeInfo(
                    node_id=nid,
                    name=dev.get("name", ""),
                    hostname=dev.get("rname", "") or dev.get("name", ""),
                    os_desc=dev.get("osdesc", ""),
                    agent_state=state,
                    ip=ip,
                    mesh_id=mesh_id,
                )
        self._cache_ts = time.monotonic()

    # -- Node discovery -----------------------------------------------

    async def list_nodes(self, refresh: bool = False) -> list[NodeInfo]:
        """List all devices. Cached for 30s unless refresh=True."""
        now = time.monotonic()
        if not refresh and (now - self._cache_ts) < 30 and self._nodes:
            return list(self._nodes.values())

        # Explicitly request nodes
        rid = self._next_id()
        fut = asyncio.get_event_loop().create_future()
        self._pending[rid] = fut
        await self._ws.send(json.dumps({
            "action": "nodes",
            "responseid": rid,
        }))
        try:
            data = await asyncio.wait_for(fut, timeout=10)
            self._update_node_cache(data)
        except asyncio.TimeoutError:
            self._pending.pop(rid, None)
            log.warning("list_nodes timeout -- using cached data")

        return list(self._nodes.values())

    def _resolve(self, node_id: str) -> str:
        """Resolve name/hostname -> node_id from cache, or pass through."""
        if node_id in self._nodes:
            return node_id
        for nid, n in self._nodes.items():
            if n.name == node_id or n.hostname == node_id:
                return nid
        return node_id

    # -- Command execution (reply:true) --------------------------------

    async def exec(
        self,
        node_id: str,
        command: str,
        cmd_type: int = 2,
        timeout: float = None,
    ) -> ExecResult:
        """
        Execute command on remote agent via control WebSocket.

        Uses reply:true -- server holds until agent completes,
        then returns full stdout in the response message.

        Args:
            node_id:  Node ID or name/hostname (resolved from cache)
            command:  Command string to execute
            cmd_type: 1=cmd.exe, 2=PowerShell, 3=Linux shell
            timeout:  Seconds to wait for response
        """
        timeout = timeout or self._timeout
        nid = self._resolve(node_id)
        t0 = time.monotonic()

        async with self._sem:
            rid = self._next_id()
            fut = asyncio.get_event_loop().create_future()
            self._pending[rid] = fut

            await self._ws.send(json.dumps({
                "action": "runcommands",
                "nodeids": [nid],
                "type": cmd_type,
                "cmds": command,
                "reply": True,
                "responseid": rid,
            }))

            try:
                data = await asyncio.wait_for(fut, timeout=timeout)
            except asyncio.TimeoutError:
                self._pending.pop(rid, None)
                elapsed = int((time.monotonic() - t0) * 1000)
                return ExecResult(
                    exit_code=124,
                    stdout="",
                    stderr=f"Timeout after {timeout}s waiting for reply",
                    duration_ms=elapsed,
                    timed_out=True,
                    node_id=nid,
                    command=command,
                )

        elapsed = int((time.monotonic() - t0) * 1000)
        result_text = data.get("result", "")

        # Parse exit code: reply:true returns the output as result string.
        # The agent doesn't return a structured exit code, so we infer:
        # - If we got a result string, exit_code=0
        # - Errors from the server have an "error" field
        if "error" in data:
            return ExecResult(
                exit_code=1,
                stdout="",
                stderr=str(data["error"]),
                duration_ms=elapsed,
                node_id=nid,
                command=command,
            )

        return ExecResult(
            exit_code=0,
            stdout=result_text.strip() if isinstance(result_text, str) else str(result_text),
            stderr="",
            duration_ms=elapsed,
            node_id=nid,
            command=command,
        )

    async def _run_command_faf(self, node_id: str, script: str,
                                cmd_type: int = 2):
        """Fire-and-forget command via control WebSocket (no reply).

        Used for file transfer scripts where the agent POSTs results
        back to the HTTP callback server instead.
        """
        await self._ws.send(json.dumps({
            "action": "runcommands",
            "nodeids": [node_id],
            "type": cmd_type,
            "cmds": script,
        }))

    # -- Callback server (lazy init) -----------------------------------

    async def _ensure_callback(self):
        """Lazy-start callback server on first file operation."""
        if not self._cb_started:
            self._cb = CallbackServer(self._cb_host, self._cb_port)
            await self._cb.start()
            self._cb_started = True

    # -- File transfer (WebSocket base64 — no callback needed) ----------

    async def file_push_b64(
        self,
        node_id: str,
        data: bytes | str,
        remote_path: str,
        chunk_size: int = 192 * 1024,
        timeout: float = 300,
    ) -> str:
        """
        Push file via WebSocket using base64 encoding.

        Each chunk is independently base64-encoded, sent via exec(reply:true),
        and decoded+appended on the agent. No callback server needed.

        Suitable for files up to ~10MB. For larger files, use file_push()
        with a properly configured callback server.

        Returns SHA256 of the written file.
        """
        nid = self._resolve(node_id)

        if isinstance(data, str):
            if os.path.isfile(data):
                with open(data, "rb") as f:
                    data = f.read()
            else:
                data = data.encode("utf-8")

        local_hash = hashlib.sha256(data).hexdigest().lower()
        esc_path = remote_path.replace("'", "''")

        # Split binary into chunks, base64-encode each independently
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        log.info("file_push_b64: %d bytes -> %s (%d chunks)",
                 len(data), remote_path, len(chunks))

        for i, chunk in enumerate(chunks):
            b64 = base64.b64encode(chunk).decode()

            if i == 0:
                # First chunk: create parent dir, write file
                cmd = (
                    f"$d=Split-Path '{esc_path}' -Parent; "
                    f"if(-not(Test-Path $d)){{New-Item $d -ItemType Directory -Force|Out-Null}}; "
                    f"[System.IO.File]::WriteAllBytes('{esc_path}',"
                    f"[Convert]::FromBase64String('{b64}')); "
                    f"'chunk_0_ok'"
                )
            else:
                # Subsequent chunks: append
                cmd = (
                    f"$f=[System.IO.File]::Open('{esc_path}',"
                    f"[System.IO.FileMode]::Append); "
                    f"$b=[Convert]::FromBase64String('{b64}'); "
                    f"$f.Write($b,0,$b.Length); $f.Close(); "
                    f"'chunk_{i}_ok'"
                )

            r = await self.exec(nid, cmd, timeout=timeout)
            if not r.ok:
                raise IOError(f"file_push_b64 chunk {i} failed: {r.output}")
            if f"chunk_{i}_ok" not in r.stdout:
                raise IOError(f"file_push_b64 chunk {i} unexpected: {r.stdout[:200]}")

        # Verify SHA256
        r = await self.exec(
            nid,
            f"(Get-FileHash '{esc_path}' -Algorithm SHA256).Hash.ToLower()",
            timeout=30,
        )
        remote_hash = r.stdout.strip().split("\n")[-1].strip()
        if remote_hash.lower() != local_hash:
            raise IOError(f"SHA256 mismatch: local={local_hash} remote={remote_hash}")

        log.info("file_push_b64: verified %s [%s]", remote_path, local_hash[:12])
        return local_hash

    async def file_pull_b64(
        self,
        node_id: str,
        remote_path: str,
        local_path: str = None,
        chunk_size: int = 3 * 1024 * 1024,
        timeout: float = 300,
    ) -> bytes:
        """
        Pull file via WebSocket using base64 encoding.

        Agent reads the file (or chunks of it), base64-encodes, and
        returns via reply:true stdout. No callback server needed.

        Suitable for files up to ~10MB.
        """
        nid = self._resolve(node_id)
        esc_path = remote_path.replace("'", "''")

        # Get file size
        r = await self.exec(
            nid, f"(Get-Item '{esc_path}' -EA Stop).Length", timeout=15)
        if not r.ok:
            raise IOError(f"Cannot stat {remote_path}: {r.output}")
        file_size = int(r.stdout.strip())

        if file_size <= chunk_size:
            # Single read
            r = await self.exec(
                nid,
                f"[Convert]::ToBase64String("
                f"[System.IO.File]::ReadAllBytes('{esc_path}'))",
                timeout=timeout,
            )
            if not r.ok:
                raise IOError(f"file_pull_b64 failed: {r.output}")
            data = base64.b64decode(r.stdout.strip())
        else:
            # Chunked read
            parts = []
            offset = 0
            while offset < file_size:
                read_size = min(chunk_size, file_size - offset)
                r = await self.exec(
                    nid,
                    f"$f=[System.IO.File]::OpenRead('{esc_path}'); "
                    f"$f.Seek({offset},[System.IO.SeekOrigin]::Begin)|Out-Null; "
                    f"$buf=New-Object byte[] {read_size}; "
                    f"$rd=$f.Read($buf,0,{read_size}); $f.Close(); "
                    f"[Convert]::ToBase64String($buf[0..($rd-1)])",
                    timeout=timeout,
                )
                if not r.ok:
                    raise IOError(
                        f"file_pull_b64 chunk at offset {offset} failed: {r.output}")
                parts.append(base64.b64decode(r.stdout.strip()))
                offset += read_size
            data = b"".join(parts)

        log.info("file_pull_b64: %d bytes from %s", len(data), remote_path)

        if local_path:
            os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
            with open(local_path, "wb") as f:
                f.write(data)

        return data

    # -- File transfer (HTTP callback — for large files) ---------------

    async def file_pull(
        self,
        node_id: str,
        remote_path: str,
        local_path: str = None,
        timeout: float = 300,
    ) -> bytes:
        """
        Download file from agent.

        Agent reads file in 2MB chunks, POSTs each to our callback
        server, then POSTs /done with SHA256 + chunk count.
        We reassemble and verify.
        """
        await self._ensure_callback()
        nid = self._resolve(node_id)

        async with self._sem:
            jid, tok = self._cb.new_file_job()
            cb_base = f"{self._cb_base}/cb/{jid}"

            script = PSGen.file_pull(remote_path, cb_base, tok)

            try:
                await self._run_command_faf(nid, script)
            except Exception as e:
                self._cb._cleanup(jid)
                raise IOError(f"Command dispatch failed: {e}") from e

            data = await self._cb.wait_file(jid, timeout=timeout)

        if local_path:
            os.makedirs(os.path.dirname(local_path) or ".", exist_ok=True)
            with open(local_path, "wb") as f:
                f.write(data)
            log.info("Pulled %d bytes -> %s", len(data), local_path)

        return data

    async def file_push(
        self,
        node_id: str,
        data: bytes | str,
        remote_path: str,
        timeout: float = 300,
    ) -> str:
        """
        Upload file to agent. Returns SHA256 of written file.

        We stage the file on our HTTP server. Agent GETs it,
        writes to disk, verifies SHA256, POSTs confirmation.
        """
        await self._ensure_callback()
        nid = self._resolve(node_id)

        if isinstance(data, str):
            if os.path.isfile(data):
                with open(data, "rb") as f:
                    data = f.read()
            else:
                data = data.encode("utf-8")

        local_hash = hashlib.sha256(data).hexdigest().lower()

        async with self._sem:
            # Stage file for download
            serve_id, serve_tok = self._cb.stage_file(data)
            serve_url = f"{self._cb_base}/serve/{serve_id}"

            # Confirmation job
            conf_id, conf_tok = self._cb.new_job()
            conf_url = f"{self._cb_base}/cb/{conf_id}"

            script = PSGen.file_push(
                remote_path, serve_url, serve_tok,
                local_hash, conf_url, conf_tok,
            )

            try:
                await self._run_command_faf(nid, script)
            except Exception as e:
                self._cb._cleanup(conf_id)
                self._cb._cleanup(serve_id)
                raise IOError(f"Command dispatch failed: {e}") from e

            result = await self._cb.wait(conf_id, timeout=timeout)

        if "error" in result:
            raise IOError(f"Push failed: {result['error']}")

        rh = result.get("sha256", "")
        if rh.lower() != local_hash:
            raise IOError(f"Hash mismatch: local={local_hash} remote={rh}")

        log.info("Pushed %d bytes -> %s [%s]", len(data), remote_path, local_hash[:12])
        return local_hash

    # -- Service management -------------------------------------------

    async def service_list(self, node_id: str,
                           name_filter: str = "*") -> list[ServiceInfo]:
        cmd = (f"Get-Service -Name '{name_filter}' | "
               "Select Name,DisplayName,Status,StartType | "
               "ConvertTo-Json -Compress")
        r = await self.exec(node_id, cmd, timeout=15)
        if not r.ok:
            raise RuntimeError(f"service_list: {r.output}")
        try:
            items = json.loads(r.stdout)
            if isinstance(items, dict):
                items = [items]
        except json.JSONDecodeError:
            return []

        STATUS = {1: "Stopped", 4: "Running", 7: "Paused"}
        START = {2: "Automatic", 3: "Manual", 4: "Disabled"}

        return [ServiceInfo(
            name=i.get("Name", ""),
            display_name=i.get("DisplayName", ""),
            status=STATUS.get(i.get("Status"), str(i.get("Status", ""))),
            start_type=START.get(i.get("StartType"), str(i.get("StartType", ""))),
        ) for i in items]

    async def service_control(self, node_id: str, name: str,
                               action: str) -> ExecResult:
        cmds = {
            "start": f"Start-Service '{name}' -PassThru",
            "stop": f"Stop-Service '{name}' -Force -PassThru",
            "restart": f"Restart-Service '{name}' -Force -PassThru",
        }
        if action not in cmds:
            raise ValueError(f"action must be start/stop/restart")
        return await self.exec(node_id, cmds[action], timeout=30)

    # -- Fleet operations ---------------------------------------------

    async def fleet_exec(
        self,
        node_ids: list[str],
        command: str,
        timeout: float = None,
    ) -> dict[str, ExecResult]:
        """Run same command on N nodes in parallel."""
        timeout = timeout or self._timeout

        async def _one(nid):
            try:
                return nid, await self.exec(nid, command, timeout=timeout)
            except Exception as e:
                return nid, ExecResult(
                    exit_code=-1, stdout="", stderr=str(e),
                    duration_ms=0, node_id=nid, command=command,
                )

        return dict(await asyncio.gather(*[_one(n) for n in node_ids]))

    async def fleet_health(self, node_ids: list[str] = None) -> dict[str, dict]:
        """DFI health check across fleet."""
        if node_ids is None:
            nodes = await self.list_nodes(refresh=True)
            node_ids = [n.node_id for n in nodes
                        if n.agent_state != AgentState.OFFLINE]

        cmd = (
            "$s=Get-Service 'DFICaptureAgent' -EA SilentlyContinue; "
            "$b='C:\\DFI\\data\\agent_buffer.db'; "
            "$d=Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\"; "
            "@{ hostname=$env:COMPUTERNAME; "
            "   svc_status=if($s){$s.Status.ToString()}else{'NotInstalled'}; "
            "   buffer_mb=if(Test-Path $b){[math]::Round((Get-Item $b).Length/1MB,1)}else{0}; "
            "   disk_free_gb=[math]::Round($d.FreeSpace/1GB,1); "
            "   ts=(Get-Date).ToString('o') "
            "} | ConvertTo-Json -Compress"
        )
        raw = await self.fleet_exec(node_ids, cmd)
        out = {}
        for nid, r in raw.items():
            if r.ok:
                try:
                    out[nid] = json.loads(r.stdout)
                    out[nid]["healthy"] = True
                except json.JSONDecodeError:
                    out[nid] = {"healthy": False, "error": "json_parse"}
            else:
                out[nid] = {"healthy": False, "error": r.output[:200]}
        return out

    # -- DFI-specific shortcuts ---------------------------------------

    async def dfi_pull_buffer(self, node_id: str,
                               local_path: str = None) -> bytes:
        return await self.file_pull(
            node_id, r"C:\DFI\data\agent_buffer.db", local_path)

    async def dfi_pull_evidence(self, node_id: str,
                                 local_path: str = None) -> bytes:
        return await self.file_pull(
            node_id, r"C:\DFI\data\evidence.db", local_path)

    async def dfi_push_config(self, node_id: str, config: dict) -> bool:
        data = json.dumps(config, indent=2).encode("utf-8")
        await self.file_push(node_id, data, r"C:\DFI\config.json")
        await self.service_control(node_id, "DFICaptureAgent", "restart")
        return True

    async def dfi_agent_status(self, node_id: str) -> dict:
        r = await self.exec(
            node_id, "Get-Content 'C:\\DFI\\status.json' -Raw", timeout=10)
        if r.ok:
            try:
                return json.loads(r.stdout)
            except json.JSONDecodeError:
                pass
        return {"error": r.output}

    async def wait_ready(self, node_id: str, timeout: float = 120,
                          poll: float = 5) -> bool:
        """Wait for agent to respond to a probe."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                r = await self.exec(node_id, "echo DFI_READY", timeout=10)
                if r.ok and "DFI_READY" in r.stdout:
                    return True
            except Exception:
                pass
            self._cache_ts = 0
            await asyncio.sleep(poll)
        return False


# =====================================================================
# CLI
# =====================================================================

async def _main():
    import argparse as ap

    p = ap.ArgumentParser(description="DFI MeshCentral Translator v3")
    p.add_argument("--url", default="wss://192.168.0.112:443",
                   help="MeshCentral URL")
    p.add_argument("--user", default="admin")
    p.add_argument("--pass", dest="password", default="CHANGE_ME")
    p.add_argument("--no-tls-verify", action="store_true", default=True)
    p.add_argument("--cb-host", default="0.0.0.0")
    p.add_argument("--cb-port", type=int, default=9080)
    p.add_argument("--cb-ext", default=None,
                   help="External IP agents use to reach callback")

    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("nodes", help="List all nodes")

    e = sub.add_parser("exec", help="Execute command")
    e.add_argument("node"); e.add_argument("command")
    e.add_argument("-t", "--timeout", type=float, default=60)
    e.add_argument("--type", type=int, default=2,
                   help="1=cmd.exe, 2=PowerShell, 3=Linux shell")

    dl = sub.add_parser("pull", help="Download file")
    dl.add_argument("node"); dl.add_argument("remote"); dl.add_argument("local")

    ul = sub.add_parser("push", help="Upload file")
    ul.add_argument("node"); ul.add_argument("local"); ul.add_argument("remote")

    sv = sub.add_parser("svc", help="Service control")
    sv.add_argument("node")
    sv.add_argument("action", choices=["list", "start", "stop", "restart"])
    sv.add_argument("name", nargs="?", default="*")

    sub.add_parser("health", help="Fleet health check")

    args = p.parse_args()
    if not args.cmd:
        p.print_help()
        return

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    async with MeshTranslator(
        url=args.url,
        username=args.user,
        password=args.password,
        verify_tls=not args.no_tls_verify,
        callback_host=args.cb_host,
        callback_port=args.cb_port,
        callback_external_host=args.cb_ext,
    ) as mt:

        if args.cmd == "nodes":
            for n in await mt.list_nodes():
                s = "ON " if n.agent_state != AgentState.OFFLINE else "OFF"
                print(f"  [{s}] {n.name:30s} {n.os_desc:40s} {n.ip}")

        elif args.cmd == "exec":
            r = await mt.exec(args.node, args.command,
                              cmd_type=args.type, timeout=args.timeout)
            print(f"[exit={r.exit_code} {r.duration_ms}ms timed_out={r.timed_out}]")
            if r.stdout: print(r.stdout)
            if r.stderr: print(f"[STDERR] {r.stderr}")

        elif args.cmd == "pull":
            d = await mt.file_pull(args.node, args.remote, args.local)
            print(f"Downloaded {len(d)} bytes -> {args.local}")

        elif args.cmd == "push":
            h = await mt.file_push(args.node, args.local, args.remote)
            print(f"Uploaded, SHA256={h}")

        elif args.cmd == "svc":
            if args.action == "list":
                for s in await mt.service_list(args.node, args.name):
                    print(f"  {s.status:10s} {s.name:30s} {s.display_name}")
            else:
                r = await mt.service_control(args.node, args.name, args.action)
                print(f"[exit={r.exit_code}] {r.stdout}")

        elif args.cmd == "health":
            h = await mt.fleet_health()
            for nid, info in h.items():
                ok = "+" if info.get("healthy") else "X"
                host = info.get("hostname", nid[:12])
                svc = info.get("svc_status", "?")
                buf = info.get("buffer_mb", "?")
                disk = info.get("disk_free_gb", "?")
                print(f"  {ok} {host:20s} svc={svc:10s} buf={buf}MB disk={disk}GB")


if __name__ == "__main__":
    asyncio.run(_main())
