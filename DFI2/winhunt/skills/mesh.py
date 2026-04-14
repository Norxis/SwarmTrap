#!/usr/bin/env python3
"""MeshCentral core library — all Windows management goes through here.

Every skill imports this module. Never use WinRM directly.

Usage:
    from mesh import MeshSession

    with MeshSession() as m:
        print(m.ps('Get-Date'))
        print(m.ps_file(big_script))
        m.upload_text(r'C:\\TEMP\\hello.txt', 'hello world')
        m.upload_bin(local_path, remote_path)
        m.svc_restart('WinHuntAgent')
"""
import paramiko
import time
import os
import sys

MAX_CONSECUTIVE_FAILURES = 3


class StrikeOut(RuntimeError):
    """Raised after MAX_CONSECUTIVE_FAILURES consecutive command failures."""
    pass

PV1 = "192.168.0.100"
PV1_USER = "root"
PV1_PASS = "CHANGE_ME"

CT_ID = 112
MESH_IP = "172.16.3.112"
MESH_USER = "admin"
MESH_PASS = "CHANGE_ME"
MESH_HTTP_PORT = 8888

NODE_ID = "node//rJxuIjVnZfALO8tHSCnolfbv3suKO0GhuhTBwHJJ170YIsgNVyRb2yfjwrgpWjvn"


class MeshSession:
    """Manages paramiko connection to PV1 and runs commands via CT112 meshctrl."""

    def __init__(self):
        self._conn = None
        self._strikes = 0  # consecutive failures

    def __enter__(self):
        self._conn = paramiko.SSHClient()
        self._conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._conn.connect(PV1, username=PV1_USER, password=PV1_PASS, timeout=10)
        return self

    def __exit__(self, *exc):
        if self._conn:
            self._conn.close()
            self._conn = None

    # ── low-level ────────────────────────────────────────────

    def _pv1(self, cmd, timeout=30):
        """Run command on PV1, return (stdout, stderr)."""
        stdin, stdout, stderr = self._conn.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        return out, err

    def _ct(self, cmd, timeout=30):
        """Run command inside CT112, return (stdout, stderr)."""
        return self._pv1(f"pct exec {CT_ID} -- {cmd}", timeout=timeout)

    def _write_ct_file(self, path, content):
        """Write content to a file inside CT112."""
        stdin, stdout, _ = self._conn.exec_command(
            f"pct exec {CT_ID} -- tee {path} > /dev/null", timeout=10)
        stdin.write(content)
        stdin.channel.shutdown_write()
        stdout.read()

    def _ensure_http(self):
        """Ensure CT112 HTTP file server is running on port 8888."""
        out, _ = self._ct(f"ss -tlnp | grep {MESH_HTTP_PORT}")
        if str(MESH_HTTP_PORT) not in out:
            self._ct(
                f'bash -c "setsid python3 -m http.server {MESH_HTTP_PORT} '
                f'--directory /tmp </dev/null >/dev/null 2>&1 &"')
            time.sleep(1)

    def _check_strikes(self):
        """Raise StrikeOut if we've hit the consecutive failure limit."""
        if self._strikes >= MAX_CONSECUTIVE_FAILURES:
            raise StrikeOut(
                f"HELP!!! {self._strikes} consecutive command failures. "
                f"--reply is likely broken. Stop and ask the user."
            )

    def _record_success(self):
        self._strikes = 0

    def _record_failure(self):
        self._strikes += 1
        print(f"[STRIKE {self._strikes}/{MAX_CONSECUTIVE_FAILURES}]")
        if self._strikes >= MAX_CONSECUTIVE_FAILURES:
            print(f"\n*** HELP!!! {self._strikes} consecutive failures — stopping ***\n")

    def _meshctrl_sh(self, run_arg, timeout=30):
        """Write and execute a meshctrl bash script on CT112, return output."""
        self._check_strikes()
        script = f"""#!/bin/bash
cd /opt/meshcentral
node node_modules/meshcentral/meshctrl.js runcommand \\
  --id "{NODE_ID}" \\
  --run '{run_arg}' \\
  --powershell --reply \\
  --url wss://localhost \\
  --loginuser {MESH_USER} --loginpass "{MESH_PASS}" 2>&1
"""
        self._write_ct_file("/tmp/_mc.sh", script)
        try:
            stdin, stdout, stderr = self._conn.exec_command(
                f"pct exec {CT_ID} -- bash /tmp/_mc.sh", timeout=timeout + 30)
            out = stdout.read().decode().strip()
            err = stderr.read().decode().strip()
        except (TimeoutError, OSError) as exc:
            self._record_failure()
            raise
        if not out and not err:
            self._record_failure()
        else:
            self._record_success()
        return out, err

    # ── public API ───────────────────────────────────────────

    def ps(self, ps_cmd, label="", timeout=30):
        """Run a PowerShell command on Windows, return output string.

        For single-line or simple multi-line commands where the PS code
        does not contain single quotes.
        """
        if label:
            print(f"\n{'='*50}\n{label}\n{'='*50}")
        out, err = self._meshctrl_sh(ps_cmd, timeout=timeout)
        if out:
            print(out)
        if err:
            print(f"ERR: {err[:300]}")
        return out

    def ps_file(self, ps_script, label="", timeout=60):
        """Run a multi-line PS1 script on Windows via file download.

        Handles any quoting — writes PS1 to CT112, Windows downloads
        and executes it.
        """
        if label:
            print(f"\n{'='*50}\n{label}\n{'='*50}")

        self._write_ct_file("/tmp/_mc_script.ps1", ps_script)
        self._ensure_http()

        # Build meshctrl command that downloads + executes the PS1
        dl_and_run = (
            f'powershell -ExecutionPolicy Bypass -Command "'
            f"(New-Object System.Net.WebClient).DownloadFile("
            f"'http://{MESH_IP}:{MESH_HTTP_PORT}/_mc_script.ps1',"
            f"'C:\\TEMP\\_mc_script.ps1'); "
            f'& C:\\TEMP\\_mc_script.ps1"'
        )
        script = f"""#!/bin/bash
cd /opt/meshcentral
node node_modules/meshcentral/meshctrl.js runcommand \\
  --id "{NODE_ID}" \\
  --run "{dl_and_run}" \\
  --powershell --reply \\
  --url wss://localhost \\
  --loginuser {MESH_USER} --loginpass "{MESH_PASS}" 2>&1
"""
        self._write_ct_file("/tmp/_mc_file.sh", script)
        stdin, stdout, stderr = self._conn.exec_command(
            f"pct exec {CT_ID} -- bash /tmp/_mc_file.sh", timeout=timeout + 30)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        if out:
            print(out)
        if err:
            print(f"ERR: {err[:300]}")
        return out

    def upload_text(self, remote_path, content, label=""):
        """Write text content to a file on Windows."""
        if label:
            print(f"\n{'='*50}\n{label}\n{'='*50}")
        # Escape for PowerShell Set-Content
        escaped = content.replace("'", "''")
        # Use BOM-free UTF8 writing
        ps = (
            f"[System.IO.File]::WriteAllText("
            f"'{remote_path}', '{escaped}', "
            f"(New-Object System.Text.UTF8Encoding $false))"
        )
        return self.ps(ps, timeout=15)

    def upload_bin(self, local_path, remote_path, label=""):
        r"""Upload a binary file to Windows via CT112 HTTP server.

        IMPORTANT: remote_path must use single backslashes (raw string).
        Example: r"C:\TEMP\file.zip"   <- CORRECT
                 "C:\\TEMP\\file.zip"  <- WRONG (escape sequences)
        """
        if label:
            print(f"\n{'='*50}\n{label}\n{'='*50}")

        filename = os.path.basename(local_path)

        # Upload to PV1 /tmp
        sftp = self._conn.open_sftp()
        sftp.put(local_path, f"/tmp/{filename}")
        sftp.close()

        # Push into CT112
        self._pv1(f"pct push {CT_ID} /tmp/{filename} /tmp/{filename}", timeout=30)

        # Serve via HTTP + download on Windows
        # Use raw string template — never \\ for Windows paths
        self._ensure_http()
        url = f"http://{MESH_IP}:{MESH_HTTP_PORT}/{filename}"
        ps = (
            '$wc = New-Object System.Net.WebClient; '
            f'$wc.DownloadFile("{url}","{remote_path}"); '
            f'(Get-Item "{remote_path}").Length'
        )
        return self.ps(ps, timeout=60)

    def svc(self, name, action="status"):
        """Manage a Windows service: status, start, stop, restart."""
        if action == "status":
            return self.ps(f'Get-Service "{name}" | Format-List Name,Status,StartType')
        elif action == "start":
            return self.ps(f'Start-Service "{name}"; Get-Service "{name}" | Format-List Status')
        elif action == "stop":
            return self.ps(f'Stop-Service "{name}" -Force; Get-Service "{name}" | Format-List Status')
        elif action == "restart":
            return self.ps(
                f'Restart-Service "{name}" -Force; Start-Sleep 3; '
                f'Get-Service "{name}" | Format-List Status')
        else:
            raise ValueError(f"Unknown action: {action}")

    def svc_restart(self, name):
        """Restart a Windows service via NSSM (for NSSM-managed services)."""
        return self.ps(
            f'nssm restart "{name}"; Start-Sleep 5; '
            f'Get-Service "{name}" | Format-List Status')

    def devices(self):
        """List MeshCentral devices."""
        out, _ = self._ct(
            'bash -c "cd /opt/meshcentral && node node_modules/meshcentral/meshctrl.js '
            f'listdevices --json --url wss://localhost '
            f'--loginuser {MESH_USER} --loginpass \\"{MESH_PASS}\\" 2>/dev/null"')
        print(out)
        return out
