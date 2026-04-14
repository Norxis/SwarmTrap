#!/usr/bin/env python3
"""
Test suite for DFI MeshCentral Translator v3.

Tests the direct WebSocket control channel with reply:true,
node discovery, command execution, and file transfer.

Run:  python3 test_mesh_translator.py [--quick]
"""

import sys
import os
import json
import asyncio
import time
import tempfile
import hashlib
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dfi_mesh_translator import MeshTranslator, AgentState, ExecResult, NodeInfo

# ── Connection details ─────────────────────────────────────────────
MC_URL  = "wss://192.168.0.112:443"
MC_USER = "admin"
MC_PASS = "CHANGE_ME"
NODE_ID = "node//rJxuIjVnZfALO8tHSCnolfbv3suKO0GhuhTBwHJJ170YIsgNVyRb2yfjwrgpWjvn"

# Callback server must be reachable from agent VM.
# Use WSL's IP on the mgmt VLAN if available.
CB_HOST = "0.0.0.0"
CB_PORT = 9080

results: dict[str, bool] = {}


def report(name: str, passed: bool, detail: str = ""):
    results[name] = passed
    icon = "[PASS]" if passed else "[FAIL]"
    line = f"  {icon} {name}"
    if detail:
        line += f"  ({detail})"
    print(line)


# ── Test 1: Connect + Auth ─────────────────────────────────────────

async def test_connect_auth(mt: MeshTranslator):
    print("\n" + "=" * 60)
    print("  Test 1: Connect + Auth")
    print("=" * 60)

    try:
        ok = mt.connected
        report("connect_auth", ok, f"connected={ok} nodes={len(mt._nodes)}")
        return ok
    except Exception as e:
        report("connect_auth", False, str(e))
        return False


# ── Test 2: List Nodes ─────────────────────────────────────────────

async def test_list_nodes(mt: MeshTranslator):
    print("\n" + "=" * 60)
    print("  Test 2: List Nodes")
    print("=" * 60)

    try:
        nodes = await mt.list_nodes(refresh=True)
        if not nodes:
            report("list_nodes", False, "no nodes returned")
            return False

        found_target = False
        for n in nodes:
            icon = "[ON] " if n.agent_state != AgentState.OFFLINE else "[OFF]"
            print(f"    {icon} {n.name:25s} {n.os_desc:35s} {n.node_id[:50]}")
            if n.node_id == NODE_ID or "SRV25" in n.name.upper():
                found_target = True

        report("list_nodes", True, f"{len(nodes)} nodes, target={'found' if found_target else 'NOT FOUND'}")
        if not found_target:
            print(f"    [WARN] Expected node {NODE_ID[:40]}... not found")
        return True
    except Exception as e:
        report("list_nodes", False, str(e))
        return False


# ── Test 3: Exec Simple (Get-Date) ────────────────────────────────

async def test_exec_simple(mt: MeshTranslator):
    print("\n" + "=" * 60)
    print("  Test 3: Exec Simple (Get-Date via reply:true)")
    print("=" * 60)

    try:
        r = await mt.exec(NODE_ID, "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'", timeout=30)
        ok = r.ok and len(r.stdout) > 5
        print(f"    stdout: {r.stdout[:200]}")
        print(f"    exit={r.exit_code} duration={r.duration_ms}ms timed_out={r.timed_out}")
        report("exec_simple", ok, f"{r.duration_ms}ms")
        return ok
    except Exception as e:
        report("exec_simple", False, str(e))
        return False


# ── Test 4: Exec Service Check ────────────────────────────────────

async def test_exec_service(mt: MeshTranslator):
    print("\n" + "=" * 60)
    print("  Test 4: Exec Service Check")
    print("=" * 60)

    try:
        r = await mt.exec(NODE_ID,
                          "Get-Service WinHuntAgent -EA SilentlyContinue | "
                          "Select Name,Status | Format-List",
                          timeout=30)
        print(f"    stdout: {r.stdout[:300]}")
        print(f"    exit={r.exit_code} duration={r.duration_ms}ms")
        # OK even if service doesn't exist -- we care about exec working
        report("exec_service", r.ok or "Cannot find" in r.stdout,
               f"{r.duration_ms}ms")
        return True
    except Exception as e:
        report("exec_service", False, str(e))
        return False


# ── Test 5: Exec Error (bad command) ──────────────────────────────

async def test_exec_error(mt: MeshTranslator):
    print("\n" + "=" * 60)
    print("  Test 5: Exec Error (intentionally bad command)")
    print("=" * 60)

    try:
        r = await mt.exec(NODE_ID,
                          "Get-InvalidCmdlet-ThatDoesNotExist-12345",
                          timeout=15)
        print(f"    stdout: {r.stdout[:200]}")
        print(f"    stderr: {r.stderr[:200]}")
        print(f"    exit={r.exit_code}")
        # reply:true returns the error text in result field
        has_output = bool(r.stdout) or bool(r.stderr)
        report("exec_error", has_output,
               "error text captured" if has_output else "no error text")
        return True
    except Exception as e:
        report("exec_error", False, str(e))
        return False


# ── Test 6: Exec Timeout ─────────────────────────────────────────

async def test_exec_timeout(mt: MeshTranslator):
    print("\n" + "=" * 60)
    print("  Test 6: Exec Timeout (Start-Sleep 30 with 5s timeout)")
    print("=" * 60)

    try:
        t0 = time.monotonic()
        r = await mt.exec(NODE_ID, "Start-Sleep 30", timeout=5)
        elapsed = time.monotonic() - t0
        print(f"    timed_out={r.timed_out} exit={r.exit_code} wall={elapsed:.1f}s")
        ok = r.timed_out and r.exit_code == 124 and elapsed < 10
        report("exec_timeout", ok, f"wall={elapsed:.1f}s")
        return ok
    except Exception as e:
        report("exec_timeout", False, str(e))
        return False


# ── Test 7: Service List ─────────────────────────────────────────

async def test_service_list(mt: MeshTranslator):
    print("\n" + "=" * 60)
    print("  Test 7: Service List (structured ServiceInfo)")
    print("=" * 60)

    try:
        svcs = await mt.service_list(NODE_ID, "W*")
        if not svcs:
            report("service_list", False, "no services returned")
            return False

        for s in svcs[:5]:
            print(f"    {s.status:10s} {s.name:25s} {s.display_name}")
        if len(svcs) > 5:
            print(f"    ... and {len(svcs) - 5} more")

        report("service_list", True, f"{len(svcs)} services")
        return True
    except Exception as e:
        report("service_list", False, str(e))
        return False


# ── Test 8: Fleet Exec ───────────────────────────────────────────

async def test_fleet_exec(mt: MeshTranslator):
    print("\n" + "=" * 60)
    print("  Test 8: Fleet Exec (parallel single node)")
    print("=" * 60)

    try:
        t0 = time.monotonic()
        results_map = await mt.fleet_exec([NODE_ID], "$env:COMPUTERNAME")
        elapsed = time.monotonic() - t0

        for nid, r in results_map.items():
            print(f"    {nid[:40]}... exit={r.exit_code} out={r.stdout[:100]}")

        ok = NODE_ID in results_map and results_map[NODE_ID].ok
        report("fleet_exec", ok, f"{elapsed:.1f}s")
        return ok
    except Exception as e:
        report("fleet_exec", False, str(e))
        return False


# ── Test 9: File Push + Pull Roundtrip ────────────────────────────

async def test_file_roundtrip(mt: MeshTranslator):
    print("\n" + "=" * 60)
    print("  Test 9: File Push + Pull Roundtrip")
    print("=" * 60)

    try:
        # Generate test data
        test_data = f"DFI translator v3 test - {time.time()}\n".encode()
        test_data += os.urandom(1024)  # Add binary payload
        expected_hash = hashlib.sha256(test_data).hexdigest().lower()
        remote_path = r"C:\TEMP\dfi_translator_test.bin"

        print(f"    Pushing {len(test_data)} bytes -> {remote_path}")
        push_hash = await mt.file_push(NODE_ID, test_data, remote_path, timeout=60)
        print(f"    Push hash: {push_hash}")

        if push_hash != expected_hash:
            report("file_roundtrip", False, f"push hash mismatch")
            return False

        # Pull it back
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp_path = tmp.name

        try:
            print(f"    Pulling back -> {tmp_path}")
            pulled = await mt.file_pull(NODE_ID, remote_path, tmp_path, timeout=60)
            pull_hash = hashlib.sha256(pulled).hexdigest().lower()
            print(f"    Pull hash: {pull_hash}")
            print(f"    Size match: {len(pulled)} == {len(test_data)}")

            ok = (pull_hash == expected_hash and len(pulled) == len(test_data))
            report("file_roundtrip", ok,
                   f"sha256 match={pull_hash == expected_hash} size={len(pulled)}")
        finally:
            os.unlink(tmp_path)

        # Clean up remote file
        await mt.exec(NODE_ID,
                      f"Remove-Item '{remote_path}' -Force -EA SilentlyContinue",
                      timeout=10)
        return ok

    except Exception as e:
        report("file_roundtrip", False, str(e))
        import traceback; traceback.print_exc()
        return False


# ── Cross-validation with skills/mesh.py ─────────────────────────

def test_cross_validate(translator_output: str):
    """Compare translator output with Paramiko->meshctrl.js --reply path."""
    print("\n" + "=" * 60)
    print("  Cross-validation: Translator vs skills/mesh.py")
    print("=" * 60)

    try:
        import paramiko

        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect("192.168.0.100", username="root",
                  password="CHANGE_ME", timeout=10)

        script = f"""#!/bin/bash
cd /opt/meshcentral
timeout 30 node node_modules/meshcentral/meshctrl.js runcommand \\
  --id "{NODE_ID}" \\
  --run "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'" \\
  --powershell --reply \\
  --url wss://localhost \\
  --loginuser admin --loginpass "CHANGE_ME" 2>&1
"""
        si, so, _ = c.exec_command(
            "pct exec 112 -- tee /tmp/_mc_xval.sh > /dev/null", timeout=10)
        si.write(script)
        si.channel.shutdown_write()
        so.read()

        si2, so2, se2 = c.exec_command(
            "pct exec 112 -- bash /tmp/_mc_xval.sh", timeout=45)
        mesh_out = so2.read().decode().strip()
        c.close()

        print(f"    Translator: {translator_output[:100]}")
        print(f"    meshctrl:   {mesh_out[:100]}")

        # Both should contain a date-like string
        has_date_t = any(c.isdigit() for c in translator_output)
        has_date_m = any(c.isdigit() for c in mesh_out)
        ok = has_date_t and has_date_m
        report("cross_validate", ok,
               f"translator={'date' if has_date_t else 'empty'} "
               f"meshctrl={'date' if has_date_m else 'empty'}")
        return ok

    except Exception as e:
        report("cross_validate", False, str(e))
        return False


# ── Main ──────────────────────────────────────────────────────────

async def async_main(quick: bool = False):
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    print("DFI MeshCentral Translator v3 — Test Suite")
    print(f"Target: {MC_URL} -> node {NODE_ID[:40]}...")
    print(f"Mode: {'quick' if quick else 'full'}")

    mt = MeshTranslator(
        url=MC_URL,
        username=MC_USER,
        password=MC_PASS,
        verify_tls=False,
        callback_host=CB_HOST,
        callback_port=CB_PORT,
    )

    try:
        await mt.connect()

        # Core tests (always run)
        await test_connect_auth(mt)
        await test_list_nodes(mt)

        exec_out = ""
        if results.get("connect_auth"):
            r = await test_exec_simple(mt)
            if r:
                # Save output for cross-validation
                exec_out = (await mt.exec(NODE_ID,
                            "Get-Date -Format 'yyyy-MM-dd HH:mm:ss'",
                            timeout=15)).stdout

            await test_exec_service(mt)
            await test_exec_error(mt)
            await test_service_list(mt)
            await test_fleet_exec(mt)

            # Timeout test LAST — Start-Sleep blocks the agent's
            # command queue, so nothing else should follow it.
            await test_exec_timeout(mt)

            if not quick:
                await test_file_roundtrip(mt)

        await mt.close()

        # Cross-validation (sync, uses Paramiko)
        if not quick and exec_out:
            test_cross_validate(exec_out)

    except Exception as e:
        print(f"\n  [FATAL] {e}")
        import traceback; traceback.print_exc()
        await mt.close()


def main():
    quick = "--quick" in sys.argv

    asyncio.run(async_main(quick))

    # Summary
    print("\n" + "=" * 60)
    print("  RESULTS")
    print("=" * 60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    for name, ok in results.items():
        icon = "[PASS]" if ok else "[FAIL]"
        print(f"  {icon} {name}")
    print(f"\n  {passed}/{total} passed")

    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
