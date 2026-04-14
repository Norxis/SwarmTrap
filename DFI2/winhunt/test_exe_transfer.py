#!/usr/bin/env python3
"""
Test exe file transfer via WebSocket base64 path.

1. Pull hostname.exe from Windows system32 via file_pull_b64
2. Push it to C:\TEMP\test_hostname.exe via file_push_b64
3. Execute it and verify output matches $env:COMPUTERNAME
4. Clean up
"""

import sys
import os
import asyncio
import hashlib
import logging
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dfi_mesh_translator import MeshTranslator

MC_URL  = "wss://192.168.0.112:443"
MC_USER = "admin"
MC_PASS = "CHANGE_ME"
NODE_ID = "node//rJxuIjVnZfALO8tHSCnolfbv3suKO0GhuhTBwHJJ170YIsgNVyRb2yfjwrgpWjvn"


async def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    mt = MeshTranslator(url=MC_URL, username=MC_USER, password=MC_PASS)
    await mt.connect()

    try:
        # -- Step 0: Get hostname for later verification ----------------
        print("\n=== Step 0: Get hostname ===")
        r = await mt.exec(NODE_ID, "$env:COMPUTERNAME", timeout=10)
        hostname = r.stdout.strip()
        print(f"  Hostname: {hostname}")

        # -- Step 1: Pull hostname.exe from system32 --------------------
        print("\n=== Step 1: Pull hostname.exe via base64 WS ===")
        src = r"C:\Windows\System32\hostname.exe"
        t0 = time.monotonic()
        exe_bytes = await mt.file_pull_b64(NODE_ID, src)
        pull_ms = int((time.monotonic() - t0) * 1000)
        pull_hash = hashlib.sha256(exe_bytes).hexdigest()
        print(f"  Pulled {len(exe_bytes):,} bytes in {pull_ms}ms")
        print(f"  SHA256: {pull_hash}")

        # Sanity: MZ header
        if exe_bytes[:2] != b"MZ":
            print("  [FAIL] Not a valid PE — missing MZ header")
            return 1

        # Save locally for inspection
        local_path = "/tmp/test_hostname.exe"
        with open(local_path, "wb") as f:
            f.write(exe_bytes)
        print(f"  Saved locally: {local_path}")

        # -- Step 2: Push to C:\TEMP\test_hostname.exe ------------------
        print("\n=== Step 2: Push hostname.exe via base64 WS ===")
        dest = r"C:\TEMP\test_hostname.exe"
        t0 = time.monotonic()
        push_hash = await mt.file_push_b64(NODE_ID, exe_bytes, dest)
        push_ms = int((time.monotonic() - t0) * 1000)
        print(f"  Pushed {len(exe_bytes):,} bytes in {push_ms}ms")
        print(f"  SHA256: {push_hash}")

        if push_hash != pull_hash:
            print(f"  [FAIL] Hash mismatch: pull={pull_hash} push={push_hash}")
            return 1
        print(f"  [OK] SHA256 match confirmed")

        # -- Step 3: Execute the pushed exe -----------------------------
        print("\n=== Step 3: Execute pushed exe ===")
        r = await mt.exec(NODE_ID, f"& '{dest}'", timeout=15)
        exe_output = r.stdout.strip()
        print(f"  Output: {exe_output}")
        print(f"  exit={r.exit_code} duration={r.duration_ms}ms")

        if hostname.upper() in exe_output.upper():
            print(f"  [OK] hostname.exe output matches $env:COMPUTERNAME")
        else:
            print(f"  [FAIL] Expected '{hostname}' in output '{exe_output}'")
            return 1

        # -- Step 4: Pull it back and verify roundtrip ------------------
        print("\n=== Step 4: Pull back + verify roundtrip ===")
        t0 = time.monotonic()
        roundtrip_bytes = await mt.file_pull_b64(NODE_ID, dest)
        rt_ms = int((time.monotonic() - t0) * 1000)
        rt_hash = hashlib.sha256(roundtrip_bytes).hexdigest()
        print(f"  Pulled back {len(roundtrip_bytes):,} bytes in {rt_ms}ms")

        if rt_hash == pull_hash and len(roundtrip_bytes) == len(exe_bytes):
            print(f"  [OK] Full roundtrip verified — SHA256 + size match")
        else:
            print(f"  [FAIL] Roundtrip mismatch: {rt_hash} vs {pull_hash}")
            return 1

        # -- Step 5: Cleanup -------------------------------------------
        print("\n=== Step 5: Cleanup ===")
        r = await mt.exec(NODE_ID,
                          f"Remove-Item '{dest}' -Force -EA SilentlyContinue; 'cleaned'",
                          timeout=10)
        print(f"  {r.stdout.strip()}")
        os.unlink(local_path)

        # -- Summary ---------------------------------------------------
        print("\n" + "=" * 60)
        print("  EXE TRANSFER TEST — ALL PASSED")
        print("=" * 60)
        print(f"  File: hostname.exe ({len(exe_bytes):,} bytes)")
        print(f"  Pull:  {pull_ms}ms")
        print(f"  Push:  {push_ms}ms")
        print(f"  Exec:  {r.duration_ms}ms")
        print(f"  Roundtrip pull: {rt_ms}ms")
        print(f"  SHA256: {pull_hash}")
        return 0

    except Exception as e:
        print(f"\n  [FATAL] {e}")
        import traceback; traceback.print_exc()
        return 1
    finally:
        await mt.close()


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
