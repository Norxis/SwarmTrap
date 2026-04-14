#!/usr/bin/env python3
"""WinRM helper — run PowerShell on 172.16.3.160."""
import sys
import winrm

HOST = "http://172.16.3.160:5985/wsman"
USER = "Administrator"
PASS = "CHANGE_ME"

def run_ps(script: str) -> tuple[str, str, int]:
    s = winrm.Session(HOST, auth=(USER, PASS), transport="ntlm")
    r = s.run_ps(script)
    return r.std_out.decode("utf-8", errors="replace"), r.std_err.decode("utf-8", errors="replace"), r.status_code

if __name__ == "__main__":
    if len(sys.argv) > 1:
        script = " ".join(sys.argv[1:])
    else:
        script = sys.stdin.read()
    out, err, code = run_ps(script)
    if out:
        print(out)
    if err:
        print("STDERR:", err, file=sys.stderr)
    sys.exit(code)
