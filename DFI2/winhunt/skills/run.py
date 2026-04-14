#!/usr/bin/env python3
"""Run arbitrary PowerShell on Windows via MeshCentral.

Usage:
    python skills/run.py 'Get-Date'
    python skills/run.py 'Get-Process | Select -First 5'
    echo 'whoami' | python skills/run.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from mesh import MeshSession


def main():
    if len(sys.argv) > 1:
        ps_cmd = " ".join(sys.argv[1:])
    elif not sys.stdin.isatty():
        ps_cmd = sys.stdin.read().strip()
    else:
        print("Usage: run.py 'PS command' | echo 'PS' | run.py")
        sys.exit(1)

    with MeshSession() as m:
        m.ps(ps_cmd)


if __name__ == "__main__":
    main()
