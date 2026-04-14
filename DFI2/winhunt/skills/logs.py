#!/usr/bin/env python3
"""View WinHunt agent logs via MeshCentral.

Usage:
    python skills/logs.py              # last 30 lines of agent.log
    python skills/logs.py --stderr     # last 30 lines of stderr.log
    python skills/logs.py -n 100       # last 100 lines
    python skills/logs.py --follow     # tail -f style (polls every 5s)
"""
import sys, os, time, argparse
sys.path.insert(0, os.path.dirname(__file__))
from mesh import MeshSession


def main():
    p = argparse.ArgumentParser(description="View WinHunt logs via MeshCentral")
    p.add_argument("-n", "--lines", type=int, default=30, help="Number of lines")
    p.add_argument("--stderr", action="store_true", help="Show stderr.log instead")
    p.add_argument("--follow", "-f", action="store_true", help="Poll continuously")
    args = p.parse_args()

    log_path = r"C:\DFI\stderr.log" if args.stderr else r"C:\Program Files\DFI\logs\agent.log"
    log_name = "stderr.log" if args.stderr else "agent.log"

    with MeshSession() as m:
        if args.follow:
            print(f"Following {log_name} (Ctrl+C to stop)...")
            seen = set()
            while True:
                out = m.ps(f'Get-Content "{log_path}" -Tail {args.lines}')
                lines = out.split("\n") if out else []
                for line in lines:
                    if line not in seen:
                        seen.add(line)
                        print(line)
                # Keep set bounded
                if len(seen) > 1000:
                    seen = set(lines)
                time.sleep(5)
        else:
            m.ps(f'Get-Content "{log_path}" -Tail {args.lines}', log_name)


if __name__ == "__main__":
    main()
