#!/usr/bin/env python3
"""Manage Windows services via MeshCentral.

Usage:
    python skills/svc.py                          # status of WinHuntAgent + Mesh Agent
    python skills/svc.py restart WinHuntAgent     # restart via NSSM
    python skills/svc.py stop WinHuntAgent        # stop
    python skills/svc.py start WinHuntAgent       # start
    python skills/svc.py list                     # list all services
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from mesh import MeshSession


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    name = sys.argv[2] if len(sys.argv) > 2 else None

    with MeshSession() as m:
        if action == "status":
            m.ps('Get-Service WinHuntAgent,"Mesh Agent" | Format-List Name,Status,StartType',
                 "Services")
        elif action == "list":
            m.ps('Get-Service | Where-Object {$_.Status -eq "Running"} | Sort-Object Name | Format-Table Name,Status,StartType -AutoSize',
                 "Running Services")
        elif action in ("start", "stop", "restart") and name:
            if action == "restart" and name == "WinHuntAgent":
                m.svc_restart(name)
            else:
                m.svc(name, action)
        else:
            print("Usage: svc.py [status|start|stop|restart|list] [ServiceName]")


if __name__ == "__main__":
    main()
