import time
from typing import Any

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VM_MAP: dict[int, dict[str, str]] = {
    100: dict(name="UBT20",  lan="172.16.3.168",  pub="216.126.0.211",  os="Ubuntu 20.04",      svcs="SSH, Winlure"),
    101: dict(name="UBT22",  lan="172.16.3.166",  pub="216.126.0.214",  os="Ubuntu 22.04",      svcs="SSH"),
    102: dict(name="UBT24",  lan="172.16.3.167",  pub="216.126.0.217",  os="Ubuntu 24.04",      svcs="SSH"),
    103: dict(name="SRV19",  lan="172.16.3.213",  pub="216.126.0.210",  os="Win Server 2019",   svcs="SSH, RDP, SMB"),
    104: dict(name="SRV22",  lan="172.16.3.212",  pub="216.126.0.212",  os="Win Server 2022",   svcs="SSH, RDP, SMB"),
    105: dict(name="SRV25",  lan="172.16.3.170",  pub="216.126.0.219",  os="Win Server 2025",   svcs="SSH, RDP, WinRM"),
    106: dict(name="WIN10",  lan="172.16.3.210",  pub="216.126.0.213",  os="Windows 10 Pro",    svcs="SSH, RDP"),
    107: dict(name="SQL19",  lan="172.16.3.209",  pub="216.126.0.215",  os="MSSQL 2019",        svcs="SSH, RDP, SQL"),
    108: dict(name="SQL22",  lan="172.16.3.208",  pub="216.126.0.216",  os="MSSQL 2022",        svcs="SSH, RDP, SQL"),
    109: dict(name="SQL25",  lan="172.16.3.169",  pub="216.126.0.218",  os="MSSQL 2025",        svcs="SSH, RDP, SQL"),
}

_TICKET_TTL = 3600  # Proxmox tickets are valid for 2h; refresh at 1h


class ProxmoxClient:
    def __init__(self, host: str, user: str, password: str):
        self._host = host.rstrip("/")
        self._user = user
        self._password = password
        self._ticket: str | None = None
        self._csrf: str | None = None
        self._ticket_exp: float = 0.0

    def _session(self) -> requests.Session:
        s = requests.Session()
        s.verify = False
        return s

    def get_ticket(self) -> tuple[str, str]:
        now = time.time()
        if self._ticket and now < self._ticket_exp:
            return self._ticket, self._csrf  # type: ignore[return-value]
        s = self._session()
        resp = s.post(
            f"{self._host}/api2/json/access/ticket",
            data={"username": self._user, "password": self._password},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        self._ticket = data["ticket"]
        self._csrf = data["CSRFPreventionToken"]
        self._ticket_exp = now + _TICKET_TTL
        return self._ticket, self._csrf  # type: ignore[return-value]

    def _get(self, path: str) -> Any:
        ticket, _ = self.get_ticket()
        s = self._session()
        s.cookies.set("PVEAuthCookie", ticket)
        resp = s.get(f"{self._host}{path}", timeout=10)
        resp.raise_for_status()
        return resp.json()["data"]

    def get_vms(self) -> list[dict]:
        try:
            return self._get("/api2/json/nodes/PV1/qemu") or []
        except Exception:
            return []

    def get_vm_status(self, vmid: int) -> dict:
        try:
            return self._get(f"/api2/json/nodes/PV1/qemu/{vmid}/status/current") or {}
        except Exception:
            return {}

    def reboot_vm(self, vmid: int) -> dict:
        ticket, csrf = self.get_ticket()
        s = self._session()
        s.cookies.set("PVEAuthCookie", ticket)
        resp = s.post(
            f"{self._host}/api2/json/nodes/PV1/qemu/{vmid}/status/reboot",
            headers={"CSRFPreventionToken": csrf},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("data", {})
