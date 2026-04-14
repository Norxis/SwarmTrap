#!/usr/bin/env python3
# DO NOT FORGET OFFLOAD! — GRO/GSO/TSO/LRO must be disabled on the capture
# interface before Hunter starts, otherwise AF_PACKET sees coalesced jumbo
# frames instead of real packets. This script handles it automatically.
import os
import pathlib
import sys

import paramiko

def _req(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f'missing required env var: {name}')
    return v


PV1_HOST = os.environ.get('PV1_HOST', '192.168.0.100')
PV1_PORT = int(os.environ.get('PV1_PORT', '22'))
PV1_USER = os.environ.get('PV1_USER', 'root')
PV1_PASS = _req('PV1_PASS')

# DO NOT FORGET OFFLOAD! — capture interface must have hardware offloads disabled
CAPTURE_IFACE = os.environ.get('CAPTURE_IFACE', 'v172')

NIC_OFFLOAD_SERVICE = """\
[Unit]
Description=Disable NIC offloads on capture interface — DO NOT FORGET OFFLOAD!
After=network-online.target
Before=dfi-hunter2.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ethtool -K {iface} gro off gso off tso off lro off sg off tx off rx off

[Install]
WantedBy=multi-user.target
""".format(iface=CAPTURE_IFACE)

BASE_DIR = pathlib.Path(__file__).resolve().parents[1]
SCHEMA_DIR = BASE_DIR / 'schema'
REMOTE_SCHEMA_DIR = '/tmp/dfi2_schema'

INSTALL_CMDS = [
    'apt-get install -y apt-transport-https ca-certificates curl gnupg',
    "curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key | gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg",
    "echo \"deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg] https://packages.clickhouse.com/deb stable main\" > /etc/apt/sources.list.d/clickhouse.list",
    'apt-get update',
    'apt-get install -y clickhouse-server clickhouse-client python3-pip',
    'pip3 install --break-system-packages -q clickhouse-driver paramiko || pip3 install -q clickhouse-driver paramiko',
]

DFI_XML = """<clickhouse>
    <max_server_memory_usage_to_ram_ratio>0.6</max_server_memory_usage_to_ram_ratio>
    <merge_tree>
        <max_bytes_to_merge_at_max_space_in_pool>10737418240</max_bytes_to_merge_at_max_space_in_pool>
    </merge_tree>
    <listen_host>0.0.0.0</listen_host>
</clickhouse>
"""


def run(ssh: paramiko.SSHClient, cmd: str) -> None:
    stdin, stdout, stderr = ssh.exec_command(cmd)
    code = stdout.channel.recv_exit_status()
    out = stdout.read().decode()
    err = stderr.read().decode()
    if code != 0:
        raise RuntimeError(f'cmd failed ({code}): {cmd}\nstdout={out}\nstderr={err}')


def sftp_put(ssh: paramiko.SSHClient, src: pathlib.Path, dst: str) -> None:
    sftp = ssh.open_sftp()
    try:
        sftp.put(str(src), dst)
    finally:
        sftp.close()


def main() -> int:
    for f in ('01_tables.sql', '02_behavioral.sql', '03_buffers.sql', '04_views.sql', '05_watchlist.sql'):
        if not (SCHEMA_DIR / f).exists():
            raise FileNotFoundError(f'Missing schema file: {SCHEMA_DIR / f}')

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(PV1_HOST, port=PV1_PORT, username=PV1_USER, password=PV1_PASS, timeout=20)

    try:
        for cmd in INSTALL_CMDS:
            run(ssh, cmd)

        run(ssh, f"mkdir -p {REMOTE_SCHEMA_DIR}")
        for fname in ('01_tables.sql', '02_behavioral.sql', '03_buffers.sql', '04_views.sql', '05_watchlist.sql'):
            sftp_put(ssh, SCHEMA_DIR / fname, f'{REMOTE_SCHEMA_DIR}/{fname}')

        run(ssh, "cat > /etc/clickhouse-server/config.d/dfi.xml <<'EOF'\n" + DFI_XML + 'EOF')
        run(ssh, 'systemctl enable --now clickhouse-server')
        run(ssh, 'clickhouse-client --query "CREATE DATABASE IF NOT EXISTS dfi"')

        for fname in ('01_tables.sql', '02_behavioral.sql', '03_buffers.sql', '04_views.sql'):
            run(ssh, f'clickhouse-client --multiquery < {REMOTE_SCHEMA_DIR}/{fname}')

        run(ssh, "sqlite3 /opt/dfi_edge/watchlist.db < /tmp/dfi2_schema/05_watchlist.sql || true")
        run(ssh, "(crontab -l 2>/dev/null; echo '*/5 * * * * /usr/bin/python3 /opt/dfi2/sync/pull_aio.py'; echo '*/10 * * * * /usr/bin/python3 /opt/dfi2/sync/push_watchlist.py') | awk '!seen[$0]++' | crontab -")

        # DO NOT FORGET OFFLOAD! — disable NIC offloads on capture interface
        run(ssh, f'ethtool -K {CAPTURE_IFACE} gro off gso off tso off lro off sg off tx off rx off || true')
        import tempfile
        with tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8') as fp:
            fp.write(NIC_OFFLOAD_SERVICE)
            tmp = fp.name
        sftp_put(ssh, pathlib.Path(tmp), '/tmp/dfi-nic-offload.service')
        run(ssh, 'cp /tmp/dfi-nic-offload.service /etc/systemd/system/dfi-nic-offload.service')
        run(ssh, 'systemctl daemon-reload && systemctl enable dfi-nic-offload')
    finally:
        ssh.close()

    print('PV1 ClickHouse deployment complete (offloads disabled)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
