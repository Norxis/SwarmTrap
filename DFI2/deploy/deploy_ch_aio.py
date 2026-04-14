#!/usr/bin/env python3
# DO NOT FORGET OFFLOAD! — GRO/GSO/TSO/LRO must be disabled on the capture
# interface before Hunter starts, otherwise AF_PACKET sees coalesced jumbo
# frames instead of real packets. This script handles it automatically.
import os
import pathlib
import re
import tempfile

import paramiko

def _req(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f'missing required env var: {name}')
    return v


AIO_HOST = os.environ.get('AIO_HOST', '192.168.0.113')
AIO_PORT = int(os.environ.get('AIO_PORT', '2222'))
AIO_USER = os.environ.get('AIO_USER', 'colo8gent')
AIO_PASS = _req('AIO_PASS')

# DO NOT FORGET OFFLOAD! — capture interface must have hardware offloads disabled
CAPTURE_IFACE = os.environ.get('CAPTURE_IFACE', 'ens192')

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
    'apt-get install -y clickhouse-server clickhouse-client python3-pip sqlite3',
    'pip3 install --break-system-packages -q clickhouse-driver paramiko || pip3 install -q clickhouse-driver paramiko',
]

DFI_XML = """<clickhouse>
    <max_server_memory_usage_to_ram_ratio>0.25</max_server_memory_usage_to_ram_ratio>
    <merge_tree>
        <max_bytes_to_merge_at_max_space_in_pool>5368709120</max_bytes_to_merge_at_max_space_in_pool>
    </merge_tree>
    <listen_host>0.0.0.0</listen_host>
</clickhouse>
"""


def rewrite_ttl_48h(sql: str) -> str:
    return re.sub(r'INTERVAL\s+\d+\s+DAY', 'INTERVAL 2 DAY', sql)


def run(ssh: paramiko.SSHClient, cmd: str, sudo: bool = False) -> None:
    final_cmd = cmd
    if sudo:
        final_cmd = f"echo '{AIO_PASS}' | sudo -S bash -lc \"{cmd.replace('\\"', '\\\\"')}\""
    stdin, stdout, stderr = ssh.exec_command(final_cmd)
    code = stdout.channel.recv_exit_status()
    out = stdout.read().decode()
    err = stderr.read().decode()
    if code != 0:
        raise RuntimeError(f'cmd failed ({code}): {cmd}\nstdout={out}\nstderr={err}')


def sftp_put_text(ssh: paramiko.SSHClient, text: str, dst: str) -> None:
    with tempfile.NamedTemporaryFile('w', delete=False, encoding='utf-8') as fp:
        fp.write(text)
        src = fp.name
    sftp = ssh.open_sftp()
    try:
        sftp.put(src, dst)
    finally:
        sftp.close()


def sftp_put_file(ssh: paramiko.SSHClient, src: pathlib.Path, dst: str) -> None:
    sftp = ssh.open_sftp()
    try:
        sftp.put(str(src), dst)
    finally:
        sftp.close()


def main() -> int:
    for f in ('01_tables.sql', '02_behavioral.sql', '03_buffers.sql', '05_watchlist.sql'):
        if not (SCHEMA_DIR / f).exists():
            raise FileNotFoundError(f'Missing schema file: {SCHEMA_DIR / f}')

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(AIO_HOST, port=AIO_PORT, username=AIO_USER, password=AIO_PASS, timeout=20)

    try:
        for cmd in INSTALL_CMDS:
            run(ssh, cmd, sudo=True)

        run(ssh, f'mkdir -p {REMOTE_SCHEMA_DIR}', sudo=True)

        raw_01 = (SCHEMA_DIR / '01_tables.sql').read_text(encoding='utf-8')
        raw_02 = (SCHEMA_DIR / '02_behavioral.sql').read_text(encoding='utf-8')
        aio_01 = rewrite_ttl_48h(raw_01)
        aio_02 = rewrite_ttl_48h(raw_02)

        sftp_put_text(ssh, aio_01, f'{REMOTE_SCHEMA_DIR}/01_tables.sql')
        sftp_put_text(ssh, aio_02, f'{REMOTE_SCHEMA_DIR}/02_behavioral.sql')
        sftp_put_file(ssh, SCHEMA_DIR / '03_buffers.sql', f'{REMOTE_SCHEMA_DIR}/03_buffers.sql')
        sftp_put_file(ssh, SCHEMA_DIR / '05_watchlist.sql', f'{REMOTE_SCHEMA_DIR}/05_watchlist.sql')

        run(ssh, "cat > /etc/clickhouse-server/config.d/dfi.xml <<'EOF'\n" + DFI_XML + 'EOF', sudo=True)
        run(ssh, 'systemctl enable --now clickhouse-server', sudo=True)
        run(ssh, 'clickhouse-client --query "CREATE DATABASE IF NOT EXISTS dfi"', sudo=True)

        for fname in ('01_tables.sql', '02_behavioral.sql', '03_buffers.sql'):
            run(ssh, f'clickhouse-client --multiquery < {REMOTE_SCHEMA_DIR}/{fname}', sudo=True)

        run(ssh, f'sqlite3 /opt/dfi-hunter/watchlist.db < {REMOTE_SCHEMA_DIR}/05_watchlist.sql', sudo=True)

        # DO NOT FORGET OFFLOAD! — disable NIC offloads on capture interface
        run(ssh, f'ethtool -K {CAPTURE_IFACE} gro off gso off tso off lro off sg off tx off rx off || true', sudo=True)
        sftp_put_text(ssh, NIC_OFFLOAD_SERVICE, '/tmp/dfi-nic-offload.service')
        run(ssh, 'cp /tmp/dfi-nic-offload.service /etc/systemd/system/dfi-nic-offload.service', sudo=True)
        run(ssh, 'systemctl daemon-reload && systemctl enable dfi-nic-offload', sudo=True)
    finally:
        ssh.close()

    print('AIO ClickHouse deployment complete (offloads disabled)')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
