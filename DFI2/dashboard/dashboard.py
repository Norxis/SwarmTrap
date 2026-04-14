#!/usr/bin/env python3
import os
import uuid
from datetime import datetime, timedelta, timezone

import requests
import streamlit as st
import urllib3
from clickhouse_driver import Client

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CH_HOST = os.environ.get('CH_HOST', 'localhost')
CH_PORT = int(os.environ.get('CH_PORT', '9000'))
BACKEND_API_URL = os.environ.get('BACKEND_API_URL', 'http://127.0.0.1:8010')
BACKEND_API_KEY = os.environ.get('BACKEND_API_KEY')

PVE_HOST = os.environ.get('PVE_HOST', 'https://192.168.0.100:8006')
PVE_USER = os.environ.get('PVE_USER', 'root@pam')
PVE_PASS = os.environ.get('PVE_PASS', 'CHANGE_ME')

# VMID -> (name, lan_ip, public_ip, os, services)
VM_MAP = {
    100: ('UBT20',  '172.16.3.168', '216.126.0.211', 'Ubuntu 20.04',    'SSH, Winlure'),
    101: ('UBT22',  '172.16.3.166', '216.126.0.214', 'Ubuntu 22.04',    'SSH'),
    102: ('UBT24',  '172.16.3.167', '216.126.0.217', 'Ubuntu 24.04',    'SSH'),
    103: ('SRV19',  '172.16.3.213', '216.126.0.210', 'Win Server 2019', 'SSH, RDP, SMB'),
    104: ('SRV22',  '172.16.3.212', '216.126.0.212', 'Win Server 2022', 'SSH, RDP, SMB'),
    105: ('SRV25',  '172.16.3.170', '216.126.0.219', 'Win Server 2025', 'SSH, RDP, WinRM'),
    106: ('WIN10',  '172.16.3.210', '216.126.0.213', 'Windows 10 Pro',  'SSH, RDP'),
    107: ('SQL19',  '172.16.3.209', '216.126.0.215', 'MSSQL 2019',      'SSH, RDP, SQL'),
    108: ('SQL22',  '172.16.3.208', '216.126.0.216', 'MSSQL 2022',      'SSH, RDP, SQL'),
    109: ('SQL25',  '172.16.3.169', '216.126.0.218', 'MSSQL 2025',      'SSH, RDP, SQL'),
}


@st.cache_resource
def get_ch():
    return Client(CH_HOST, port=CH_PORT)


def _analyst_action(ip: str, action_type: str, capture_depth=None, priority=None, expires_hours=None):
    exp_dt = None
    if expires_hours:
        exp_dt = datetime.now(tz=timezone.utc).replace(microsecond=0) + timedelta(hours=expires_hours)

    payload = {
        'ip': ip,
        'capture_depth': int(capture_depth if capture_depth is not None else 1),
        'priority': int(priority if priority is not None else 3),
        'reason': f'analyst_{action_type}',
        'source': 'analyst',
        'actor': 'dashboard',
        'expires_at': exp_dt.isoformat().replace('+00:00', 'Z') if exp_dt else None,
    }

    try:
        headers = {'Idempotency-Key': str(uuid.uuid4())}
        if BACKEND_API_KEY:
            headers['X-API-Key'] = BACKEND_API_KEY
        resp = requests.post(
            f'{BACKEND_API_URL}/watchlist/upsert',
            json=payload,
            headers=headers,
            timeout=10,
        )
    except requests.RequestException as exc:
        st.error(f'Control-plane API unreachable: {exc}')
        return

    if resp.ok:
        body = resp.json() if resp.content else {}
        st.success(f"Action applied: {body.get('message', 'ok')}")
        return

    detail = ''
    try:
        detail = resp.json().get('detail', '')
    except Exception:
        detail = resp.text[:200]
    st.error(f'Action failed ({resp.status_code}): {detail or "unknown error"}')


def render_overview(ch: Client):
    c1, c2, c3, c4 = st.columns(4)
    c1.metric('Total Flows', f"{ch.execute('SELECT count() FROM dfi.flows')[0][0]:,}")
    c2.metric('Flows (1h)', f"{ch.execute('SELECT count() FROM dfi.flows WHERE first_ts >= now() - INTERVAL 1 HOUR')[0][0]:,}")
    c3.metric('Unique Attackers (24h)', f"{ch.execute('SELECT uniq(src_ip) FROM dfi.flows WHERE first_ts >= now() - INTERVAL 24 HOUR')[0][0]:,}")
    c4.metric('Labeled Flows', f"{ch.execute('SELECT count() FROM dfi.labels FINAL')[0][0]:,}")


def render_ip_lookup(ch: Client):
    ip = st.text_input('Attacker IP', placeholder='e.g. 1.2.3.4')
    if not ip:
        return

    # Current group assignment
    group = ch.execute(
        '''SELECT group_id, sub_group_id, confidence, priority, assigned_at
           FROM dfi.group_assignments WHERE attacker_ip=%(ip)s
           ORDER BY assigned_at DESC LIMIT 1''',
        {'ip': ip},
    )
    if group:
        g = group[0]
        c1, c2, c3 = st.columns(3)
        c1.metric('Group', f'{g[0]} / {g[1]}')
        c2.metric('Confidence', f'{g[2]:.2f}')
        c3.metric('Priority', f'P{g[3]}')

    # Labels for this attacker's flows
    labels = ch.execute(
        '''SELECT l.label, count() AS cnt, avg(l.label_confidence) AS avg_conf
           FROM (SELECT * FROM dfi.labels FINAL) AS l
           INNER JOIN dfi.flows f ON f.flow_id = l.flow_id
           WHERE f.src_ip = %(ip)s AND f.first_ts >= now() - INTERVAL 7 DAY
           GROUP BY l.label ORDER BY l.label''',
        {'ip': ip},
    )
    if labels:
        names = {0: 'RECON', 1: 'KNOCK', 2: 'BRUTEFORCE', 3: 'EXPLOIT', 4: 'COMPROMISE'}
        st.subheader('Label Distribution')
        st.dataframe(
            [{'Label': names.get(r[0], str(r[0])), 'Flows': r[1], 'Avg Confidence': f'{r[2]:.2f}'} for r in labels],
            use_container_width=True,
        )

    # Evidence events
    evidence = ch.execute(
        '''SELECT ts, event_type, source_program, event_detail, source_log
           FROM dfi.evidence_events WHERE src_ip = %(ip)s
           ORDER BY ts DESC LIMIT 50''',
        {'ip': ip},
    )
    if evidence:
        st.subheader('Evidence Events')
        st.dataframe(
            [{'Time': r[0], 'Type': r[1], 'Source': r[2], 'Detail': r[3], 'Log': str(r[4])[:200]} for r in evidence],
            use_container_width=True,
        )

    # Group trajectory (last 10 assignments)
    trajectory = ch.execute(
        '''SELECT assigned_at, group_id, sub_group_id, confidence, priority
           FROM dfi.group_assignments WHERE attacker_ip=%(ip)s
           ORDER BY assigned_at DESC LIMIT 10''',
        {'ip': ip},
    )
    if trajectory:
        st.subheader('Group Trajectory')
        st.dataframe(
            [{'Time': r[0], 'Group': r[1], 'SubGroup': r[2], 'Confidence': f'{r[3]:.2f}', 'Priority': f'P{r[4]}'} for r in trajectory],
            use_container_width=True,
        )

    # Movement timeline (fanout hops)
    hops = ch.execute(
        '''SELECT first_ts,target_ip,dst_port,app_proto,vlan_id,pkts_fwd,pkts_rev,conn_state,duration_ms,session_gap_sec
           FROM dfi.fanout_hops WHERE attacker_ip=%(ip)s
           ORDER BY first_ts DESC LIMIT 100''',
        {'ip': ip},
    )
    if hops:
        st.subheader('Movement Timeline')
        st.dataframe(
            [
                {
                    'Time': r[0],
                    'Target': str(r[1]),
                    'Port': r[2],
                    'Proto': r[3],
                    'VLAN': r[4],
                    'Pkts Fwd': r[5],
                    'Pkts Rev': r[6],
                    'State': r[7],
                    'Duration': r[8],
                    'Gap(s)': r[9],
                }
                for r in hops
            ],
            use_container_width=True,
        )

    c1, c2, c3 = st.columns(3)
    if c1.button('Promote to D3'):
        _analyst_action(ip, 'promote', capture_depth=3, priority=1, expires_hours=72)
    if c2.button('Push to Block'):
        _analyst_action(ip, 'block', capture_depth=0, priority=1, expires_hours=168)
    if c3.button('Watch 72h'):
        _analyst_action(ip, 'watch', capture_depth=2, priority=2, expires_hours=72)


def render_top_attackers(ch: Client):
    rows = ch.execute(
        '''SELECT src_ip, count() AS flows, uniq(dst_port) AS ports, uniq(dst_ip) AS targets
           FROM dfi.flows WHERE first_ts >= now() - INTERVAL 24 HOUR
           GROUP BY src_ip ORDER BY flows DESC LIMIT 100'''
    )
    st.dataframe([{'IP': str(r[0]), 'Flows': r[1], 'Ports': r[2], 'Targets': r[3]} for r in rows], use_container_width=True)


def render_label_distribution(ch: Client):
    rows = ch.execute('SELECT label, count() FROM dfi.labels FINAL GROUP BY label ORDER BY label')
    names = {0: 'RECON', 1: 'KNOCK', 2: 'BRUTEFORCE', 3: 'EXPLOIT', 4: 'COMPROMISE'}
    st.dataframe([{'Label': names.get(r[0], r[0]), 'Count': r[1]} for r in rows], use_container_width=True)


def render_ingest_monitor(ch: Client):
    import pandas as pd
    rows = ch.execute(
        '''SELECT toStartOfMinute(first_ts) AS minute, count() AS flows_per_min,
                  round(count()/60, 0) AS flows_per_sec
           FROM dfi.flows
           WHERE first_ts >= now() - INTERVAL 1 HOUR
           GROUP BY minute ORDER BY minute LIMIT 60'''
    )
    if rows:
        df = pd.DataFrame(rows, columns=['Minute', 'Flows/min', 'Flows/sec'])
        df = df.set_index('Minute')
        st.line_chart(df['Flows/sec'])
        st.dataframe(df.reset_index().sort_values('Minute', ascending=False), use_container_width=True)
    else:
        st.info('No flow data in the last hour.')


def render_storage_stats(ch: Client):
    rows = ch.execute(
        '''SELECT table, formatReadableSize(sum(data_uncompressed_bytes)) AS raw,
                  formatReadableSize(sum(data_compressed_bytes)) AS compressed,
                  round(sum(data_uncompressed_bytes)/greatest(sum(data_compressed_bytes),1),1) AS ratio,
                  sum(rows) AS rows
           FROM system.parts WHERE database='dfi' AND active
           GROUP BY table ORDER BY sum(data_uncompressed_bytes) DESC'''
    )
    st.dataframe([{'Table': r[0], 'Raw': r[1], 'Compressed': r[2], 'Ratio': r[3], 'Rows': r[4]} for r in rows], use_container_width=True)


@st.cache_data(ttl=3600)
def get_pve_ticket():
    resp = requests.post(
        f'{PVE_HOST}/api2/json/access/ticket',
        data={'username': PVE_USER, 'password': PVE_PASS},
        verify=False,
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()['data']
    return data['ticket'], data['CSRFPreventionToken']


def get_vm_list(ticket):
    resp = requests.get(
        f'{PVE_HOST}/api2/json/nodes/PV1/qemu',
        cookies={'PVEAuthCookie': ticket},
        verify=False,
        timeout=10,
    )
    resp.raise_for_status()
    return {vm['vmid']: vm for vm in resp.json()['data']}


def _fmt_uptime(seconds):
    if not seconds:
        return '-'
    d, rem = divmod(int(seconds), 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    parts = []
    if d:
        parts.append(f'{d}d')
    if h:
        parts.append(f'{h}h')
    parts.append(f'{m}m')
    return ' '.join(parts)


def _fmt_bytes(b):
    if not b:
        return '-'
    gb = b / (1024 ** 3)
    if gb >= 1:
        return f'{gb:.1f} GB'
    return f'{b / (1024 ** 2):.0f} MB'


def render_vm_status(ch: Client):
    # Fetch Proxmox data
    try:
        ticket, _ = get_pve_ticket()
        pve_vms = get_vm_list(ticket)
        pve_ok = True
    except Exception as e:
        st.warning(f'Proxmox API unavailable: {e}')
        pve_vms = {}
        pve_ok = False

    # Fetch attack metrics per public IP from ClickHouse
    public_ips = [info[2] for info in VM_MAP.values()]
    try:
        traffic = ch.execute(
            '''SELECT dst_ip, count() AS flows, uniq(src_ip) AS attackers
               FROM dfi.flows
               WHERE first_ts >= now() - INTERVAL 24 HOUR
                 AND dst_ip IN %(ips)s
               GROUP BY dst_ip''',
            {'ips': public_ips},
        )
        traffic_map = {str(r[0]): (r[1], r[2]) for r in traffic}
    except Exception:
        traffic_map = {}

    # Summary metrics
    running = sum(1 for vmid in VM_MAP if pve_vms.get(vmid, {}).get('status') == 'running')
    total_flows = sum(v[0] for v in traffic_map.values())
    c1, c2 = st.columns(2)
    c1.metric('VMs Running', f'{running} / {len(VM_MAP)}')
    c2.metric('Total Flows (24h)', f'{total_flows:,}')

    # Build table rows
    rows = []
    for vmid in sorted(VM_MAP.keys()):
        name, lan_ip, pub_ip, os_name, services = VM_MAP[vmid]
        pve = pve_vms.get(vmid, {})
        status = pve.get('status', 'unknown')
        status_icon = '\U0001f7e2' if status == 'running' else '\U0001f534' if status == 'stopped' else '\u26aa'
        cpu_pct = f"{pve.get('cpu', 0) * 100:.1f}%" if pve_ok and 'cpu' in pve else '-'
        mem_used = pve.get('mem', 0)
        mem_max = pve.get('maxmem', 0)
        ram_str = f'{_fmt_bytes(mem_used)} / {_fmt_bytes(mem_max)}' if pve_ok and mem_max else '-'
        uptime = _fmt_uptime(pve.get('uptime', 0)) if pve_ok else '-'
        flows_24h, attackers_24h = traffic_map.get(pub_ip, (0, 0))

        rows.append({
            'VM': name,
            'Status': f'{status_icon} {status}',
            'OS': os_name,
            'CPU %': cpu_pct,
            'RAM': ram_str,
            'LAN IP': lan_ip,
            'Public IP': pub_ip,
            'Flows (24h)': flows_24h,
            'Attackers (24h)': attackers_24h,
            'Services': services,
            'Uptime': uptime,
        })

    st.dataframe(rows, use_container_width=True, hide_index=True)


def render_evidence(ch: Client):
    # Summary metrics
    c1, c2, c3 = st.columns(3)
    c1.metric('Total Evidence Events', f"{ch.execute('SELECT count() FROM dfi.evidence_events')[0][0]:,}")
    c2.metric('Events (1h)', f"{ch.execute('SELECT count() FROM dfi.evidence_events WHERE ts >= now() - INTERVAL 1 HOUR')[0][0]:,}")
    c3.metric('Unique Attackers (24h)', f"{ch.execute('SELECT uniq(src_ip) FROM dfi.evidence_events WHERE ts >= now() - INTERVAL 24 HOUR')[0][0]:,}")

    # Event type breakdown
    st.subheader('Event Types (24h)')
    types = ch.execute(
        '''SELECT event_type, count() AS cnt, uniq(src_ip) AS attackers
           FROM dfi.evidence_events
           WHERE ts >= now() - INTERVAL 24 HOUR
           GROUP BY event_type ORDER BY cnt DESC'''
    )
    if types:
        st.dataframe(
            [{'Event Type': r[0], 'Count': r[1], 'Unique Attackers': r[2]} for r in types],
            use_container_width=True, hide_index=True,
        )

    # Top attacker IPs by evidence volume
    st.subheader('Top Attackers by Evidence (24h)')
    top = ch.execute(
        '''SELECT src_ip, count() AS events,
                  groupUniqArray(10)(event_type) AS types,
                  min(ts) AS first_seen, max(ts) AS last_seen
           FROM dfi.evidence_events
           WHERE ts >= now() - INTERVAL 24 HOUR
           GROUP BY src_ip ORDER BY events DESC LIMIT 50'''
    )
    if top:
        st.dataframe(
            [{'Attacker': str(r[0]), 'Events': r[1], 'Types': ', '.join(r[2]), 'First': r[3], 'Last': r[4]} for r in top],
            use_container_width=True, hide_index=True,
        )

    # Recent events stream
    st.subheader('Recent Evidence Events')
    recent = ch.execute(
        '''SELECT ts, src_ip, target_ip, event_type, source_program, event_detail,
                  source_log
           FROM dfi.evidence_events
           ORDER BY ts DESC LIMIT 100'''
    )
    if recent:
        st.dataframe(
            [
                {
                    'Time': r[0],
                    'Attacker': str(r[1]),
                    'Target': str(r[2]),
                    'Type': r[3],
                    'Source': r[4],
                    'Detail': r[5],
                    'Log': str(r[6])[:200],
                }
                for r in recent
            ],
            use_container_width=True, hide_index=True,
        )
    else:
        st.info('No evidence events yet.')


def main():
    st.set_page_config(page_title='DFI2 Dashboard', layout='wide')
    st.title('DFI2 - Attacker Intelligence Dashboard')
    ch = get_ch()

    page = st.sidebar.radio('View', ['Overview', 'VM Status', 'Evidence', 'IP Lookup', 'Top Attackers', 'Label Distribution', 'Ingest Monitor', 'Storage Stats'])
    if page == 'Overview':
        render_overview(ch)
    elif page == 'VM Status':
        render_vm_status(ch)
    elif page == 'Evidence':
        render_evidence(ch)
    elif page == 'IP Lookup':
        render_ip_lookup(ch)
    elif page == 'Top Attackers':
        render_top_attackers(ch)
    elif page == 'Label Distribution':
        render_label_distribution(ch)
    elif page == 'Ingest Monitor':
        render_ingest_monitor(ch)
    elif page == 'Storage Stats':
        render_storage_stats(ch)


if __name__ == '__main__':
    main()
