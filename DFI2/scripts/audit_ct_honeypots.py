#!/usr/bin/env python3
"""
Audit and self-heal CT110 + CT127-162 honeypot containers on PV1.
Checks: winlure process, dfi-trap, dfi-watchlist-pusher, dfi-sensor-agent.
Fixes: restart dead services, restart dead winlure process.
Run via cron on PV1 every 5 minutes.
"""
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
log = logging.getLogger('ct_audit')

# CT110 = base honeypot; CT127-162 = farm (CT111-126 are KVM VMs, not LXC)
CTS = [110] + list(range(127, 163))
AIO_IP = '172.16.3.2'         # PV1 v172 bridge — reachable from containers (VLAN 208)
AIO_MGMT_IP = '127.0.0.1'    # localhost — script runs on PV1
AIO_API_PORT = 81
AIO_SYSLOG_PORT = 514

SERVICES = ['dfi-trap', 'dfi-sensor-agent']


def pct(ct, cmd, capture=True):
    try:
        r = subprocess.run(
            ['/usr/sbin/pct', 'exec', str(ct), '--'] + (['bash', '-c', cmd] if isinstance(cmd, str) else cmd),
            capture_output=capture, text=True, timeout=30
        )
        return r.stdout.strip() if capture else r.returncode == 0
    except subprocess.TimeoutExpired:
        log.error('CT%d: pct exec timed out', ct)
        return '' if capture else False


def aio_reachable_from_host():
    """Pre-check AIO API reachability from PV1 before per-container probes."""
    try:
        r = subprocess.run(['nc', '-z', '-w3', AIO_MGMT_IP, str(AIO_API_PORT)],
                           capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception:
        return False


def restart_winlure(ct):
    ip = pct(ct, "ip addr show eth0 | awk '/inet.*\\/32/{print $2}' | cut -d/ -f1")
    if not ip:
        ip = pct(ct, "ip addr show eth0 | awk '/inet /{print $2}' | head -1 | cut -d/ -f1")

    persona = pct(ct, f"""
        f=/opt/winlure/winlure/config/personas/persona_{ct}.yaml
        if [ -f "$f" ]; then echo "$f"; exit; fi
        for y in /opt/winlure/winlure/config/personas/*.yaml; do
            base=$(basename $y)
            [ "$base" = "meridian_fs.yaml" ] && continue
            [ "$base" = "win2022_dc.yaml" ] && continue
            echo "$y"; exit
        done
        echo /opt/winlure/winlure/config/personas/meridian_fs.yaml
    """)

    if not ip or not persona:
        log.error('CT%d: winlure dead, could not determine ip/persona', ct)
        return

    pct(ct, (
        f"cd /opt/winlure && nohup /opt/winlure/venv/bin/python3 -u -m winlure.winlure "
        f"--config {persona} --state-dir /opt/winlure/state "
        f"--interface eth0 --ip {ip} --log-level WARNING "
        f">> /opt/winlure/winlure.log 2>&1 &"
    ), capture=False)
    log.warning('CT%d: winlure restarted (ip=%s persona=%s)', ct, ip, persona)


def check_and_fix(ct, skip_aio_check=False):
    issues = []

    if not skip_aio_check:
        result = pct(ct, (
            f"nc -z -w3 {AIO_IP} {AIO_API_PORT} 2>/dev/null && echo api_ok || echo api_fail; "
            f"nc -z -w3 {AIO_IP} {AIO_SYSLOG_PORT} 2>/dev/null && echo syslog_ok || echo syslog_fail"
        ))
        for tag, label, port in (
            ('api_ok', 'API', AIO_API_PORT),
            ('syslog_ok', 'syslog', AIO_SYSLOG_PORT),
        ):
            if tag not in result:
                issues.append(f'aio_{label.lower()}_unreachable')
                log.error('CT%d: cannot reach AIO %s:%d (%s)', ct, AIO_IP, port, label)

    if not pct(ct, "pgrep -f 'winlure.winlure' > /dev/null 2>&1", capture=False):
        issues.append('winlure_dead')
        restart_winlure(ct)

    svc_states = pct(ct, f"systemctl is-active {' '.join(SERVICES)} 2>/dev/null").splitlines()
    for svc, state in zip(SERVICES, svc_states):
        if state not in ('active', 'activating'):
            issues.append(f'{svc}_dead')
            pct(ct, f'systemctl restart {svc}', capture=False)
            log.warning('CT%d: %s restarted (was: %s)', ct, svc, state)

    if not issues:
        log.debug('CT%d: OK', ct)
    return issues


def main():
    aio_up = aio_reachable_from_host()
    if not aio_up:
        log.error('AIO %s:%d unreachable from PV1 — skipping per-container connectivity checks',
                  AIO_IP, AIO_API_PORT)

    total_issues = 0
    with ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(check_and_fix, ct, skip_aio_check=not aio_up): ct for ct in CTS}
        for future in as_completed(futures):
            ct = futures[future]
            try:
                issues = future.result()
                total_issues += len(issues)
            except Exception as e:
                log.error('CT%d: exception — %s', ct, e)
                total_issues += 1

    if total_issues:
        log.info('Audit complete: %d issues fixed across %d containers', total_issues, len(CTS))
    else:
        log.info('Audit complete: all %d containers healthy', len(CTS))


if __name__ == '__main__':
    main()
