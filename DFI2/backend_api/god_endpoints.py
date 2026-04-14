"""GOD Dashboard API endpoints.

15 endpoints for the GOD-first SOC dashboard, reading from:
  dfi.ip_profile, dfi.ip_score_log, dfi.evidence_events,
  dfi.ip_capture_d2, dfi.ip_service_labels, dfi.ip_capture_budget

All CH queries use a single lock acquisition per endpoint to avoid concurrent query errors.
"""

import logging
import time
from typing import Optional

from fastapi import FastAPI, Query, HTTPException
from pydantic import BaseModel

log = logging.getLogger("dfi2.god")

VERDICT_NAMES = {"NONE": "None", "CAPTURE": "Capture", "DROP": "Drop"}
CLASS_NAMES = {0: "RECON", 1: "KNOCK", 2: "BRUTE", 3: "EXPLOIT", 4: "CLEAN"}
SERVICE_NAMES = {1: "SSH", 2: "HTTP", 3: "RDP", 4: "SQL", 5: "SMB"}
SERVICE_CLASSES = {
    1: {0: "SCAN", 1: "PROBE", 2: "BRUTE", 3: "CREDENTIAL", 4: "COMMAND", 5: "PERSIST"},
    2: {0: "SCAN", 1: "CRAWL", 2: "FUZZ", 3: "EXPLOIT", 4: "WEBSHELL", 5: "EXFIL"},
    3: {0: "SCAN", 1: "PROBE", 2: "BRUTE", 3: "CREDENTIAL", 4: "COMMAND", 5: "PERSIST"},
    4: {0: "SCAN", 1: "PROBE", 2: "BRUTE", 3: "INJECTION", 4: "EXFIL"},
    5: {0: "SCAN", 1: "NEGOTIATE", 2: "ENUM", 3: "BRUTE", 4: "EXPLOIT", 5: "LATERAL"},
}

_overview_cache: dict = {}
_overview_cache_ts: float = 0.0


class AllowlistRequest(BaseModel):
    ip: str


def register_god_routes(app: FastAPI, ch_adapter) -> None:

    lock = ch_adapter._lock
    client = ch_adapter.client

    # -----------------------------------------------------------------------
    # 1. GET /data/god/health
    # -----------------------------------------------------------------------
    @app.get("/data/god/health")
    def god_health():
        try:
            with lock:
                # Stage 1: GOD1 scores (ip_score_log)
                sr = client.execute("""
                    SELECT countIf(ingested_at >= now() - INTERVAL 5 MINUTE),
                           countIf(ingested_at >= now() - INTERVAL 30 MINUTE),
                           toUnixTimestamp(max(ingested_at))
                    FROM dfi.ip_score_log WHERE ingested_at >= now() - INTERVAL 1 HOUR
                """)
                # Stage 2: Brain judgments (ip_profile updated recently)
                br = client.execute("""
                    SELECT count(), toUnixTimestamp(max(updated_at))
                    FROM dfi.ip_profile FINAL
                    WHERE updated_at >= now() - INTERVAL 10 MINUTE
                """)
                # Stage 3: GOD2 verdicts (DROP entries in ip_profile)
                vr = client.execute("""
                    SELECT count(), toUnixTimestamp(max(updated_at))
                    FROM dfi.ip_profile FINAL
                    WHERE verdict = 'DROP'
                      AND updated_at >= now() - INTERVAL 10 MINUTE
                """)
                # Stage 4: ip_profile read latency check
                nr = client.execute("""
                    SELECT count(), toUnixTimestamp(max(updated_at))
                    FROM dfi.ip_profile FINAL
                    WHERE updated_at >= now() - INTERVAL 10 MINUTE
                      AND verdict != 'NONE'
                """)

            s5 = int(sr[0][0]) if sr else 0
            s30 = int(sr[0][1]) if sr else 0
            lst = int(sr[0][2]) if sr and sr[0][2] else 0
            brn = int(br[0][0]) if br else 0
            bts = int(br[0][1]) if br and br[0][1] else 0
            vrc = int(vr[0][0]) if vr else 0
            vts = int(vr[0][1]) if vr and vr[0][1] else 0
            nrc = int(nr[0][0]) if nr else 0
            nts = int(nr[0][1]) if nr and nr[0][1] else 0

            # Overall status: healthy if GOD1 scoring + brain both active
            if s5 > 0 and brn > 0:
                status = "healthy"
            elif s30 > 0:
                status = "stale"
            else:
                status = "dead"

            return {
                "pipeline_status": status,
                "stages": {
                    "god1_scores": {"count_5min": s5, "count_30min": s30, "last_ts": lst,
                                    "ok": s5 > 0},
                    "brain_judgments": {"count_10min": brn, "last_ts": bts,
                                       "ok": brn > 0},
                    "god2_verdicts": {"count_10min": vrc, "last_ts": vts,
                                     "ok": vrc > 0},
                    "profile_active": {"count_10min": nrc, "last_ts": nts,
                                      "ok": nrc > 0},
                },
            }
        except Exception as exc:
            log.error("god health: %s", exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 2. GET /data/god/overview
    # -----------------------------------------------------------------------
    @app.get("/data/god/overview")
    def god_overview():
        global _overview_cache, _overview_cache_ts
        now = time.time()
        if _overview_cache and (now - _overview_cache_ts) < 15.0:
            return _overview_cache

        try:
            with lock:
                # KPI tiles
                rows = client.execute("""
                    SELECT
                        count() AS total_ips,
                        countIf(verdict = 'DROP') AS drop_count,
                        countIf(verdict = 'CAPTURE') AS capture_count,
                        countIf(evidence_count > 0) AS evidence_count,
                        countIf(verdict_group LIKE 'DIS_%%') AS discrepancy_count,
                        countIf(verdict = 'DROP' AND updated_at >= now() - INTERVAL 1 HOUR) AS recent_drops
                    FROM dfi.ip_profile FINAL
                """)
                # Score rate
                rate_rows = client.execute("""
                    SELECT count() FROM dfi.ip_score_log
                    WHERE ingested_at >= now() - INTERVAL 5 MINUTE
                """)
                # Verdict group breakdown
                arch_rows = client.execute("""
                    SELECT verdict_group, count() AS cnt
                    FROM dfi.ip_profile FINAL
                    WHERE verdict != 'NONE'
                    GROUP BY verdict_group
                    ORDER BY cnt DESC
                    LIMIT 20
                """)
                # Verdict breakdown
                group_rows = client.execute("""
                    SELECT verdict, count() AS cnt
                    FROM dfi.ip_profile FINAL
                    GROUP BY verdict
                """)
                # Service summary: join ip_service_labels with ip_profile
                svc_rows = client.execute("""
                    SELECT s.service_id,
                           count() AS ip_count,
                           countIf(r.evidence_count > 0) AS with_evidence,
                           sum(s.event_count) AS total_events
                    FROM dfi.ip_service_labels AS s FINAL
                    INNER JOIN dfi.ip_profile AS r FINAL ON s.src_ip = r.src_ip
                    GROUP BY s.service_id
                    ORDER BY s.service_id
                """)

            r = rows[0] if rows else (0, 0, 0, 0, 0, 0)
            result = {
                "total_ips": int(r[0]),
                "drop_count": int(r[1]),
                "capture_count": int(r[2]),
                "evidence_count": int(r[3]),
                "discrepancy_count": int(r[4]),
                "recent_drops": int(r[5]),
                "score_log_5min": int(rate_rows[0][0]) if rate_rows else 0,
                "verdict_group_breakdown": [
                    {"verdict_group": str(a[0]), "count": int(a[1])}
                    for a in arch_rows
                ],
                "verdict_breakdown": [
                    {"verdict": str(g[0]), "name": VERDICT_NAMES.get(str(g[0]), "?"),
                     "count": int(g[1])}
                    for g in group_rows
                ],
                "service_summary": [
                    {"service_id": int(sv[0]),
                     "service_name": SERVICE_NAMES.get(int(sv[0]), f"SVC_{sv[0]}"),
                     "ip_count": int(sv[1]),
                     "with_evidence": int(sv[2]),
                     "total_events": int(sv[3])}
                    for sv in svc_rows
                ],
            }
            _overview_cache = result
            _overview_cache_ts = now
            return result
        except Exception as exc:
            log.error("god overview: %s", exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 3. GET /data/god/catches
    # -----------------------------------------------------------------------
    @app.get("/data/god/catches")
    def god_catches(
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ):
        try:
            with lock:
                cnt = client.execute("""
                    SELECT count() FROM dfi.ip_profile FINAL
                    WHERE verdict_group LIKE 'DIS_FN_%%'
                """)
                rows = client.execute("""
                    SELECT toString(src_ip), verdict, verdict_group,
                           evidence_count, best_xgb_class, xgb_clean_ratio,
                           total_flows, unique_ports, unique_dsts,
                           services, service_classes,
                           toUnixTimestamp(first_seen), toUnixTimestamp(last_seen),
                           toUnixTimestamp(updated_at)
                    FROM dfi.ip_profile FINAL
                    WHERE verdict_group LIKE 'DIS_FN_%%'
                    ORDER BY updated_at DESC
                    LIMIT %(limit)s OFFSET %(offset)s
                """, {"limit": limit, "offset": offset})

                # Collect IPs for enrichment
                ips = [r[0] for r in rows]
                evidence_map: dict[str, list] = {}
                service_map: dict[str, list] = {}
                if ips:
                    ip_list = ", ".join(f"toIPv4('{ip}')" for ip in ips)
                    ev_rows = client.execute(f"""
                        SELECT toString(src_ip), event_type, source_program,
                               toUnixTimestamp(ts)
                        FROM dfi.evidence_events
                        WHERE src_ip IN ({ip_list})
                        ORDER BY ts DESC
                        LIMIT 500
                    """)
                    for ev in ev_rows:
                        evidence_map.setdefault(str(ev[0]), []).append({
                            "event_type": str(ev[1]),
                            "source_program": str(ev[2]),
                            "ts": int(ev[3]),
                        })
                    sl_rows = client.execute(f"""
                        SELECT toString(src_ip), service_id, service_class,
                               label_confidence, event_count
                        FROM dfi.ip_service_labels FINAL
                        WHERE src_ip IN ({ip_list})
                    """)
                    for sl in sl_rows:
                        sid = int(sl[1])
                        scl = int(sl[2])
                        service_map.setdefault(str(sl[0]), []).append({
                            "service_id": sid,
                            "service_name": SERVICE_NAMES.get(sid, f"SVC_{sid}"),
                            "service_class": scl,
                            "class_name": SERVICE_CLASSES.get(sid, {}).get(scl, f"CLASS_{scl}"),
                            "label_confidence": round(float(sl[3]), 3),
                            "event_count": int(sl[4]),
                        })

            return {
                "total": int(cnt[0][0]) if cnt else 0,
                "items": [{
                    "src_ip": r[0],
                    "verdict": str(r[1]),
                    "verdict_name": VERDICT_NAMES.get(str(r[1]), "?"),
                    "verdict_group": str(r[2]),
                    "has_evidence": int(r[3]) > 0,
                    "evidence_count": int(r[3]),
                    "best_xgb_class": int(r[4]),
                    "xgb_class_name": CLASS_NAMES.get(int(r[4]), "?"),
                    "xgb_clean_ratio": round(float(r[5]), 3),
                    "total_flows": int(r[6]),
                    "unique_ports": int(r[7]),
                    "unique_dsts": int(r[8]),
                    "services": list(r[9]) if r[9] else [],
                    "service_classes": list(r[10]) if r[10] else [],
                    "first_seen": int(r[11]),
                    "last_seen": int(r[12]),
                    "updated_at": int(r[13]),
                    "evidence": evidence_map.get(r[0], []),
                    "service_labels": service_map.get(r[0], []),
                } for r in rows],
            }
        except Exception as exc:
            log.error("god catches: %s", exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 4. GET /data/god/reputation
    # -----------------------------------------------------------------------
    @app.get("/data/god/reputation")
    def god_reputation(
        verdict: Optional[str] = Query(None, description="NONE, CAPTURE, or DROP"),
        verdict_group: Optional[str] = Query(None, description="verdict_group filter or prefix"),
        has_evidence: Optional[int] = Query(None, ge=0, le=1),
        search: Optional[str] = Query(None, description="IP prefix search"),
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        sort: str = Query("total_flows"),
        order: str = Query("desc"),
    ):
        try:
            allowed_sorts = {"total_flows", "updated_at", "xgb_clean_ratio",
                             "unique_ports", "unique_dsts",
                             "first_seen", "last_seen", "evidence_count"}
            if sort not in allowed_sorts:
                sort = "total_flows"
            if order not in ("asc", "desc"):
                order = "desc"

            wheres: list[str] = []
            params: dict = {}
            if verdict is not None:
                wheres.append("verdict = %(verdict)s")
                params["verdict"] = verdict
            if verdict_group is not None:
                wheres.append("verdict_group LIKE %(verdict_group)s")
                params["verdict_group"] = f"{verdict_group}%"
            if has_evidence is not None:
                if has_evidence:
                    wheres.append("evidence_count > 0")
                else:
                    wheres.append("evidence_count = 0")
            if search:
                wheres.append("toString(src_ip) LIKE %(search)s")
                params["search"] = f"{search}%"

            where_sql = ("WHERE " + " AND ".join(wheres)) if wheres else ""
            params["limit"] = limit
            params["offset"] = offset

            with lock:
                cnt = client.execute(
                    f"SELECT count() FROM dfi.ip_profile FINAL {where_sql}", params)
                rows = client.execute(f"""
                    SELECT toString(src_ip), verdict, verdict_group,
                           evidence_count, best_xgb_class, xgb_clean_ratio,
                           total_flows, unique_ports, unique_dsts,
                           services, service_classes, evidence_services, evidence_types,
                           toUnixTimestamp(first_seen), toUnixTimestamp(last_seen),
                           toUnixTimestamp(updated_at)
                    FROM dfi.ip_profile FINAL {where_sql}
                    ORDER BY {sort} {order} LIMIT %(limit)s OFFSET %(offset)s
                """, params)

            return {
                "total": int(cnt[0][0]) if cnt else 0,
                "items": [{
                    "src_ip": r[0],
                    "verdict": str(r[1]),
                    "verdict_name": VERDICT_NAMES.get(str(r[1]), "?"),
                    "verdict_group": str(r[2]),
                    "has_evidence": int(r[3]) > 0,
                    "evidence_count": int(r[3]),
                    "best_xgb_class": int(r[4]),
                    "xgb_class_name": CLASS_NAMES.get(int(r[4]), "?"),
                    "xgb_clean_ratio": round(float(r[5]), 3),
                    "total_flows": int(r[6]),
                    "unique_ports": int(r[7]),
                    "unique_dsts": int(r[8]),
                    "services": list(r[9]) if r[9] else [],
                    "service_classes": list(r[10]) if r[10] else [],
                    "evidence_services": list(r[11]) if r[11] else [],
                    "evidence_types": int(r[12]),
                    "first_seen": int(r[13]),
                    "last_seen": int(r[14]),
                    "updated_at": int(r[15]),
                } for r in rows],
            }
        except Exception as exc:
            log.error("god reputation: %s", exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 5. GET /data/god/ip/{ip:path}
    # -----------------------------------------------------------------------
    @app.get("/data/god/ip/{ip:path}")
    def god_ip_detail(ip: str):
        try:
            with lock:
                rep = client.execute("""
                    SELECT toString(src_ip), verdict, verdict_group,
                           evidence_count, evidence_services, evidence_types,
                           best_xgb_class, xgb_clean_ratio,
                           total_flows, unique_ports, unique_dsts,
                           services, service_classes,
                           toUnixTimestamp(first_seen), toUnixTimestamp(last_seen),
                           toUnixTimestamp(updated_at), toUnixTimestamp(verdict_expires)
                    FROM dfi.ip_profile FINAL WHERE src_ip = toIPv4(%(ip)s) LIMIT 1
                """, {"ip": ip})
                timeline = client.execute("""
                    SELECT toUnixTimestamp(ingested_at), xgb_class, xgb_confidence,
                           dst_port, pkts_rev, toString(dst_ip), ip_proto, vlan_id
                    FROM dfi.ip_score_log WHERE src_ip = toIPv4(%(ip)s)
                    ORDER BY ingested_at DESC LIMIT 100
                """, {"ip": ip})
                evidence = client.execute("""
                    SELECT toUnixTimestamp(ts), event_type, event_detail,
                           source_program, source_log, toString(target_ip)
                    FROM dfi.evidence_events
                    WHERE src_ip = toIPv4(%(ip)s)
                    ORDER BY ts DESC LIMIT 100
                """, {"ip": ip})
                svc_labels = client.execute("""
                    SELECT service_id, service_class, label_confidence,
                           label_source, evidence_mask, event_count,
                           toUnixTimestamp(first_seen), toUnixTimestamp(last_seen)
                    FROM dfi.ip_service_labels FINAL
                    WHERE src_ip = toIPv4(%(ip)s)
                """, {"ip": ip})

            if not rep:
                raise HTTPException(404, "IP not found")

            r = rep[0]
            geo = ch_adapter._geoip_lookup(ip)

            return {
                "profile": {
                    "src_ip": r[0],
                    "verdict": str(r[1]),
                    "verdict_name": VERDICT_NAMES.get(str(r[1]), "?"),
                    "verdict_group": str(r[2]),
                    "evidence_count": int(r[3]),
                    "has_evidence": int(r[3]) > 0,
                    "evidence_services": list(r[4]) if r[4] else [],
                    "evidence_types": int(r[5]),
                    "best_xgb_class": int(r[6]),
                    "xgb_class_name": CLASS_NAMES.get(int(r[6]), "?"),
                    "xgb_clean_ratio": round(float(r[7]), 3),
                    "total_flows": int(r[8]),
                    "unique_ports": int(r[9]),
                    "unique_dsts": int(r[10]),
                    "services": list(r[11]) if r[11] else [],
                    "service_classes": list(r[12]) if r[12] else [],
                    "first_seen": int(r[13]),
                    "last_seen": int(r[14]),
                    "updated_at": int(r[15]),
                    "verdict_expires": int(r[16]),
                },
                "geo": geo,
                "timeline": [{
                    "ts": int(t[0]),
                    "xgb_class": int(t[1]),
                    "xgb_class_name": CLASS_NAMES.get(int(t[1]), "?"),
                    "xgb_confidence": round(float(t[2]), 3),
                    "dst_port": int(t[3]),
                    "pkts_rev": int(t[4]),
                    "dst_ip": str(t[5]),
                    "ip_proto": int(t[6]),
                    "vlan_id": int(t[7]),
                } for t in timeline],
                "evidence": [{
                    "ts": int(e[0]),
                    "event_type": str(e[1]),
                    "event_detail": str(e[2]),
                    "source_program": str(e[3]),
                    "source_log": str(e[4]),
                    "target_ip": str(e[5]),
                } for e in evidence],
                "service_labels": [{
                    "service_id": int(sl[0]),
                    "service_name": SERVICE_NAMES.get(int(sl[0]), f"SVC_{sl[0]}"),
                    "service_class": int(sl[1]),
                    "class_name": SERVICE_CLASSES.get(int(sl[0]), {}).get(int(sl[1]), f"CLASS_{sl[1]}"),
                    "label_confidence": round(float(sl[2]), 3),
                    "label_source": str(sl[3]),
                    "evidence_mask": int(sl[4]),
                    "event_count": int(sl[5]),
                    "first_seen": int(sl[6]),
                    "last_seen": int(sl[7]),
                } for sl in svc_labels],
            }
        except HTTPException:
            raise
        except Exception as exc:
            log.error("god ip detail %s: %s", ip, exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 6. GET /data/god/verdicts
    # -----------------------------------------------------------------------
    @app.get("/data/god/verdicts")
    def god_verdicts(
        tab: str = Query("drops", description="'drops' or 'captures'"),
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ):
        try:
            if tab == "captures":
                with lock:
                    cnt = client.execute(
                        "SELECT count() FROM dfi.ip_capture_d2")
                    rows = client.execute("""
                        SELECT toString(src_ip), toString(dst_ip), dst_port, ip_proto,
                               vlan_id, xgb_class, xgb_confidence,
                               discrepancy_type, truth_label, service_id, service_class,
                               capture_value_score,
                               toUnixTimestamp(first_ts), toUnixTimestamp(last_ts),
                               toUnixTimestamp(captured_at),
                               pkts_fwd, pkts_rev, bytes_fwd, bytes_rev
                        FROM dfi.ip_capture_d2
                        ORDER BY captured_at DESC
                        LIMIT %(limit)s OFFSET %(offset)s
                    """, {"limit": limit, "offset": offset})
                return {
                    "tab": "captures",
                    "total": int(cnt[0][0]) if cnt else 0,
                    "items": [{
                        "src_ip": r[0], "dst_ip": r[1],
                        "dst_port": int(r[2]), "ip_proto": int(r[3]),
                        "vlan_id": int(r[4]),
                        "xgb_class": int(r[5]),
                        "xgb_class_name": CLASS_NAMES.get(int(r[5]), "?"),
                        "xgb_confidence": round(float(r[6]), 3),
                        "discrepancy_type": str(r[7]),
                        "truth_label": str(r[8]),
                        "service_id": int(r[9]),
                        "service_name": SERVICE_NAMES.get(int(r[9]), f"SVC_{r[9]}"),
                        "service_class": int(r[10]),
                        "class_name": SERVICE_CLASSES.get(int(r[9]), {}).get(int(r[10]), f"CLASS_{r[10]}"),
                        "capture_value_score": round(float(r[11]), 3),
                        "first_ts": int(r[12]), "last_ts": int(r[13]),
                        "captured_at": int(r[14]),
                        "pkts_fwd": int(r[15]), "pkts_rev": int(r[16]),
                        "bytes_fwd": int(r[17]), "bytes_rev": int(r[18]),
                    } for r in rows],
                }
            else:
                # drops tab: ip_profile WHERE verdict='DROP'
                with lock:
                    cnt = client.execute("""
                        SELECT count() FROM dfi.ip_profile FINAL
                        WHERE verdict = 'DROP'
                    """)
                    rows = client.execute("""
                        SELECT toString(src_ip), verdict_group, evidence_count,
                               best_xgb_class, xgb_clean_ratio,
                               total_flows, unique_ports, unique_dsts,
                               services, service_classes,
                               toUnixTimestamp(first_seen), toUnixTimestamp(last_seen),
                               toUnixTimestamp(updated_at), toUnixTimestamp(verdict_expires)
                        FROM dfi.ip_profile FINAL
                        WHERE verdict = 'DROP'
                        ORDER BY updated_at DESC
                        LIMIT %(limit)s OFFSET %(offset)s
                    """, {"limit": limit, "offset": offset})
                return {
                    "tab": "drops",
                    "total": int(cnt[0][0]) if cnt else 0,
                    "items": [{
                        "src_ip": r[0],
                        "verdict": "DROP",
                        "verdict_group": str(r[1]),
                        "has_evidence": int(r[2]) > 0,
                        "evidence_count": int(r[2]),
                        "best_xgb_class": int(r[3]),
                        "xgb_class_name": CLASS_NAMES.get(int(r[3]), "?"),
                        "xgb_clean_ratio": round(float(r[4]), 3),
                        "total_flows": int(r[5]),
                        "unique_ports": int(r[6]),
                        "unique_dsts": int(r[7]),
                        "services": list(r[8]) if r[8] else [],
                        "service_classes": list(r[9]) if r[9] else [],
                        "first_seen": int(r[10]),
                        "last_seen": int(r[11]),
                        "updated_at": int(r[12]),
                        "verdict_expires": int(r[13]),
                    } for r in rows],
                }
        except Exception as exc:
            log.error("god verdicts: %s", exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 7. GET /data/god/services
    # -----------------------------------------------------------------------
    @app.get("/data/god/services")
    def god_services():
        try:
            with lock:
                # Per-service class distribution
                dist_rows = client.execute("""
                    SELECT service_id, service_class, count() AS ip_count,
                           sum(event_count) AS total_events
                    FROM dfi.ip_service_labels FINAL
                    GROUP BY service_id, service_class
                    ORDER BY service_id, service_class
                """)
                # Evidence by source_program
                ev_rows = client.execute("""
                    SELECT source_program, count() AS ev_count,
                           uniq(src_ip) AS unique_ips
                    FROM dfi.evidence_events
                    WHERE ts >= now() - INTERVAL 24 HOUR
                    GROUP BY source_program
                    ORDER BY ev_count DESC
                """)
                # Budget
                bud_rows = client.execute("""
                    SELECT service_id, service_class,
                           group_count, group_target, group_complete, unique_actors
                    FROM dfi.ip_capture_budget
                    ORDER BY service_id, service_class
                """)

            # Build per-service result
            services: dict[int, dict] = {}
            for sid in SERVICE_NAMES:
                services[sid] = {
                    "service_id": sid,
                    "service_name": SERVICE_NAMES[sid],
                    "classes": [],
                    "budgets": [],
                    "total_ips": 0,
                    "total_events": 0,
                }

            for dr in dist_rows:
                sid = int(dr[0])
                scl = int(dr[1])
                ipc = int(dr[2])
                tev = int(dr[3])
                if sid in services:
                    services[sid]["classes"].append({
                        "service_class": scl,
                        "class_name": SERVICE_CLASSES.get(sid, {}).get(scl, f"CLASS_{scl}"),
                        "ip_count": ipc,
                        "total_events": tev,
                    })
                    services[sid]["total_ips"] += ipc
                    services[sid]["total_events"] += tev

            for br in bud_rows:
                sid = int(br[0])
                scl = int(br[1])
                if sid in services:
                    services[sid]["budgets"].append({
                        "service_class": scl,
                        "class_name": SERVICE_CLASSES.get(sid, {}).get(scl, f"CLASS_{scl}"),
                        "group_count": int(br[2]),
                        "group_target": int(br[3]),
                        "group_complete": int(br[4]),
                        "unique_actors": int(br[5]),
                    })

            return {
                "services": list(services.values()),
                "evidence_by_program": [{
                    "source_program": str(ev[0]),
                    "event_count": int(ev[1]),
                    "unique_ips": int(ev[2]),
                } for ev in ev_rows],
            }
        except Exception as exc:
            log.error("god services: %s", exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 8. GET /data/god/services/{service_id}
    # -----------------------------------------------------------------------
    @app.get("/data/god/services/{service_id}")
    def god_service_detail(
        service_id: int,
        limit: int = Query(50, ge=1, le=500),
    ):
        if service_id not in SERVICE_NAMES:
            raise HTTPException(404, f"Unknown service_id: {service_id}")
        try:
            with lock:
                # Class distribution for this service
                dist = client.execute("""
                    SELECT service_class, count() AS ip_count,
                           sum(event_count) AS total_events,
                           avg(label_confidence) AS avg_conf
                    FROM dfi.ip_service_labels FINAL
                    WHERE service_id = %(sid)s
                    GROUP BY service_class
                    ORDER BY service_class
                """, {"sid": service_id})
                # Top IPs by event count
                top_ips = client.execute("""
                    SELECT toString(s.src_ip), s.service_class, s.label_confidence,
                           s.event_count, r.verdict_group, r.evidence_count,
                           r.total_flows, r.best_xgb_class, r.xgb_clean_ratio
                    FROM dfi.ip_service_labels AS s FINAL
                    INNER JOIN dfi.ip_profile AS r FINAL ON s.src_ip = r.src_ip
                    WHERE s.service_id = %(sid)s
                    ORDER BY s.event_count DESC
                    LIMIT %(limit)s
                """, {"sid": service_id, "limit": limit})
                # Budget for this service
                bud = client.execute("""
                    SELECT service_class, group_count, group_target,
                           group_complete, unique_actors
                    FROM dfi.ip_capture_budget
                    WHERE service_id = %(sid)s
                    ORDER BY service_class
                """, {"sid": service_id})

            return {
                "service_id": service_id,
                "service_name": SERVICE_NAMES[service_id],
                "class_distribution": [{
                    "service_class": int(d[0]),
                    "class_name": SERVICE_CLASSES.get(service_id, {}).get(int(d[0]), f"CLASS_{d[0]}"),
                    "ip_count": int(d[1]),
                    "total_events": int(d[2]),
                    "avg_confidence": round(float(d[3]), 3),
                } for d in dist],
                "top_ips": [{
                    "src_ip": t[0],
                    "service_class": int(t[1]),
                    "class_name": SERVICE_CLASSES.get(service_id, {}).get(int(t[1]), f"CLASS_{t[1]}"),
                    "label_confidence": round(float(t[2]), 3),
                    "event_count": int(t[3]),
                    "verdict_group": str(t[4]),
                    "has_evidence": int(t[5]) > 0,
                    "evidence_count": int(t[5]),
                    "total_flows": int(t[6]),
                    "best_xgb_class": int(t[7]),
                    "xgb_class_name": CLASS_NAMES.get(int(t[7]), "?"),
                    "xgb_clean_ratio": round(float(t[8]), 3),
                } for t in top_ips],
                "budgets": [{
                    "service_class": int(b[0]),
                    "class_name": SERVICE_CLASSES.get(service_id, {}).get(int(b[0]), f"CLASS_{b[0]}"),
                    "group_count": int(b[1]),
                    "group_target": int(b[2]),
                    "group_complete": int(b[3]),
                    "unique_actors": int(b[4]),
                } for b in bud],
            }
        except HTTPException:
            raise
        except Exception as exc:
            log.error("god service detail %d: %s", service_id, exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 9. GET /data/god/training
    # -----------------------------------------------------------------------
    @app.get("/data/god/training")
    def god_training():
        try:
            cap_limit = 1_000_000
            with lock:
                # D2 capture counts by discrepancy type
                d2_rows = client.execute("""
                    SELECT discrepancy_type, count() AS cnt
                    FROM dfi.ip_capture_d2
                    GROUP BY discrepancy_type
                    ORDER BY cnt DESC
                """)
                d2_total = client.execute(
                    "SELECT count() FROM dfi.ip_capture_d2")
                # Per-service x class budget deficits
                bud_rows = client.execute("""
                    SELECT service_id, service_class,
                           group_count, group_target, group_complete, unique_actors
                    FROM dfi.ip_capture_budget
                    ORDER BY service_id, service_class
                """)

            total_captured = int(d2_total[0][0]) if d2_total else 0
            return {
                "total_captured": total_captured,
                "capture_limit": cap_limit,
                "pct_complete": round(total_captured / cap_limit * 100, 1) if cap_limit else 0,
                "by_discrepancy_type": [{
                    "discrepancy_type": str(d[0]),
                    "count": int(d[1]),
                } for d in d2_rows],
                "service_budgets": [{
                    "service_id": int(b[0]),
                    "service_name": SERVICE_NAMES.get(int(b[0]), f"SVC_{b[0]}"),
                    "service_class": int(b[1]),
                    "class_name": SERVICE_CLASSES.get(int(b[0]), {}).get(int(b[1]), f"CLASS_{b[1]}"),
                    "group_count": int(b[2]),
                    "group_target": int(b[3]),
                    "group_complete": int(b[4]),
                    "unique_actors": int(b[5]),
                    "deficit": max(0, int(b[3]) - int(b[2])),
                } for b in bud_rows],
            }
        except Exception as exc:
            log.error("god training: %s", exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 10. GET /data/god/map/events
    # -----------------------------------------------------------------------
    @app.get("/data/god/map/events")
    def god_map_events(
        hours: int = Query(1, ge=1, le=168),
        limit: int = Query(500, ge=1, le=5000),
    ):
        try:
            with lock:
                rows = client.execute("""
                    SELECT toString(src_ip), xgb_class, count() AS flow_count,
                           toUnixTimestamp(min(ingested_at)) AS first_ts,
                           toUnixTimestamp(max(ingested_at)) AS last_ts
                    FROM dfi.ip_score_log
                    WHERE ingested_at >= now() - INTERVAL %(hours)s HOUR
                      AND xgb_class < 4
                    GROUP BY src_ip, xgb_class
                    ORDER BY flow_count DESC
                    LIMIT %(limit)s
                """, {"hours": hours, "limit": limit})

            events = []
            for r in rows:
                ip_str = str(r[0])
                geo = ch_adapter._geoip_lookup(ip_str)
                events.append({
                    "src_ip": ip_str,
                    "xgb_class": int(r[1]),
                    "xgb_class_name": CLASS_NAMES.get(int(r[1]), "?"),
                    "flow_count": int(r[2]),
                    "first_ts": int(r[3]),
                    "last_ts": int(r[4]),
                    "country": geo["country"] if geo else "Unknown",
                    "country_code": geo["country_code"] if geo else "XX",
                    "lat": geo["lat"] if geo else 0.0,
                    "lng": geo["lng"] if geo else 0.0,
                })

            return {"events": events, "total": len(events)}
        except Exception as exc:
            log.error("god map events: %s", exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 11. GET /data/god/map/heatmap
    # -----------------------------------------------------------------------
    @app.get("/data/god/map/heatmap")
    def god_map_heatmap(hours: int = Query(168, ge=1, le=720)):
        try:
            with lock:
                rows = client.execute("""
                    SELECT toDayOfWeek(ingested_at) AS dow,
                           toHour(ingested_at) AS hr,
                           count() AS cnt
                    FROM dfi.ip_score_log
                    WHERE ingested_at >= now() - INTERVAL %(hours)s HOUR
                      AND xgb_class < 4
                    GROUP BY dow, hr
                    ORDER BY dow, hr
                """, {"hours": hours})

            heatmap: dict[str, int] = {}
            for r in rows:
                key = f"{int(r[0])}:{int(r[1])}"
                heatmap[key] = int(r[2])
            return {"heatmap": heatmap, "hours": hours}
        except Exception as exc:
            log.error("god map heatmap: %s", exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 12. GET /data/god/map/countries
    # -----------------------------------------------------------------------
    @app.get("/data/god/map/countries")
    def god_map_countries(
        hours: int = Query(24, ge=1, le=720),
        limit: int = Query(20, ge=1, le=100),
    ):
        try:
            with lock:
                rows = client.execute("""
                    SELECT toString(src_ip), count() AS cnt
                    FROM dfi.ip_score_log
                    WHERE ingested_at >= now() - INTERVAL %(hours)s HOUR
                      AND xgb_class < 4
                    GROUP BY src_ip
                    ORDER BY cnt DESC
                    LIMIT 5000
                """, {"hours": hours})

            # Aggregate by country using GeoIP
            country_agg: dict[str, dict] = {}
            for r in rows:
                ip = str(r[0])
                cnt = int(r[1])
                geo = ch_adapter._geoip_lookup(ip)
                cc = geo["country_code"] if geo else "XX"
                name = geo["country"] if geo else "Unknown"
                if cc not in country_agg:
                    country_agg[cc] = {"country": name, "country_code": cc,
                                       "attacks": 0, "unique_ips": 0}
                country_agg[cc]["attacks"] += cnt
                country_agg[cc]["unique_ips"] += 1

            sorted_countries = sorted(country_agg.values(),
                                      key=lambda x: x["attacks"], reverse=True)
            return {"countries": sorted_countries[:limit], "hours": hours}
        except Exception as exc:
            log.error("god map countries: %s", exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 13. GET /data/god/allowlist
    # -----------------------------------------------------------------------
    @app.get("/data/god/allowlist")
    def god_allowlist(
        limit: int = Query(200, ge=1, le=1000),
        offset: int = Query(0, ge=0),
    ):
        try:
            with lock:
                cnt = client.execute("""
                    SELECT count() FROM dfi.ip_profile FINAL
                    WHERE verdict_group = 'RB'
                """)
                rows = client.execute("""
                    SELECT toString(src_ip), total_flows, unique_ports, unique_dsts,
                           best_xgb_class, xgb_clean_ratio,
                           toUnixTimestamp(first_seen), toUnixTimestamp(last_seen),
                           toUnixTimestamp(updated_at)
                    FROM dfi.ip_profile FINAL
                    WHERE verdict_group = 'RB'
                    ORDER BY updated_at DESC
                    LIMIT %(limit)s OFFSET %(offset)s
                """, {"limit": limit, "offset": offset})

            return {
                "total": int(cnt[0][0]) if cnt else 0,
                "items": [{
                    "src_ip": r[0],
                    "total_flows": int(r[1]),
                    "unique_ports": int(r[2]),
                    "unique_dsts": int(r[3]),
                    "best_xgb_class": int(r[4]),
                    "xgb_class_name": CLASS_NAMES.get(int(r[4]), "?"),
                    "xgb_clean_ratio": round(float(r[5]), 3),
                    "first_seen": int(r[6]),
                    "last_seen": int(r[7]),
                    "updated_at": int(r[8]),
                } for r in rows],
            }
        except Exception as exc:
            log.error("god allowlist: %s", exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 14. POST /data/god/allowlist/add
    # -----------------------------------------------------------------------
    @app.post("/data/god/allowlist/add")
    def god_allowlist_add(req: AllowlistRequest):
        ip = req.ip.strip()
        if not ip:
            raise HTTPException(400, "IP required")
        try:
            with lock:
                # Check if IP exists
                exists = client.execute("""
                    SELECT count() FROM dfi.ip_profile FINAL
                    WHERE src_ip = toIPv4(%(ip)s)
                """, {"ip": ip})
                if not exists or int(exists[0][0]) == 0:
                    # Insert new row with allowlist verdict
                    client.execute("""
                        INSERT INTO dfi.ip_profile
                        (src_ip, services, service_classes, evidence_count,
                         evidence_services, evidence_types,
                         unique_dsts, unique_ports, total_flows,
                         first_seen, last_seen, best_xgb_class, xgb_clean_ratio,
                         verdict, verdict_group, verdict_expires, updated_at)
                        VALUES (toIPv4(%(ip)s), [], [], 0,
                                [], 0,
                                0, 0, 0,
                                now(), now(), 4, 0.0,
                                'CAPTURE', 'RB', now() + INTERVAL 365 DAY, now())
                    """, {"ip": ip})
                else:
                    # Update existing: insert new version with verdict='CAPTURE', verdict_group='RB'
                    # ReplacingMergeTree will keep the latest version
                    client.execute("""
                        INSERT INTO dfi.ip_profile
                        SELECT src_ip, services, service_classes, evidence_count,
                               evidence_services, evidence_types,
                               unique_dsts, unique_ports, total_flows,
                               first_seen, last_seen, best_xgb_class, xgb_clean_ratio,
                               'CAPTURE' AS verdict, 'RB' AS verdict_group,
                               now() + INTERVAL 365 DAY AS verdict_expires,
                               now() AS updated_at
                        FROM dfi.ip_profile FINAL
                        WHERE src_ip = toIPv4(%(ip)s)
                    """, {"ip": ip})

            log.info("Allowlist ADD: %s", ip)
            return {"status": "ok", "action": "added", "ip": ip}
        except Exception as exc:
            log.error("god allowlist add %s: %s", ip, exc)
            raise HTTPException(500, str(exc))

    # -----------------------------------------------------------------------
    # 15. POST /data/god/allowlist/remove
    # -----------------------------------------------------------------------
    @app.post("/data/god/allowlist/remove")
    def god_allowlist_remove(req: AllowlistRequest):
        ip = req.ip.strip()
        if not ip:
            raise HTTPException(400, "IP required")
        try:
            with lock:
                exists = client.execute("""
                    SELECT count() FROM dfi.ip_profile FINAL
                    WHERE src_ip = toIPv4(%(ip)s) AND verdict_group = 'RB'
                """, {"ip": ip})
                if not exists or int(exists[0][0]) == 0:
                    raise HTTPException(404, f"{ip} not on allowlist")

                # Insert new version with verdict='NONE', clear RB group
                client.execute("""
                    INSERT INTO dfi.ip_profile
                    SELECT src_ip, services, service_classes, evidence_count,
                           evidence_services, evidence_types,
                           unique_dsts, unique_ports, total_flows,
                           first_seen, last_seen, best_xgb_class, xgb_clean_ratio,
                           'NONE' AS verdict, 'CLN' AS verdict_group,
                           toDateTime64(0, 3) AS verdict_expires,
                           now() AS updated_at
                    FROM dfi.ip_profile FINAL
                    WHERE src_ip = toIPv4(%(ip)s)
                """, {"ip": ip})

            log.info("Allowlist REMOVE: %s", ip)
            return {"status": "ok", "action": "removed", "ip": ip}
        except HTTPException:
            raise
        except Exception as exc:
            log.error("god allowlist remove %s: %s", ip, exc)
            raise HTTPException(500, str(exc))
