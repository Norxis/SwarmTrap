import json
import time
from dataclasses import asdict, dataclass
from typing import Any, Protocol


class SQLitePort(Protocol):
    def payload_hash(self, payload: dict[str, Any]) -> str: ...
    def connect(self): ...
    def load_request(self, conn, request_id: str): ...
    def save_request(self, conn, *, request_id: str, action: str, payload_hash: str, response_json: str) -> None: ...
    def get_current_depth(self, conn, ip: str) -> int: ...
    def upsert_watchlist(self, conn, *, ip: str, capture_depth: int, priority: int, group_id, sub_group_id, reason: str, source: str, expires_at) -> None: ...
    def delete_watchlist(self, conn, *, ip: str) -> bool: ...
    def list_watchlist(self, conn, *, limit: int = 500) -> list[dict[str, Any]]: ...


class LedgerPort(Protocol):
    def is_active(self, ip: str, active_window_sec: int) -> bool: ...
    def log_analyst_action(self, *, ip: str, action_type: str, capture_depth, priority, reason: str, actor: str, expires_at, request_id: str | None = None) -> None: ...
    def log_depth_change(self, *, ip: str, old_depth: int, new_depth: int, reason: str, triggered_by: str, request_id: str | None = None) -> None: ...
    def log_watchlist_sync(self, *, ip: str, capture_depth: int, priority: int, group_id, sub_group_id, source: str, reason: str, expires_at, request_id: str | None = None) -> None: ...
    def resolve_campaign_ips(self, campaign_id: str, max_ips: int) -> list[str]: ...
    def query_audit_log(self, limit: int = 200) -> list[dict]: ...
    def query_vm_flows(self, pub_ips: list[str], hours: int = 24) -> dict: ...
    def query_vm_events(self, pub_ip: str, limit: int = 100) -> list[dict]: ...
    def query_ml_stats(self, model_name: str, ml_metrics_dir: str) -> dict: ...
    def query_map_events(self, hours: int = 1, limit: int = 500) -> dict: ...
    def query_attack_heatmap(self, days: int = 7) -> dict: ...
    def query_top_countries(self, hours: int = 24, limit: int = 10) -> dict: ...


@dataclass
class OperationResult:
    ok: bool
    request_id: str
    message: str


@dataclass
class BulkOperationResult(OperationResult):
    processed: int
    skipped: int


class PolicyError(RuntimeError):
    pass


class ConflictError(RuntimeError):
    pass


class ControlPlaneService:
    def __init__(
        self,
        *,
        sqlite_adapter: SQLitePort,
        ledger_adapter: LedgerPort,
        active_window_sec: int,
        max_bulk_ips: int,
    ):
        self.sqlite = sqlite_adapter
        self.ledger = ledger_adapter
        self.active_window_sec = active_window_sec
        self.max_bulk_ips = max_bulk_ips

    def upsert_watchlist(
        self,
        *,
        request_id: str,
        ip: str,
        capture_depth: int,
        priority: int,
        reason: str,
        source: str,
        actor: str,
        expires_at,
        group_id=None,
        sub_group_id=None,
    ) -> OperationResult:
        payload = {
            "ip": ip,
            "capture_depth": capture_depth,
            "priority": priority,
            "reason": reason,
            "source": source,
            "actor": actor,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "group_id": group_id,
            "sub_group_id": sub_group_id,
        }
        phash = self.sqlite.payload_hash(payload)

        conn = self.sqlite.connect()
        conn.execute("BEGIN")
        try:
            existing = self.sqlite.load_request(conn, request_id)
            if existing:
                if existing.payload_hash != phash:
                    raise ConflictError("idempotency key reused with different payload")
                cached = json.loads(existing.response_json)
                conn.rollback()
                return OperationResult(**cached)

            old_depth = self.sqlite.get_current_depth(conn, ip)
            if capture_depth < old_depth and self.ledger.is_active(ip, self.active_window_sec):
                raise PolicyError("cannot demote while attacker is active")

            reason_with_req = f"{reason} [request_id={request_id}]"
            self.sqlite.upsert_watchlist(
                conn,
                ip=ip,
                capture_depth=capture_depth,
                priority=priority,
                group_id=group_id,
                sub_group_id=sub_group_id,
                reason=reason_with_req,
                source=source,
                expires_at=expires_at,
            )

            self.ledger.log_analyst_action(
                ip=ip,
                action_type="upsert",
                capture_depth=capture_depth,
                priority=priority,
                reason=reason_with_req,
                actor=actor,
                expires_at=expires_at,
                request_id=request_id,
            )
            if old_depth != capture_depth:
                self.ledger.log_depth_change(
                    ip=ip,
                    old_depth=old_depth,
                    new_depth=capture_depth,
                    reason=reason_with_req,
                    triggered_by=source,
                    request_id=request_id,
                )
            self.ledger.log_watchlist_sync(
                ip=ip,
                capture_depth=capture_depth,
                priority=priority,
                group_id=group_id,
                sub_group_id=sub_group_id,
                source=source,
                reason=reason_with_req,
                expires_at=expires_at,
                request_id=request_id,
            )

            result = OperationResult(ok=True, request_id=request_id, message="watchlist upserted")
            self.sqlite.save_request(
                conn,
                request_id=request_id,
                action="upsert",
                payload_hash=phash,
                response_json=json.dumps(asdict(result)),
            )
            conn.commit()
            return result
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def delete_watchlist(self, *, request_id: str, ip: str, reason: str, actor: str) -> OperationResult:
        payload = {"ip": ip, "reason": reason, "actor": actor}
        phash = self.sqlite.payload_hash(payload)

        conn = self.sqlite.connect()
        conn.execute("BEGIN")
        try:
            existing = self.sqlite.load_request(conn, request_id)
            if existing:
                if existing.payload_hash != phash:
                    raise ConflictError("idempotency key reused with different payload")
                cached = json.loads(existing.response_json)
                conn.rollback()
                return OperationResult(**cached)

            reason_with_req = f"{reason} [request_id={request_id}]"
            deleted = self.sqlite.delete_watchlist(conn, ip=ip)
            self.ledger.log_analyst_action(
                ip=ip,
                action_type="delete",
                capture_depth=None,
                priority=None,
                reason=reason_with_req,
                actor=actor,
                expires_at=None,
                request_id=request_id,
            )

            msg = "watchlist deleted" if deleted else "watchlist entry not found"
            result = OperationResult(ok=True, request_id=request_id, message=msg)
            self.sqlite.save_request(
                conn,
                request_id=request_id,
                action="delete",
                payload_hash=phash,
                response_json=json.dumps(asdict(result)),
            )
            conn.commit()
            return result
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def bulk_action(
        self,
        *,
        request_id: str,
        action: str,
        ip_list: list[str],
        campaign_id: str | None,
        reason: str,
        actor: str,
        source: str,
        capture_depth: int | None = None,
        priority: int | None = None,
        expires_at=None,
    ) -> BulkOperationResult:
        if not ip_list and not campaign_id:
            raise ValueError("ip_list or campaign_id is required")
        if campaign_id:
            campaign_ips = self.ledger.resolve_campaign_ips(campaign_id, self.max_bulk_ips)
            ip_list = list(set(ip_list + campaign_ips))
        if not ip_list:
            raise ValueError("resolved ip list is empty")
        if len(ip_list) > self.max_bulk_ips:
            raise ValueError(f"ip_list exceeds max_bulk_ips={self.max_bulk_ips}")

        payload = {
            "action": action,
            "ip_list": sorted(ip_list),
            "campaign_id": campaign_id,
            "reason": reason,
            "actor": actor,
            "source": source,
            "capture_depth": capture_depth,
            "priority": priority,
            "expires_at": expires_at.isoformat() if expires_at else None,
        }
        phash = self.sqlite.payload_hash(payload)

        conn = self.sqlite.connect()
        conn.execute("BEGIN")
        try:
            existing = self.sqlite.load_request(conn, request_id)
            if existing:
                if existing.payload_hash != phash:
                    raise ConflictError("idempotency key reused with different payload")
                cached = json.loads(existing.response_json)
                conn.rollback()
                return BulkOperationResult(**cached)

            processed = 0
            skipped = 0
            reason_with_req = f"{reason} [request_id={request_id}]"
            for ip in ip_list:
                if action == "upsert":
                    if capture_depth is None or priority is None:
                        raise ValueError("capture_depth and priority are required for bulk upsert")
                    old_depth = self.sqlite.get_current_depth(conn, ip)
                    if capture_depth < old_depth and self.ledger.is_active(ip, self.active_window_sec):
                        skipped += 1
                        continue
                    self.sqlite.upsert_watchlist(
                        conn,
                        ip=ip,
                        capture_depth=capture_depth,
                        priority=priority,
                        group_id=None,
                        sub_group_id=None,
                        reason=reason_with_req,
                        source=source,
                        expires_at=expires_at,
                    )
                    self.ledger.log_analyst_action(
                        ip=ip,
                        action_type="bulk_upsert",
                        capture_depth=capture_depth,
                        priority=priority,
                        reason=reason_with_req,
                        actor=actor,
                        expires_at=expires_at,
                        request_id=request_id,
                    )
                    if old_depth != capture_depth:
                        self.ledger.log_depth_change(
                            ip=ip,
                            old_depth=old_depth,
                            new_depth=capture_depth,
                            reason=reason_with_req,
                            triggered_by=source,
                            request_id=request_id,
                        )
                    self.ledger.log_watchlist_sync(
                        ip=ip,
                        capture_depth=capture_depth,
                        priority=priority,
                        group_id=None,
                        sub_group_id=None,
                        source=source,
                        reason=reason_with_req,
                        expires_at=expires_at,
                        request_id=request_id,
                    )
                    processed += 1
                    continue

                if action == "delete":
                    self.sqlite.delete_watchlist(conn, ip=ip)
                    self.ledger.log_analyst_action(
                        ip=ip,
                        action_type="bulk_delete",
                        capture_depth=None,
                        priority=None,
                        reason=reason_with_req,
                        actor=actor,
                        expires_at=None,
                        request_id=request_id,
                    )
                    processed += 1
                    continue

                raise ValueError(f"unsupported bulk action: {action}")

            result = BulkOperationResult(
                ok=True,
                request_id=request_id,
                message=f"bulk {action} finished",
                processed=processed,
                skipped=skipped,
            )
            self.sqlite.save_request(
                conn,
                request_id=request_id,
                action=f"bulk_{action}",
                payload_hash=phash,
                response_json=json.dumps(asdict(result)),
            )
            conn.commit()
            return result
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def annotate(self, *, request_id: str, ip: str, note: str, tags: list[str], actor: str) -> OperationResult:
        payload = {"ip": ip, "note": note, "tags": sorted(tags), "actor": actor}
        phash = self.sqlite.payload_hash(payload)
        conn = self.sqlite.connect()
        conn.execute("BEGIN")
        try:
            existing = self.sqlite.load_request(conn, request_id)
            if existing:
                if existing.payload_hash != phash:
                    raise ConflictError("idempotency key reused with different payload")
                cached = json.loads(existing.response_json)
                conn.rollback()
                return OperationResult(**cached)

            reason = f"note={note} tags={','.join(tags)} [request_id={request_id}]"
            self.ledger.log_analyst_action(
                ip=ip,
                action_type="annotate",
                capture_depth=None,
                priority=None,
                reason=reason,
                actor=actor,
                expires_at=None,
                request_id=request_id,
            )
            result = OperationResult(ok=True, request_id=request_id, message="annotation logged")
            self.sqlite.save_request(
                conn,
                request_id=request_id,
                action="annotate",
                payload_hash=phash,
                response_json=json.dumps(asdict(result)),
            )
            conn.commit()
            return result
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def demote_quiet(self, *, quiet_after_sec: int, actor: str = "quiet-demoter", source: str = "rule") -> BulkOperationResult:
        conn = self.sqlite.connect()
        conn.execute("BEGIN")
        request_id = "quiet-demoter"
        try:
            rows = self.sqlite.list_watchlist(conn, limit=self.max_bulk_ips)
            processed = 0
            skipped = 0
            for row in rows:
                ip = row["ip"]
                old_depth = int(row["capture_depth"])
                updated_at = float(row.get("updated_at_epoch") or 0)
                if old_depth <= 1:
                    continue
                if updated_at > 0 and (time.time() - updated_at) < quiet_after_sec:
                    skipped += 1
                    continue
                if self.ledger.is_active(ip, self.active_window_sec):
                    skipped += 1
                    continue
                new_depth = old_depth - 1
                reason = f"quiet_demote {old_depth}->{new_depth}"
                self.sqlite.upsert_watchlist(
                    conn,
                    ip=ip,
                    capture_depth=new_depth,
                    priority=int(row["priority"]),
                    group_id=row.get("group_id"),
                    sub_group_id=row.get("sub_group_id"),
                    reason=reason,
                    source=source,
                    expires_at=None,
                )
                self.ledger.log_analyst_action(
                    ip=ip,
                    action_type="auto_demote",
                    capture_depth=new_depth,
                    priority=int(row["priority"]),
                    reason=reason,
                    actor=actor,
                    expires_at=None,
                )
                self.ledger.log_depth_change(
                    ip=ip,
                    old_depth=old_depth,
                    new_depth=new_depth,
                    reason=reason,
                    triggered_by=source,
                )
                self.ledger.log_watchlist_sync(
                    ip=ip,
                    capture_depth=new_depth,
                    priority=int(row["priority"]),
                    group_id=row.get("group_id"),
                    sub_group_id=row.get("sub_group_id"),
                    source=source,
                    reason=reason,
                    expires_at=None,
                )
                processed += 1

            conn.commit()
            return BulkOperationResult(
                ok=True,
                request_id=request_id,
                message="quiet demotion completed",
                processed=processed,
                skipped=skipped,
            )
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get_audit_log(self, limit: int = 200):
        return self.ledger.query_audit_log(limit)

    def get_ml_stats(self, model_name: str = "xgb_v6", ml_metrics_dir: str = "/opt/dfi2/ml_metrics/"):
        from .models import (
            MlModelStats, ConfusionCell, FeatureImportance, ScoringThroughput,
        )
        data = self.ledger.query_ml_stats(model_name, ml_metrics_dir)
        return MlModelStats(
            model_name=data["model_name"],
            version=data["version"],
            trained_at=data["trained_at"],
            accuracy=data["accuracy"],
            precision_score=data["precision"],
            recall=data["recall"],
            f1=data["f1"],
            total_predictions_24h=data["total_predictions_24h"],
            attack_rate_24h=data["attack_rate_24h"],
            confusion_matrix=[ConfusionCell(**c) for c in data["confusion_matrix"]],
            feature_importance=[FeatureImportance(**f) for f in data["feature_importance"]],
            scoring_throughput=[ScoringThroughput(**s) for s in data["scoring_throughput"]],
            label_distribution=data["label_distribution"],
        )

    def get_map_events(self, hours: int = 1, limit: int = 500) -> dict:
        return self.ledger.query_map_events(hours=hours, limit=limit)

    def get_attack_heatmap(self, days: int = 7) -> dict:
        return self.ledger.query_attack_heatmap(days=days)

    def get_top_countries(self, hours: int = 24, limit: int = 10) -> dict:
        return self.ledger.query_top_countries(hours=hours, limit=limit)

    # ---------------------------------------------------------------------------
    # Model Registry
    # ---------------------------------------------------------------------------

    def get_model_registry(self) -> list[dict]:
        from .rescorer import list_model_registry
        return list_model_registry()
