import logging
from pathlib import Path
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from starlette.staticfiles import StaticFiles

from .adapters import ClickHouseLedgerAdapter, SQLiteWatchlistAdapter
from .config import SETTINGS
from .god_endpoints import register_god_routes
from .models import (
    AnnotateRequest, ApiResponse,
    AuditRow, BulkActionRequest, BulkResponse,
    MapAttacker, MapEventsResponse, MlModelStats,
    ModelInfo, ModelRegistryEntry,
    NormRescoreStatus, NormRescoreLastRun,
    RescoreConfig, RescoreRequest,
    TrainConfig, TrainExportProgress, TrainFoldResult, TrainRequest,
    TrainResult, TrainStatus, TrainTrainProgress,
    VMEvent, VMRebootRequest, VMStatus,
    WatchlistDeleteRequest, WatchlistEntry, WatchlistUpsertRequest,
)
from .proxmox import ProxmoxClient, VM_MAP
from .service import ConflictError, ControlPlaneService, PolicyError
from .scheduler import QuietDemoter

log = logging.getLogger("dfi2.app")


service = ControlPlaneService(
    sqlite_adapter=SQLiteWatchlistAdapter(SETTINGS.watchlist_db),
    ledger_adapter=ClickHouseLedgerAdapter(SETTINGS.ch_host, SETTINGS.ch_port),
    active_window_sec=SETTINGS.active_window_sec,
    max_bulk_ips=SETTINGS.max_bulk_ips,
)
_pve: ProxmoxClient | None = None

def _get_pve() -> ProxmoxClient:
    global _pve
    if _pve is None:
        _pve = ProxmoxClient(SETTINGS.pve_host, SETTINGS.pve_user, SETTINGS.pve_pass)
    return _pve

UI_INDEX = Path(__file__).resolve().parent / "ui" / "index.html"
_UI_DIST = Path(__file__).resolve().parent / "ui" / "soc-dashboard" / "dist"
security = HTTPBasic(auto_error=False)


def _request_id(idempotency_key: str | None) -> str:
    if not idempotency_key:
        raise HTTPException(status_code=400, detail="Idempotency-Key header is required")
    return idempotency_key.strip()


def _require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if not SETTINGS.api_key:
        return
    if x_api_key != SETTINGS.api_key:
        raise HTTPException(status_code=401, detail="invalid API key")


def _ui_auth(credentials: HTTPBasicCredentials | None = Depends(security)) -> None:
    if not SETTINGS.ui_password:
        return
    if not credentials:
        raise HTTPException(status_code=401, detail="auth required")
    user_ok = secrets.compare_digest(credentials.username, SETTINGS.ui_username)
    pass_ok = secrets.compare_digest(credentials.password, SETTINGS.ui_password)
    if not (user_ok and pass_ok):
        raise HTTPException(status_code=401, detail="invalid credentials")


def create_app() -> FastAPI:
    app = FastAPI(title="DFI2 Backend Control Plane", version="0.1.0")

    # SPA static files
    if _UI_DIST.exists():
        app.mount("/ui/assets", StaticFiles(directory=_UI_DIST / "assets"), name="ui-assets")

    demoter = QuietDemoter(service, SETTINGS)

    if SETTINGS.enable_quiet_demoter:
        @app.on_event("startup")
        def _start_demoter() -> None:
            demoter.start()

        @app.on_event("shutdown")
        def _stop_demoter() -> None:
            demoter.stop()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"ok": "true"}

    @app.get("/ui/legacy")
    def ui_legacy(_=Depends(_ui_auth)) -> FileResponse:
        if not UI_INDEX.exists():
            raise HTTPException(status_code=404, detail="UI file not found")
        return FileResponse(UI_INDEX)

    @app.get("/ui")
    @app.get("/ui/{rest:path}")
    def ui_spa(rest: str = "", _=Depends(_ui_auth)):
        if _UI_DIST.exists():
            return FileResponse(_UI_DIST / "index.html")
        raise HTTPException(404, "SPA not built. Run npm run build in ui/soc-dashboard/")

    @app.get("/watchlist", response_model=list[WatchlistEntry])
    def watchlist_list(limit: int = Query(default=200, ge=1, le=5000), _=Depends(_require_api_key)):
        conn = service.sqlite.connect()
        try:
            rows = service.sqlite.list_watchlist(conn, limit=limit)
            return [WatchlistEntry(**row) for row in rows]
        finally:
            conn.close()

    @app.post("/action/annotate", response_model=ApiResponse)
    def action_annotate(req: AnnotateRequest, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"), _=Depends(_require_api_key)):
        rid = _request_id(idempotency_key)
        try:
            res = service.annotate(
                request_id=rid,
                ip=str(req.ip),
                note=req.note,
                tags=req.tags,
                actor=req.actor,
            )
            return ApiResponse(ok=res.ok, request_id=res.request_id, message=res.message)
        except ConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"annotate failed: {exc}") from exc

    @app.post("/watchlist/upsert", response_model=ApiResponse)
    def watchlist_upsert(req: WatchlistUpsertRequest, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"), _=Depends(_require_api_key)):
        rid = _request_id(idempotency_key)
        try:
            res = service.upsert_watchlist(
                request_id=rid,
                ip=str(req.ip),
                capture_depth=req.capture_depth,
                priority=req.priority,
                reason=req.reason,
                source=req.source,
                actor=req.actor,
                expires_at=req.expires_at,
                group_id=req.group_id,
                sub_group_id=req.sub_group_id,
            )
            return ApiResponse(ok=res.ok, request_id=res.request_id, message=res.message)
        except PolicyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"upsert failed: {exc}") from exc

    @app.post("/watchlist/delete", response_model=ApiResponse)
    def watchlist_delete(req: WatchlistDeleteRequest, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"), _=Depends(_require_api_key)):
        rid = _request_id(idempotency_key)
        try:
            res = service.delete_watchlist(
                request_id=rid,
                ip=str(req.ip),
                reason=req.reason,
                actor=req.actor,
            )
            return ApiResponse(ok=res.ok, request_id=res.request_id, message=res.message)
        except ConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"delete failed: {exc}") from exc

    @app.post("/action/bulk", response_model=BulkResponse)
    def action_bulk(req: BulkActionRequest, idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"), _=Depends(_require_api_key)):
        rid = _request_id(idempotency_key)
        try:
            res = service.bulk_action(
                request_id=rid,
                action=req.action,
                ip_list=[str(ip) for ip in req.ip_list],
                campaign_id=req.campaign_id,
                reason=req.reason,
                actor=req.actor,
                source=req.source,
                capture_depth=req.capture_depth,
                priority=req.priority,
                expires_at=req.expires_at,
            )
            return BulkResponse(
                ok=res.ok,
                request_id=res.request_id,
                message=res.message,
                processed=res.processed,
                skipped=res.skipped,
            )
        except ConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"bulk action failed: {exc}") from exc

    # ---- Data read endpoints ----

    @app.get("/data/audit", response_model=list[AuditRow])
    def data_audit(limit: int = Query(default=200, ge=1, le=1000), _=Depends(_require_api_key)):
        try:
            rows = service.get_audit_log(limit)
            return [AuditRow(**r) for r in rows]
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    # ---- ML endpoints ----

    @app.get("/data/ml/stats", response_model=MlModelStats)
    def data_ml_stats(model_name: str = Query(default="xgb_v6"), _=Depends(_require_api_key)):
        try:
            return service.get_ml_stats(model_name, SETTINGS.ml_metrics_dir)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    # ---- Attack Map endpoints ----

    @app.get("/data/map/events", response_model=MapEventsResponse)
    def map_events(
        hours: int = Query(default=1, ge=1, le=168),
        limit: int = Query(default=200, ge=1, le=1000),
        _=Depends(_require_api_key),
    ):
        try:
            data = service.get_map_events(hours=hours, limit=limit)
            return MapEventsResponse(
                attackers=[MapAttacker(**a) for a in data.get("attackers", [])],
                honeypots=data.get("honeypots", []),
                total_attacks=data.get("total_attacks", 0),
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/data/map/heatmap")
    def attack_heatmap(
        days: int = Query(default=7, ge=1, le=30),
        _=Depends(_require_api_key),
    ):
        return service.get_attack_heatmap(days=days)

    @app.get("/data/map/countries")
    def top_countries(
        hours: int = Query(default=24, ge=1, le=168),
        limit: int = Query(default=10, ge=1, le=50),
        _=Depends(_require_api_key),
    ):
        return service.get_top_countries(hours=hours, limit=limit)

    # ---- VM endpoints ----

    @app.get("/vms", response_model=list[VMStatus])
    def vms_list(_=Depends(_require_api_key)):
        try:
            pve = _get_pve()
            vm_list = pve.get_vms()
            vm_by_id = {int(v["vmid"]): v for v in vm_list}

            pub_ips = [info["pub"] for info in VM_MAP.values()]
            flow_data = service.ledger.query_vm_flows(pub_ips)

            result = []
            for vmid, info in VM_MAP.items():
                pve_vm = vm_by_id.get(vmid, {})
                status = pve_vm.get("status", "unknown")
                cpu_pct = float(pve_vm.get("cpu", 0.0)) * 100
                maxmem = int(pve_vm.get("maxmem", 0))
                mem = int(pve_vm.get("mem", 0))
                uptime = int(pve_vm.get("uptime", 0))
                flow_info = flow_data.get(info["pub"], {})
                result.append(VMStatus(
                    vmid=vmid,
                    name=info["name"],
                    lan_ip=info["lan"],
                    pub_ip=info["pub"],
                    os=info["os"],
                    services=info["svcs"],
                    status=status,
                    cpu_pct=round(cpu_pct, 1),
                    ram_used_mb=mem // (1024 * 1024),
                    ram_total_mb=maxmem // (1024 * 1024),
                    uptime_s=uptime,
                    flows_24h=flow_info.get("flows_24h", 0),
                    attackers_24h=flow_info.get("attackers_24h", 0),
                ))
            return result
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/vms/{vmid}/events", response_model=list[VMEvent])
    def vm_events(vmid: int, _=Depends(_require_api_key)):
        info = VM_MAP.get(vmid)
        if not info:
            raise HTTPException(status_code=404, detail="vmid not in VM_MAP")
        try:
            rows = service.ledger.query_vm_events(info["lan"])
            return [VMEvent(**r) for r in rows]
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/vms/{vmid}/reboot", response_model=ApiResponse)
    def vm_reboot(
        vmid: int,
        req: VMRebootRequest,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        _=Depends(_require_api_key),
    ):
        rid = _request_id(idempotency_key)
        info = VM_MAP.get(vmid)
        if not info:
            raise HTTPException(status_code=404, detail="vmid not in VM_MAP")
        try:
            pve = _get_pve()
            pve.reboot_vm(vmid)
            service.ledger.log_analyst_action(
                ip=info["pub"],
                action_type="VM_REBOOT",
                capture_depth=None,
                priority=None,
                reason=req.reason,
                actor=req.actor,
                expires_at=None,
                request_id=rid,
            )
            return ApiResponse(ok=True, request_id=rid, message=f"Reboot task queued for VMID {vmid}")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    # ---- ML Rescore endpoints ----

    @app.get("/data/ml/registry", response_model=list[ModelRegistryEntry])
    def model_registry(_=Depends(_require_api_key)):
        """List all models with training metrics, deploy status, and aliases."""
        try:
            entries = service.get_model_registry()
            return [ModelRegistryEntry(**e) for e in entries]
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/data/ml/models", response_model=list[ModelInfo])
    def ml_models(_=Depends(_require_api_key)):
        from .rescorer import list_models
        try:
            return [ModelInfo(**m) for m in list_models()]
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/data/ml/models/{filename}/download")
    def ml_model_download(
        filename: str,
        api_key: str | None = Query(default=None),
        x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    ):
        # Accept api_key as query param (for direct links) or X-API-Key header
        key = api_key or x_api_key
        if SETTINGS.api_key and key != SETTINGS.api_key:
            raise HTTPException(status_code=401, detail="Unauthorized")
        from .rescorer import MODELS_DIR
        safe = Path(filename).name
        fpath = Path(MODELS_DIR) / safe
        if not fpath.exists():
            raise HTTPException(status_code=404, detail=f"Model not found: {safe}")
        return FileResponse(str(fpath), filename=safe, media_type="application/octet-stream")

    @app.delete("/action/ml/models/{filename}", response_model=ApiResponse)
    def ml_model_delete(filename: str, _=Depends(_require_api_key)):
        from .rescorer import delete_model
        try:
            result = delete_model(filename)
            return ApiResponse(ok=result["ok"], request_id="model-delete", message=result["message"])
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/data/ml/rescore-status", response_model=NormRescoreStatus)
    def ml_rescore_status(
        model_name: str | None = Query(default=None),
        labels: str | None = Query(default=None),
        _=Depends(_require_api_key),
    ):
        from .rescorer import get_status
        try:
            label_list = [int(x) for x in labels.split(",")] if labels else None
            raw = get_status(model_name=model_name, labels=label_list)
            last = raw.get("last_run_results")
            cfg = raw.get("config")
            return NormRescoreStatus(
                status=raw["status"],
                total=raw.get("total", 0),
                scored=raw.get("scored", 0),
                batch=raw.get("batch", 0),
                attack_count=raw.get("attack_count", 0),
                norm_count=raw.get("norm_count", 0),
                unscored_remaining=raw.get("unscored_remaining", 0),
                started_at=raw.get("started_at"),
                finished_at=raw.get("finished_at"),
                elapsed_sec=raw.get("elapsed_sec", 0),
                rate=raw.get("rate", 0),
                error=raw.get("error"),
                last_run_results=NormRescoreLastRun(**last) if last else None,
                config=RescoreConfig(**cfg) if cfg else None,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.post("/action/ml/rescore", response_model=ApiResponse)
    def ml_rescore(req: RescoreRequest, _=Depends(_require_api_key)):
        from .rescorer import start_rescore
        try:
            result = start_rescore(
                model_path=req.model_path,
                model_name=req.model_name,
                model_version=req.model_version,
                labels=req.labels,
                skip_scored=req.skip_scored,
            )
            return ApiResponse(ok=result["ok"], request_id="rescore", message=result["message"])
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    # ---- ML Validation endpoint ----

    @app.get("/data/ml/recon-validation")
    def ml_recon_validation(_=Depends(_require_api_key)):
        import json as _json
        vpath = Path("/opt/dfi2/ml/models/recon_validation_latest.json")
        if not vpath.exists():
            return {}
        with open(vpath) as f:
            return _json.load(f)

    # ---- ML Training endpoints ----

    @app.post("/action/ml/train", response_model=ApiResponse)
    def ml_train(req: TrainRequest, _=Depends(_require_api_key)):
        from .trainer import start_training
        try:
            result = start_training(
                model_type=req.model_type,
                balanced=req.balanced,
                min_conf=req.min_conf,
                hours=req.hours,
                folds=req.folds,
            )
            return ApiResponse(ok=result["ok"], request_id="train", message=result["message"])
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    @app.get("/data/ml/train-status", response_model=TrainStatus)
    def ml_train_status(_=Depends(_require_api_key)):
        from .trainer import get_train_status
        try:
            raw = get_train_status()
            cfg = raw.get("config")
            exp = raw.get("export")
            trn = raw.get("train")
            res = raw.get("result")
            return TrainStatus(
                status=raw.get("status", "idle"),
                phase=raw.get("phase"),
                started_at=raw.get("started_at"),
                config=TrainConfig(**cfg) if cfg else None,
                export=TrainExportProgress(**exp) if exp else None,
                train=TrainTrainProgress(
                    status=trn.get("status", "pending"),
                    current_fold=trn.get("current_fold", 0),
                    total_folds=trn.get("total_folds", 5),
                    folds_completed=[TrainFoldResult(**f) for f in trn.get("folds_completed", [])],
                    elapsed_sec=trn.get("elapsed_sec", 0),
                ) if trn else None,
                result=TrainResult(**res) if res else None,
                error=raw.get("error"),
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    # ── GOD Dashboard endpoints ──────────────────────────────────────────
    register_god_routes(app, service.ledger)

    return app


app = create_app()
