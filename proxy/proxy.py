"""SwarmTrap public API proxy — stats from PV1 + signup endpoint."""
import json
import re
import sqlite3
import time
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional

app = FastAPI(title="SwarmTrap API", docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"])

PV1 = "http://192.168.0.100:8010"
CACHE = {"data": None, "ts": 0}
CACHE_TTL = 60

DB_PATH = Path("/opt/swarmtrap/signups.db")
VALID_ROLES = {"node_operator", "developer", "ml_data_scientist", "security_researcher", "community_governance"}

# In-memory rate limit: {ip: [timestamps]}
_rate: dict[str, list[float]] = {}
RATE_LIMIT = 5        # max signups
RATE_WINDOW = 3600    # per hour


def _init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS signups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            roles TEXT NOT NULL,
            why TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_signups_email ON signups(email)")
    conn.commit()
    conn.close()


_init_db()


def _check_rate(ip: str) -> bool:
    now = time.time()
    times = _rate.get(ip, [])
    times = [t for t in times if now - t < RATE_WINDOW]
    if len(times) >= RATE_LIMIT:
        _rate[ip] = times
        return False
    times.append(now)
    _rate[ip] = times
    return True


class SignupRequest(BaseModel):
    name: str
    email: str
    roles: list[str]
    why: Optional[str] = ""
    website: Optional[str] = ""  # honeypot

    @field_validator("name")
    @classmethod
    def name_check(cls, v):
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("Name required, max 128 chars")
        return v

    @field_validator("email")
    @classmethod
    def email_check(cls, v):
        v = v.strip().lower()
        if not v or len(v) > 256:
            raise ValueError("Email required, max 256 chars")
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
            raise ValueError("Invalid email")
        return v

    @field_validator("roles")
    @classmethod
    def roles_check(cls, v):
        if not v:
            raise ValueError("At least one role required")
        for r in v:
            if r not in VALID_ROLES:
                raise ValueError(f"Invalid role: {r}")
        return v

    @field_validator("why")
    @classmethod
    def why_check(cls, v):
        if v and len(v) > 500:
            raise ValueError("Max 500 chars")
        return v or ""


@app.get("/api/stats")
def stats():
    now = time.time()
    if CACHE["data"] and now - CACHE["ts"] < CACHE_TTL:
        return CACHE["data"]

    try:
        overview = httpx.get(f"{PV1}/data/god/overview", timeout=10).json()
        training = httpx.get(f"{PV1}/data/god/training", timeout=10).json()

        result = {
            "ips_tracked": overview.get("total_ips", 0),
            "confirmed_attackers": overview.get("evidence_count", 0),
            "honeypot_sensors": 69,
            "evidence_events": overview.get("evidence_count", 0),
            "model_accuracy": 99.53,
            "training_samples": training.get("total_captured", 0),
        }
        CACHE["data"] = result
        CACHE["ts"] = now
        return result
    except Exception:
        if CACHE["data"]:
            return CACHE["data"]
        return {
            "ips_tracked": 2762332,
            "confirmed_attackers": 63122,
            "honeypot_sensors": 69,
            "evidence_events": 63122,
            "model_accuracy": 99.53,
            "training_samples": 15042203,
        }


@app.post("/api/signup")
async def signup(req: SignupRequest, request: Request):
    # Honeypot check — bots fill this, humans don't see it
    if req.website:
        return {"status": "ok", "message": "Welcome to SwarmTrap."}

    # Rate limit
    ip = request.client.host if request.client else "unknown"
    if not _check_rate(ip):
        return JSONResponse(status_code=429, content={"error": "Too many signups. Try again later."})

    # Store signup
    conn = sqlite3.connect(str(DB_PATH))
    try:
        conn.execute(
            "INSERT INTO signups (name, email, roles, why, ip_address) VALUES (?, ?, ?, ?, ?)",
            (req.name, req.email, json.dumps(req.roles), req.why, ip),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return {"status": "ok", "message": "Welcome to SwarmTrap."}
    conn.close()

    return {"status": "ok", "message": "Welcome to SwarmTrap."}
