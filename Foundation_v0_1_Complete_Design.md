# Foundation v0.1 — Complete Design

### The First Buildable Release of Open Utopia's Infrastructure Platform

**Design Document — April 2026**

*This document turns the Foundation Initial Specification into a buildable system. It defines the decentralized hardware platform, open-source software stack, data model, API, security architecture, Tri-Key deployment authorization, and repo structure for the first open-source release.*

*Founders: Charles Chen, Claude (Anthropic)*

---

## Scope of v0.1

Foundation v0.1 implements two things: **the Ledger** and **the API that reads and writes it**. Everything else in the Foundation spec — Communication, Voting, Distribution, AI Layer — builds on top of this. The Ledger is the foundation of Foundation.

v0.1 delivers:

1. **The Decentralized Hardware Platform** — globally distributed, multi-tier node infrastructure running 100% open-source software, shared with SwarmTrap's AIO honeypot network
2. **The Ledger** — append-only, hash-chained, publicly auditable contribution record, replicated across multiple independent nodes
3. **The API** — RESTful service for recording contributions, querying balances, and exporting the full ledger for independent verification
4. **The Web UI** — minimal dashboard showing the ledger, contributor balances, and token state
5. **The CLI** — command-line tool for contributors to interact with the ledger directly
6. **The Verifier** — standalone tool that downloads the ledger and independently recomputes every balance, confirming integrity
7. **The Tri-Key Gate** — Shamir's Secret Sharing deployment authorization requiring all three functions (Provider, Consumer, Bridge) to approve code changes

This maps to the spec's "Month 2-3" milestone: *"The first module of Foundation comes online. Contributions are now tracked in the platform's own ledger. Manual P/C/B tagging continues, but the ledger is auditable and hash-chained."*

---

## Design Principles (from the Spec, Applied Here)

Every decision in this document is traceable to the Six Trust Principles:

| Principle | How v0.1 Implements It |
|---|---|
| AI Suggests, Humans Confirm | v0.1 has no AI. All classification is manual. AI comes in v0.3+. |
| Every AI Decision Is Explainable | N/A for v0.1. The data model includes explanation fields for future use. |
| AI Layer Is Separable | The entire system works without AI from day one. |
| Multiple Independent Auditors | The Verifier tool lets anyone audit. The ledger export is a public endpoint. |
| Ledger Is Source of Truth | The ledger is the only stateful component. Everything else derives from it. |
| Fork as Ultimate Audit | Single `docker compose up` deploys the full stack. Ledger is exportable as JSON. Any node can become an independent instance. |

---

## The Decentralized Hardware Platform

### The Problem with Centralized Infrastructure

If Foundation runs on a single server — even if the software is open source and the ledger is hash-chained — the platform operator controls the physical hardware. They can intercept network traffic, modify memory, swap binaries between Tri-Key deployments, or simply unplug the machine. Open-source software on centralized hardware is a half-measure. The spec says: *"Whoever controls it controls everything."* That includes whoever controls the metal.

Foundation must run on **decentralized, contributor-operated hardware** where no single person, company, or datacenter can take the system offline or silently compromise it.

### The Dual-Purpose Insight

SwarmTrap already requires a globally distributed network of cheap VMs running AIO honeypot nodes — hundreds of machines across dozens of countries at $2–6/month each. These machines have CPU, RAM, storage, and network capacity that isn't fully consumed by honeypot operations. Foundation's infrastructure needs (ledger replication, API serving, static web hosting, background verification) are lightweight. The same nodes that capture attacker traffic can simultaneously serve as Foundation infrastructure.

This is not a coincidence. It is the structural advantage of building the platform and the first project together. SwarmTrap pays for the infrastructure. Foundation rides on it. The incremental cost of running Foundation across the honeypot network is near zero — and the decentralization comes for free.

### Node Architecture

Every machine in the network runs the **Foundation Node Agent** — a lightweight daemon that participates in the distributed platform alongside whatever primary workload the machine serves (honeypot, ML training, customer service, etc.).

**Four node tiers based on hardware capability:**

```
TIER        HARDWARE SPEC                  ROLE IN FOUNDATION              ROLE IN SWARMTRAP         EXAMPLE HOSTS
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Sentinel    1 vCPU, 512MB–1GB RAM          Ledger read replica,           AIO honeypot node         $2–6/mo VMs:
            10–20GB SSD                    chain verification witness,                               Vultr, Hetzner,
                                           health heartbeat                                          DO, OVH, Oracle
                                                                                                     /Google free tier

Keeper      2–4 vCPU, 4–8GB RAM            Ledger full replica,           AIO node + syslog         $10–30/mo VMs:
            50–100GB SSD                   API read endpoint,             correlation engine,        Hetzner CX,
                                           background chain verification,  conversation assembly     Vultr High Freq
                                           Verifier auto-runs

Guardian    4–8 vCPU, 16–32GB RAM          Primary write node (one of     Central aggregation,      $40–100/mo:
            200GB+ NVMe                    3+), API write endpoint,       ClickHouse analytics,     Hetzner dedicated,
                                           full API service,              model serving              Vultr Bare Metal
                                           PostgreSQL primary/replica

Forge       8+ vCPU, 32–128GB RAM          ML training workloads          CNN/XGBoost training,     Charles's datacenter,
            GPU (NVIDIA T4/A10/L4+)        (AI classification layer       DFI model training,       cloud GPU instances
            500GB+ NVMe                    in v0.3+), heavy compute       batch inference            (Lambda, RunPod,
                                                                                                     Vast.ai)
```

**Every tier runs the same Foundation Node Agent.** The agent detects available resources and self-configures its role. A Sentinel with 512MB RAM knows it can only maintain a partial ledger index and serve as a verification witness. A Guardian with 32GB RAM knows it can run the full PostgreSQL primary. The node agent is one binary — the hardware determines the role, not a separate installation.

### The Open-Source Hardware Stack

**Every layer of the software stack — from operating system to application — must be open source.** No proprietary firmware, no closed-source drivers, no commercial software anywhere in the platform. This is Article IV (Radical Transparency) applied to infrastructure.

```
LAYER               OPEN-SOURCE CHOICE           REPLACES
────────────────────────────────────────────────────────────────────
Operating System    Debian 12 / Ubuntu 24 LTS    N/A (already open)
Kernel              Linux 6.x mainline           N/A
Container Runtime   Docker CE / Podman           Docker Desktop (proprietary parts)
Orchestration       Docker Compose (v0.1)        Kubernetes (later versions)
                    Nomad / K3s (v0.3+)
Reverse Proxy       Caddy                        Nginx Plus, HAProxy Enterprise
Database            PostgreSQL 16                Any commercial DB
Replication         PostgreSQL streaming +       Commercial replication
                    Patroni (HA failover)
Message Queue       NATS                         Kafka (complex), RabbitMQ (sufficient
                                                 but NATS is simpler for this use case)
Monitoring          Prometheus + Grafana          Datadog, New Relic
Logging             Vector + Loki                Splunk, Elastic Cloud
DNS                 CoreDNS / PowerDNS           Route 53, Cloudflare DNS
TLS Certificates    Let's Encrypt (via Caddy)    Commercial CAs
Secrets             SOPS + age                   Vault Enterprise, AWS Secrets Manager
CI/CD               Gitea Actions (self-hosted)  GitHub Actions (runs on Microsoft)
Code Hosting        Gitea (self-hosted)          GitHub, GitLab SaaS
Communication       Matrix (Synapse/Conduit)     Discord, Slack
GPU Compute         ROCm / CUDA (open driver)    Proprietary cloud GPU APIs
ML Framework        PyTorch (open source)        N/A
```

**Why Gitea over GitHub?** GitHub is owned by Microsoft. Every commit, every PR, every CI run flows through infrastructure a single company controls. For bootstrapping (v0.1), we mirror to GitHub for visibility and contributor access. But the canonical repository lives on self-hosted Gitea running on Foundation's own nodes. The migration path: GitHub mirror → Gitea primary with GitHub mirror → Gitea only (once contributor tools are mature).

**Why NATS?** The distributed node network needs a lightweight message bus for: ledger entry propagation (new entry on the primary → broadcast to all replicas), node health heartbeats, chain verification results, and Tri-Key authorization coordination. NATS is open source, single-binary, zero-dependency, and handles exactly this workload profile. It's not a database. It's not a queue. It's a nervous system.

### Distributed Ledger Architecture

The ledger is still PostgreSQL — not blockchain. But it's now **replicated across multiple Guardian nodes** with streaming replication, and **verified by every Sentinel and Keeper node** in the network.

```
                    ┌─────────────────────┐
                    │  Guardian Node #1   │  PostgreSQL PRIMARY
                    │  (Charles DC)       │  Accepts writes
                    └──────────┬──────────┘
                               │ Streaming replication
              ┌────────────────┼────────────────┐
              │                │                │
    ┌─────────┴─────┐  ┌──────┴────────┐  ┌───┴──────────┐
    │ Guardian #2   │  │ Guardian #3   │  │ Guardian #4  │
    │ (EU region)   │  │ (APAC region) │  │ (US-West)    │
    │ PG REPLICA    │  │ PG REPLICA    │  │ PG REPLICA   │
    │ API read+write│  │ API read+write│  │ API read+write│
    │ (promotes if  │  │               │  │              │
    │  primary dies)│  │               │  │              │
    └───────┬───────┘  └───────┬───────┘  └──────┬───────┘
            │                  │                  │
     NATS mesh (all nodes interconnected)
            │                  │                  │
    ┌───────┴──┐  ┌───────┐  ┌┴──────┐  ┌───────┴──┐
    │Keeper    │  │Keeper │  │Keeper │  │Keeper    │
    │(DE)      │  │(SG)   │  │(BR)   │  │(US-E)    │
    │read API  │  │read   │  │read   │  │read API  │
    │verify    │  │verify │  │verify │  │verify    │
    └──────────┘  └───────┘  └───────┘  └──────────┘
         │            │           │           │
    ┌────┴────┐  ┌────┴───┐  ┌───┴────┐  ┌───┴─────┐
    │Sentinel │  │Sentinel│  │Sentinel│  │Sentinel │
    │(VPS x50)│  │(x30)   │  │(x20)   │  │(x40)    │
    │witness  │  │witness │  │witness │  │witness  │
    └─────────┘  └────────┘  └────────┘  └─────────┘
```

**Write path:** A contributor submits an entry via API → hits any Guardian → if not the primary, forwards to primary → primary appends to ledger with hash chain → streams to all replicas → NATS broadcasts entry to all Keepers and Sentinels → every node independently verifies the hash.

**Read path:** Any Keeper or Guardian can serve read requests. Geographic DNS routing sends contributors to the nearest node. The data is eventually consistent (replication lag is typically < 1 second).

**Failover:** Patroni manages automatic failover. If the primary Guardian goes down, another Guardian promotes to primary. The Tri-Key mechanism still gates deployments — failover changes which node is primary, not what code runs on it.

**Sentinel verification (the "witness network"):** Every Sentinel node periodically downloads the latest ledger entries via NATS and verifies the hash chain independently. A Sentinel is too small to store the full ledger — it maintains a rolling window (last 10,000 entries + all entry hashes). If any Sentinel detects a chain break, it broadcasts an alert to the entire NATS mesh. With hundreds of Sentinels across dozens of countries and providers, silently corrupting the chain requires compromising ALL of them simultaneously.

### Node Identity and Trust

Every node has a cryptographic identity:

```
NODE IDENTITY:
  node_id:        UUID (generated at first boot)
  node_tier:      sentinel | keeper | guardian | forge
  public_key:     Ed25519 (generated at first boot, private key stays on node)
  operator_id:    UUID of the contributor who operates this node
  location:       geographic region (self-reported, verified by latency probes)
  provider:       hosting provider (Hetzner, Vultr, etc.)
  joined_at:      timestamp of first registration
```

Nodes register with the network by signing a registration message with their private key. Node operation is **Provider work** — operators earn SCT/FCT tokens for uptime, verification work, and data served.

**Anti-concentration for nodes:** No single operator may run more than 20% of Guardian nodes. No single hosting provider may host more than 40% of Guardian nodes. These thresholds are governable by contributor vote.

### Resource Allocation on Dual-Purpose Nodes

On a typical $5/month Sentinel (1 vCPU, 1GB RAM, 25GB SSD):

```
PROCESS                     CPU (avg)    RAM        DISK         PRIORITY
────────────────────────────────────────────────────────────────────────────
AIO Honeypot Services       30-40%       200MB      2GB logs     PRIMARY
Foundation Node Agent       5-10%        100MB      500MB index  SECONDARY
  └── Chain witness          1%          50MB       rolling      BACKGROUND
  └── NATS client            1%          20MB       —            BACKGROUND
  └── Health heartbeat       <1%         10MB       —            BACKGROUND
OS + overhead               10%          200MB      3GB          SYSTEM
────────────────────────────────────────────────────────────────────────────
REMAINING HEADROOM          40-55%       ~400MB     ~19GB
```

SwarmTrap's honeypot workload is I/O-bound (network connections), not CPU-bound. Foundation's witness workload is negligible — hash a few entries per minute. The two workloads coexist comfortably with headroom to spare.

On a Guardian ($50–100/month, 8 vCPU, 32GB RAM):

```
PROCESS                     CPU (avg)    RAM        DISK         PRIORITY
────────────────────────────────────────────────────────────────────────────
PostgreSQL (replica/primary) 15-25%      8GB        50GB+        PRIMARY
Foundation API Server        10-15%      2GB        —            PRIMARY
AIO Honeypot Services        10-15%      500MB      5GB logs     SECONDARY
ClickHouse (SwarmTrap)       10-20%      4GB        50GB+        SECONDARY
NATS Server                  2-5%        200MB      —            INFRASTRUCTURE
Caddy Reverse Proxy          1-3%        100MB      —            INFRASTRUCTURE
Monitoring (Prometheus)       2-5%        500MB      5GB          INFRASTRUCTURE
────────────────────────────────────────────────────────────────────────────
REMAINING HEADROOM           ~25%        ~16GB      ~80GB+
```

On a Forge (GPU node, Charles's datacenter):

```
PROCESS                     CPU         RAM         GPU          DISK
────────────────────────────────────────────────────────────────────────────
ML Training Jobs             40-80%     16-64GB     80-100%      100GB+
  └── CNN v2 training
  └── XGBoost model builds
  └── AI classification (v0.3+)
Foundation Node Agent         5%        200MB       —            1GB
AIO Honeypot (if applicable)  5%        200MB       —            2GB
────────────────────────────────────────────────────────────────────────────
```

GPU nodes are primarily compute infrastructure. They participate in the Foundation network as witnesses but their main purpose is ML workloads — both SwarmTrap's DFI models and Foundation's future AI classification layer.

### The Open-Source Supply Chain

Every binary, every library, every tool running on Foundation nodes must be traceable to open-source code. The supply chain is:

```
SOURCE CODE (public repo)
    │
    ▼
REPRODUCIBLE BUILD (Gitea Actions, self-hosted runners on Foundation nodes)
    │
    ▼
SIGNED ARTIFACT (Docker image, signed by 2+ maintainers)
    │
    ▼
TRI-KEY AUTHORIZED (all three function keyholders approve)
    │
    ▼
DEPLOYED TO NODES (via Foundation's own deployment system)
    │
    ▼
VERIFIED BY WITNESSES (every Sentinel confirms image digest matches)
```

No step in this chain touches proprietary infrastructure. No step requires trusting a single company. The entire path from source code to running binary is auditable, reproducible, and decentralized.

---

## Tech Stack

The full open-source software stack running on the decentralized hardware:

```
LAYER               TECHNOLOGY              WHY
─────────────────────────────────────────────────────────────────
OS                  Debian 12 / Ubuntu 24   Stable, well-supported, open source
Container Runtime   Docker CE / Podman      Open source container runtime
Orchestration       Docker Compose (v0.1)   Single command per node. Nomad/K3s later.

Database            PostgreSQL 16           ACID, streaming replication, append-only
                                            enforcement via role permissions.
Replication         Patroni + pg_replication Automatic failover, multi-Guardian HA.
Message Bus         NATS                    Lightweight, single-binary, open source.
                                            Node-to-node ledger propagation and
                                            witness coordination.

API                 Python 3.12 + FastAPI   Async, typed, auto-generates OpenAPI docs.
Web UI              React + Vite            Lightweight SPA, huge contributor pool.
CLI                 Python (Click)          Same language as API.
Verifier            Python (standalone)     MIT-licensed. Zero dependency on platform.

Reverse Proxy       Caddy                   Auto-TLS, open source, simple config.
Monitoring          Prometheus + Grafana    Industry standard, open source.
Logging             Vector + Loki           Lightweight log pipeline, open source.
Code Hosting        Gitea (self-hosted)     No dependency on GitHub/GitLab SaaS.
CI/CD               Gitea Actions           Self-hosted runners on Foundation nodes.
Communication       Matrix (Conduit)        Replaces Discord/Slack dependency.
Secrets             SOPS + age              Encrypted secrets in Git, no Vault needed.

Hash Chain          SHA-256                 Industry standard, well-understood.
Tri-Key             Shamir's SSS            Proven 1979 cryptographic scheme.
Node Identity       Ed25519                 Fast, secure, small key size.
```

**What we deliberately don't use:**

- No blockchain (per spec: "unnecessary consensus overhead")
- No proprietary databases (no Aurora, no Cloud SQL)
- No proprietary CI/CD (no GitHub Actions for canonical builds)
- No proprietary monitoring (no Datadog, no New Relic)
- No proprietary communication (no Discord, no Slack)
- No proprietary DNS (no Cloudflare, no Route 53 — self-hosted CoreDNS/PowerDNS)
- No ClickHouse in Foundation (SwarmTrap uses it for analytics; Foundation's data model is relational)
- No microservices (monolith per node is correct at this scale)
- No Kubernetes for v0.1 (Docker Compose per node; K3s/Nomad for multi-node orchestration in v0.3+)

---

## Data Model

### The Ledger Entry

The atomic unit. Every contribution, correction, vote, and distribution is a ledger entry.

```sql
CREATE TABLE ledger_entries (
    -- Identity
    id              BIGSERIAL PRIMARY KEY,
    entry_hash      CHAR(64) NOT NULL UNIQUE,       -- SHA-256 of this entry
    prev_hash       CHAR(64) NOT NULL,               -- SHA-256 of previous entry (genesis = '0' * 64)

    -- Who
    contributor_id  UUID NOT NULL REFERENCES contributors(id),

    -- When
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    epoch           VARCHAR(7) NOT NULL,             -- e.g. '2026-Q2' — the quarter

    -- What
    entry_type      VARCHAR(32) NOT NULL,            -- 'contribution', 'correction', 'distribution', 'vote'
    contribution_type VARCHAR(128),                  -- specific work type, e.g. 'code_commit', 'support_response'

    -- Classification
    function_tag    VARCHAR(8) NOT NULL,             -- 'P', 'C', or 'B'
    revenue_path    INTEGER,                         -- 1-11 for SwarmTrap, NULL for Foundation-internal

    -- Value
    token_amount    NUMERIC(18, 4) NOT NULL DEFAULT 0,
    quality_score   NUMERIC(5, 4),                   -- 0.0000 to 1.0000, NULL if not assessed
    confidence      NUMERIC(5, 4),                   -- AI confidence (NULL in v0.1, all manual)

    -- Classification provenance
    classified_by   VARCHAR(16) NOT NULL DEFAULT 'manual',  -- 'manual', 'ai_suggested', 'ai_confirmed'
    confirmed_by    UUID REFERENCES contributors(id),        -- who confirmed (NULL if self-reported)
    explanation     TEXT,                             -- human-readable classification reason

    -- Correction chain
    corrects_entry  BIGINT REFERENCES ledger_entries(id),  -- if this corrects a prior entry
    correction_reason TEXT,
    authorized_by   VARCHAR(64),                     -- 'contributor', 'peer_review', 'tribunal_tier_N'

    -- Integrity
    CHECK (entry_type IN ('contribution', 'correction', 'distribution', 'vote', 'system')),
    CHECK (function_tag IN ('P', 'C', 'B')),
    CHECK (classified_by IN ('manual', 'ai_suggested', 'ai_confirmed'))
);

-- Append-only enforcement: no UPDATE or DELETE allowed via application.
-- PostgreSQL row-level security + revoke UPDATE/DELETE on the role.

CREATE INDEX idx_ledger_contributor ON ledger_entries(contributor_id);
CREATE INDEX idx_ledger_epoch ON ledger_entries(epoch);
CREATE INDEX idx_ledger_function ON ledger_entries(function_tag);
CREATE INDEX idx_ledger_path ON ledger_entries(revenue_path);
CREATE INDEX idx_ledger_type ON ledger_entries(entry_type);
```

### Contributors

```sql
CREATE TABLE contributors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    handle          VARCHAR(64) NOT NULL UNIQUE,
    display_name    VARCHAR(128) NOT NULL,
    email           VARCHAR(256) UNIQUE,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    status          VARCHAR(16) NOT NULL DEFAULT 'active',
    api_key_hash    CHAR(64),                        -- SHA-256 of their API key

    CHECK (status IN ('active', 'inactive', 'suspended'))
);
```

### Cooperative Configuration

Each cooperative running on Foundation has its own configuration. This is **data, not code** — per the spec.

```sql
CREATE TABLE cooperatives (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            VARCHAR(64) NOT NULL UNIQUE,      -- e.g. 'foundation', 'swarmtrap'
    name            VARCHAR(256) NOT NULL,
    token_symbol    VARCHAR(8) NOT NULL,               -- 'FCT', 'SCT'
    distribution_share NUMERIC(5, 4) NOT NULL DEFAULT 0.9000,  -- 90%
    executive_share NUMERIC(5, 4) NOT NULL DEFAULT 0.1000,     -- 10% of distribution pool
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE contribution_types (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cooperative_id  UUID NOT NULL REFERENCES cooperatives(id),
    slug            VARCHAR(128) NOT NULL,
    display_name    VARCHAR(256) NOT NULL,
    function_tag    VARCHAR(8) NOT NULL,               -- default P/C/B for this type
    revenue_path    INTEGER,
    base_tokens     NUMERIC(18, 4) NOT NULL DEFAULT 1.0,
    description     TEXT,

    UNIQUE(cooperative_id, slug),
    CHECK (function_tag IN ('P', 'C', 'B'))
);
```

### Token Decay

Tokens decay per the Open Utopia framework. Decay is computed at query time, not stored — the ledger records the original grant, and the decay formula is applied when calculating active balances.

```sql
CREATE TABLE decay_config (
    cooperative_id  UUID NOT NULL REFERENCES cooperatives(id),
    decay_model     VARCHAR(32) NOT NULL DEFAULT 'linear',  -- 'linear', 'exponential', 'step'
    half_life_epochs INTEGER NOT NULL DEFAULT 8,             -- quarters until 50% decay
    floor_pct       NUMERIC(5, 4) NOT NULL DEFAULT 0.1000,  -- minimum 10% retained forever

    UNIQUE(cooperative_id)
);
```

### Node Registry

Every node in the decentralized network is tracked in the registry:

```sql
CREATE TABLE nodes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    operator_id     UUID NOT NULL REFERENCES contributors(id),
    tier            VARCHAR(16) NOT NULL,            -- 'sentinel', 'keeper', 'guardian', 'forge'
    public_key      TEXT NOT NULL,                    -- Ed25519 public key (base64)
    hostname        VARCHAR(256),
    ip_address      INET,
    region          VARCHAR(64),                      -- e.g. 'us-east', 'eu-west', 'apac-sg'
    provider        VARCHAR(64),                      -- e.g. 'hetzner', 'vultr', 'self-hosted'
    cpu_cores       INTEGER,
    ram_mb          INTEGER,
    disk_gb         INTEGER,
    has_gpu         BOOLEAN NOT NULL DEFAULT false,
    gpu_model       VARCHAR(128),                     -- e.g. 'NVIDIA T4', 'NVIDIA A10'
    gpu_vram_gb     INTEGER,
    status          VARCHAR(16) NOT NULL DEFAULT 'active',
    last_heartbeat  TIMESTAMPTZ,
    joined_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    
    -- Dual-purpose tracking
    runs_swarmtrap  BOOLEAN NOT NULL DEFAULT false,   -- also running AIO honeypot
    runs_foundation BOOLEAN NOT NULL DEFAULT true,

    CHECK (tier IN ('sentinel', 'keeper', 'guardian', 'forge')),
    CHECK (status IN ('active', 'degraded', 'offline', 'deregistered'))
);

CREATE INDEX idx_nodes_tier ON nodes(tier);
CREATE INDEX idx_nodes_operator ON nodes(operator_id);
CREATE INDEX idx_nodes_status ON nodes(status);
```

---

## Hash Chain Mechanics

Every ledger entry is hashed. The hash input is a deterministic canonical JSON of the entry's immutable fields:

```python
import hashlib, json

def compute_entry_hash(entry: dict, prev_hash: str) -> str:
    """Compute SHA-256 hash for a ledger entry."""
    canonical = json.dumps({
        "prev_hash": prev_hash,
        "contributor_id": str(entry["contributor_id"]),
        "created_at": entry["created_at"].isoformat(),
        "epoch": entry["epoch"],
        "entry_type": entry["entry_type"],
        "contribution_type": entry["contribution_type"],
        "function_tag": entry["function_tag"],
        "revenue_path": entry["revenue_path"],
        "token_amount": str(entry["token_amount"]),
        "quality_score": str(entry["quality_score"]) if entry["quality_score"] else None,
        "classified_by": entry["classified_by"],
        "confirmed_by": str(entry["confirmed_by"]) if entry["confirmed_by"] else None,
        "corrects_entry": entry["corrects_entry"],
    }, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()
```

The genesis entry has `prev_hash = "0" * 64`. Every subsequent entry chains from the previous. Any modification to any entry breaks the chain from that point forward — detectable by the Verifier.

---

## API Design

Base URL: `/api/v1`

### Ledger Endpoints

```
POST   /entries                  Record a new contribution (requires auth)
GET    /entries                  List entries (paginated, filterable)
GET    /entries/{id}             Get single entry with full detail
GET    /entries/export           Export full ledger as JSON (public, no auth)
GET    /entries/verify           Run chain verification, return result
```

### Contributor Endpoints

```
GET    /contributors             List contributors
GET    /contributors/{id}        Get contributor profile
GET    /contributors/{id}/balance   Get active token balance (with decay applied)
GET    /contributors/{id}/history   Get contribution history
GET    /contributors/{id}/audit     Personal verification report
POST   /contributors             Register new contributor (admin only in v0.1)
```

### Cooperative Endpoints

```
GET    /cooperatives             List cooperatives
GET    /cooperatives/{slug}      Get cooperative config
GET    /cooperatives/{slug}/balances   All contributor balances for this cooperative
GET    /cooperatives/{slug}/stats      Aggregate stats (total tokens, by function, by path)
```

### System Endpoints

```
GET    /health                   Health check
GET    /chain/status             Chain integrity status (last hash, entry count, last verified)
GET    /system/attestation       Deployment attestation (commit, image digest, Tri-Key authorization)
```

### Node Network Endpoints

```
GET    /nodes                    List all registered nodes (with health status)
GET    /nodes/{id}               Get node details
GET    /nodes/map                Geographic distribution summary
GET    /nodes/witnesses          Current witness count and recent verification results
POST   /nodes/register           Register a new node (requires node Ed25519 signature)
POST   /nodes/{id}/heartbeat     Node health heartbeat (requires node signature)
```

### Example: Recording a Contribution

```bash
curl -X POST https://foundation.openutopia.org/api/v1/entries \
  -H "Authorization: Bearer fct_abc123..." \
  -H "Content-Type: application/json" \
  -d '{
    "cooperative": "swarmtrap",
    "contribution_type": "code_commit",
    "function_tag": "P",
    "revenue_path": 2,
    "token_amount": 15.0,
    "explanation": "Implemented CNN v2 training pipeline for DFI models"
  }'
```

Response:

```json
{
  "id": 1042,
  "entry_hash": "a3f8c2...",
  "prev_hash": "7b1d9e...",
  "contributor_id": "550e8400-...",
  "epoch": "2026-Q2",
  "entry_type": "contribution",
  "contribution_type": "code_commit",
  "function_tag": "P",
  "revenue_path": 2,
  "token_amount": "15.0000",
  "classified_by": "manual",
  "created_at": "2026-04-06T14:30:00Z",
  "receipt": {
    "entry_hash": "a3f8c2d1e9b4...",
    "chain_position": 1042,
    "your_active_balance": {
      "total": "4,215.0000 SCT",
      "by_function": {"P": "3,100.0000", "C": "215.0000", "B": "900.0000"}
    }
  }
}
```

### Example: Full Ledger Export

```bash
curl https://foundation.openutopia.org/api/v1/entries/export > ledger.json
```

Returns every entry, in order, with hashes. Anyone can download this and run the Verifier.

---

## The Verifier

A standalone Python script — not part of the server. Anyone can run it. Licensed under MIT separately from the platform (AGPLv3) so that verification has zero barriers.

```
foundation-verify ledger.json
```

What it does:

1. Loads the exported ledger JSON
2. Checks genesis entry has `prev_hash = "0" * 64`
3. For every subsequent entry, recomputes the hash from the canonical fields and confirms it matches `entry_hash`
4. Confirms each entry's `prev_hash` matches the previous entry's `entry_hash`
5. Recomputes every contributor's active token balance (applying decay)
6. Compares computed balances against the balances reported by the API
7. Reports: chain integrity (pass/fail), balance discrepancies (list), total entries verified

If the chain is intact and balances match, the ledger is honest. If anything diverges, someone has tampered.

```
$ foundation-verify ledger.json --compare-api https://foundation.openutopia.org

Foundation Ledger Verification Report
======================================
Entries verified:     1,042
Chain integrity:      PASS (all hashes valid)
Balance check:        PASS (all 47 contributors match)
Decay model:          linear, half_life=8, floor=0.10
Last entry hash:      a3f8c2d1e9...
Verification time:    0.34s

✓ Ledger is consistent and verifiable.
```

---

## Web UI (v0.1 — Minimal)

The UI is a read-heavy dashboard. In v0.1, contribution recording happens via CLI or API. The UI shows:

**Dashboard page:**
- Total entries, total contributors, chain integrity status
- Recent entries (last 50, live-updating via polling)
- Token distribution by function (P/C/B pie chart)
- Token distribution by revenue path (bar chart)

**Ledger page:**
- Full paginated entry list with filters (contributor, function, path, epoch, type)
- Each entry expandable to show hash, prev_hash, explanation, classification provenance
- "Export Full Ledger" button (triggers `/entries/export`)

**Contributor page:**
- Profile, join date, status
- Active token balance (with decay applied), breakdown by function and path
- Contribution history timeline
- Function ratio visualization (what % of their work is P vs C vs B)

**Cooperative page:**
- Config display (token symbol, distribution/executive shares, decay params)
- Contribution type registry
- Aggregate stats

**No login in v0.1 UI.** The ledger is public. The UI is a read-only window into public data. Write operations go through CLI/API with API keys.

---

## CLI Design

```bash
# Install
pip install foundation-cli

# Configure
foundation config set api-url https://foundation.openutopia.org
foundation config set api-key fct_abc123...

# Record a contribution
foundation contribute \
  --coop swarmtrap \
  --type code_commit \
  --function P \
  --path 2 \
  --tokens 15 \
  --note "Implemented CNN v2 training pipeline"

# Check your balance
foundation balance
foundation balance --by-path
foundation balance --by-function

# Browse the ledger
foundation ledger --last 20
foundation ledger --contributor charles --epoch 2026-Q2

# Export and verify
foundation export > ledger.json
foundation verify ledger.json

# Cooperative info
foundation coop info swarmtrap
foundation coop types swarmtrap   # list contribution types
```

---

## Repository Structure

```
foundation/
├── LICENSE                      # AGPLv3 — copyleft ensures forks stay open
├── README.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── docker-compose.yml           # Single-node development setup
├── docker-compose.guardian.yml  # Guardian node production config
├── docker-compose.keeper.yml   # Keeper node production config
├── docker-compose.sentinel.yml # Sentinel node production config
├── .env.example
├── install.sh                   # One-command node deployment script
│
├── agent/                       # Foundation Node Agent (runs on every node)
│   ├── pyproject.toml
│   └── foundation_agent/
│       ├── __init__.py
│       ├── main.py              # Agent daemon entry point
│       ├── identity.py          # Ed25519 node identity generation/management
│       ├── discovery.py         # Resource detection, auto-tier assignment
│       ├── nats_client.py       # NATS mesh connection, ledger propagation
│       ├── witness.py           # Chain verification witness (Sentinel role)
│       ├── heartbeat.py         # Health reporting to the mesh
│       └── config.py
│
├── api/                         # Python FastAPI backend
│   ├── pyproject.toml
│   ├── foundation/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI app
│   │   ├── config.py            # Settings from environment
│   │   ├── models/
│   │   │   ├── ledger.py        # SQLAlchemy models
│   │   │   ├── contributor.py
│   │   │   ├── cooperative.py
│   │   │   └── node.py          # Node registry model
│   │   ├── schemas/
│   │   │   ├── ledger.py        # Pydantic request/response schemas
│   │   │   ├── contributor.py
│   │   │   ├── cooperative.py
│   │   │   └── node.py
│   │   ├── routers/
│   │   │   ├── entries.py
│   │   │   ├── contributors.py
│   │   │   ├── cooperatives.py
│   │   │   ├── nodes.py         # Node registry and health endpoints
│   │   │   └── system.py
│   │   ├── services/
│   │   │   ├── ledger.py        # Hash chain logic, entry creation
│   │   │   ├── balance.py       # Decay computation, balance queries
│   │   │   ├── verify.py        # Chain verification
│   │   │   └── replication.py   # Ledger propagation via NATS
│   │   ├── auth.py              # API key authentication
│   │   └── db.py                # Database session management
│   ├── alembic/                 # Database migrations
│   │   └── versions/
│   └── tests/
│       ├── test_ledger.py
│       ├── test_hash_chain.py
│       ├── test_balance.py
│       ├── test_verify.py
│       └── test_replication.py
│
├── web/                         # React frontend
│   ├── package.json
│   ├── vite.config.ts
│   ├── src/
│   │   ├── App.tsx
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Ledger.tsx
│   │   │   ├── Contributor.tsx
│   │   │   ├── Cooperative.tsx
│   │   │   └── Network.tsx      # Node map, health status, witness count
│   │   ├── components/
│   │   │   ├── EntryRow.tsx
│   │   │   ├── BalanceCard.tsx
│   │   │   ├── FunctionChart.tsx
│   │   │   ├── ChainStatus.tsx
│   │   │   └── NodeMap.tsx      # Geographic node distribution visualization
│   │   └── api/
│   │       └── client.ts
│   └── public/
│
├── cli/                         # Python CLI
│   ├── pyproject.toml
│   └── foundation_cli/
│       ├── __init__.py
│       ├── main.py
│       ├── commands/
│       │   ├── contribute.py
│       │   ├── balance.py
│       │   ├── ledger.py
│       │   ├── verify.py
│       │   ├── coop.py
│       │   └── node.py          # Node management commands
│       └── config.py
│
├── verifier/                    # Standalone verification tool (MIT licensed)
│   ├── LICENSE                  # MIT — no barriers to auditing
│   ├── pyproject.toml
│   └── foundation_verifier/
│       ├── __init__.py
│       ├── verify.py
│       └── decay.py
│
├── trikey/                      # Tri-Key deployment authorization
│   ├── pyproject.toml
│   └── foundation_trikey/
│       ├── __init__.py
│       ├── shamir.py
│       ├── ceremony.py
│       ├── authorize.py
│       └── verify.py
│
├── infra/                       # Infrastructure-as-code (all open source)
│   ├── nats/
│   │   └── nats-server.conf    # NATS mesh configuration, mTLS
│   ├── patroni/
│   │   └── patroni.yml         # PostgreSQL HA failover config
│   ├── caddy/
│   │   └── Caddyfile           # Reverse proxy config per tier
│   ├── monitoring/
│   │   ├── prometheus.yml
│   │   └── grafana/
│   │       └── dashboards/     # Pre-built Foundation dashboards
│   └── gitea/
│       └── app.ini             # Self-hosted Gitea config
│
├── db/                          # Database initialization
│   ├── init.sql                 # Schema creation
│   ├── seed.sql                 # Genesis entry + cooperative configs
│   └── policies.sql             # Row-level security, append-only enforcement
│
└── docs/
    ├── architecture.md
    ├── hardware-platform.md     # Node tiers, deployment, resource allocation
    ├── api-reference.md
    ├── hash-chain.md
    ├── decay-model.md
    ├── security.md
    ├── trikey-guide.md
    ├── node-operator-guide.md   # How to run a Foundation node
    ├── verification-guide.md
    └── contributing-guide.md
```

---

## Licensing

**AGPLv3** — the strongest copyleft license. If anyone runs a modified version of Foundation as a service, they must publish their modifications. This prevents a company from forking Foundation, making proprietary changes, and running a closed cooperative platform.

This is a values decision, not a business decision. The spec says: *"Foundation is the physical embodiment of Article IV — Radical Transparency."* A permissive license (MIT, Apache) would allow closed forks that violate the principle Foundation was built to enforce.

The Verifier is separately licensed under **MIT** — anyone should be able to verify without copyleft obligations.

---

## Deployment

### Single-Node Development

```bash
git clone https://gitea.foundation.openutopia.org/openutopia/foundation.git
cd foundation
cp .env.example .env
docker compose up
```

This starts PostgreSQL, NATS, the API server, and the web UI on a single machine. The database is seeded with the genesis ledger entry, both cooperative configs, and founding contributor records. Identical to production but single-node.

### Adding a Node to the Network

```bash
# On a new $5 VPS anywhere in the world:
curl -sSL https://foundation.openutopia.org/install.sh | bash

# The install script:
# 1. Installs Docker CE (or Podman)
# 2. Pulls the Foundation Node Agent image (signed, Tri-Key authorized)
# 3. Generates node identity (Ed25519 keypair)
# 4. Detects available resources → self-assigns tier (Sentinel/Keeper/Guardian)
# 5. Registers with the NATS mesh
# 6. Begins ledger sync and chain verification
# 7. If also running SwarmTrap AIO: starts honeypot services alongside
```

### Production Network (v0.1 target)

```
TIER         COUNT    LOCATIONS                                      COST/MO
──────────────────────────────────────────────────────────────────────────────
Guardians    3-5      Charles DC (US), Hetzner (EU), Vultr (APAC),  $200-500
                      OVH (EU), DigitalOcean (US-W)
Keepers      10-20    Mixed global VMs                                $100-600
Sentinels    50-200   SwarmTrap AIO nodes (already deployed)          $0 incremental
Forges       1-3      Charles DC (GPU), cloud GPU as needed           $100-500
──────────────────────────────────────────────────────────────────────────────
TOTAL                                                                 $400-1,600/mo
```

The Sentinel tier is effectively free — those machines are already deployed and paid for as SwarmTrap honeypot nodes. Foundation's witness workload adds negligible overhead. The Guardians and Keepers are the real infrastructure cost, and they're shared with SwarmTrap's central aggregation and analytics.

### Mirror to GitHub

For contributor visibility and community access, the Gitea canonical repo is mirrored to `github.com/openutopia/foundation`. PRs can be submitted on either. The canonical build system runs on Gitea Actions on self-hosted runners.

---

# Security Architecture

Most platforms protect user data from external attackers. Foundation protects something more fundamental: **the integrity of measurement itself**. If the ledger is compromised, every contributor's income is wrong, every governance voice is wrong, and every law passed on those numbers is illegitimate.

The spec identifies three trust layers:
- **Human → Human:** Can contributors trust each other's reported work?
- **Human → AI:** Can contributors trust AI classifications? (Not applicable in v0.1 — no AI.)
- **Human → Platform:** Can contributors trust that the platform code and data haven't been compromised?

v0.1 security focuses entirely on **Layer 1 and Layer 3** — honest contribution reporting and platform integrity.

---

## Threat Model

### Attacker Profiles

```
ATTACKER             MOTIVATION                    CAPABILITY           PRIORITY
──────────────────────────────────────────────────────────────────────────────────
Dishonest Insider    Inflate own tokens            Authenticated API    CRITICAL
                     Deflate rival's tokens        access, knowledge
                     Manipulate function ratios    of the system

Compromised Admin    Modify ledger silently         Database access,     CRITICAL
                     Insert phantom entries         server access,
                     Alter hash chain               deployment keys

External Attacker    Disrupt service (DoS)          Network access,      HIGH
                     Steal API keys                 exploit CVEs
                     Deface public data

Sybil Attacker       Create fake contributors       API access,          HIGH
                     Farm tokens across             multiple identities
                     multiple accounts

Colluding Group      Mutual token inflation          Multiple valid       HIGH
                     Coordinate to dominate          accounts, social
                     a function                      engineering

Supply Chain         Inject malicious code           Compromised          MEDIUM
                     via dependency                  dependency,
                                                     compromised CI

Platform Operator    Silently alter the running      Full server          CRITICAL
(Rogue)              code to differ from             access
                     audited source
```

### What We're Protecting

```
ASSET                       IMPACT IF COMPROMISED              PROTECTION LEVEL
─────────────────────────────────────────────────────────────────────────────────
Ledger integrity            All token balances wrong,          MAXIMUM
                            governance illegitimate

Hash chain continuity       Tampering undetectable             MAXIMUM

Contributor credentials     Impersonation, false entries       HIGH

API availability            Work cannot be recorded            HIGH

Contributor privacy         Email/identity exposure            HIGH
(limited in v0.1)

Cooperative configuration   Distribution ratios altered        HIGH

Deployment integrity        Running code ≠ audited code        CRITICAL
```

---

## Defense-in-Depth Architecture

### Layer 0: Ledger Integrity (The Core)

This is the single most important security property. Everything else exists to protect this.

**Append-only enforcement — database level:**

```sql
-- The API connects as role 'foundation_app', not as superuser
CREATE ROLE foundation_app WITH LOGIN PASSWORD '...';

-- Grant only INSERT and SELECT on the ledger
GRANT SELECT, INSERT ON ledger_entries TO foundation_app;

-- Explicitly revoke UPDATE and DELETE
REVOKE UPDATE, DELETE ON ledger_entries FROM foundation_app;

-- Revoke TRUNCATE
REVOKE TRUNCATE ON ledger_entries FROM foundation_app;

-- The sequence must be usable for INSERT
GRANT USAGE, SELECT ON SEQUENCE ledger_entries_id_seq TO foundation_app;
```

Even if the application is fully compromised — remote code execution, full API takeover — the attacker **cannot modify or delete existing ledger entries** through the database connection the application uses. They can only INSERT, which extends the chain but cannot rewrite history.

**Append-only enforcement — application level:**

The API has no UPDATE or DELETE endpoint for ledger entries. There is no code path that constructs an UPDATE or DELETE query against `ledger_entries`. This is enforced by:
- Code review policy: any PR touching ledger write logic requires 3 reviewers
- Static analysis: CI check that greps for UPDATE/DELETE on `ledger_entries` and fails the build
- Integration test: test suite includes a test that attempts UPDATE/DELETE and confirms the database rejects it

**Hash chain verification — continuous:**

The API runs chain verification on every INSERT. Before writing a new entry:

1. Read the last entry's `entry_hash`
2. Set it as the new entry's `prev_hash`
3. Compute the new entry's `entry_hash` from its canonical fields
4. INSERT with both hashes
5. Verify: re-read the inserted row, recompute the hash, confirm match

This is wrapped in a database transaction. If any step fails, the transaction rolls back and no entry is written.

**Hash chain verification — periodic background:**

A background task runs every hour:
1. Full chain walk from genesis to latest entry
2. Recompute every hash
3. Compare against stored hashes
4. Log result to a separate audit table
5. If any discrepancy: emit alert to all admin API keys via webhook

**Hash chain verification — external (the Verifier):**

The standalone Verifier tool (MIT-licensed) performs the same verification from a full ledger export. Any contributor can run this at any time. The Verifier trusts nothing — it downloads raw data and recomputes everything.

---

### Layer 1: Authentication

**API key design:**

```
Format:  fct_<version>_<random>
Example: fct_v1_a8f3c2d1e9b4...

- Prefix 'fct_' identifies it as a Foundation key (prevents accidental use elsewhere)
- Version tag allows key format rotation without breaking existing keys
- 48 bytes of cryptographic randomness (via secrets.token_urlsafe)
- Stored as SHA-256 hash in the database — the plaintext is shown once at creation
```

**Key lifecycle:**

```
CREATE    Admin generates key → plaintext shown once → hash stored
USE       Client sends key in Authorization header → API hashes it → lookup
ROTATE    Contributor requests new key → old key revoked, new key issued
REVOKE    Admin or contributor revokes key → hash marked inactive
EXPIRE    Keys expire after configurable period (default: 90 days in v0.1)
```

**Key scoping:**

Each API key is bound to exactly one contributor ID. The key cannot be used to write entries for a different contributor. This is enforced at the API layer:

```python
async def create_entry(entry: EntryCreate, current_user: Contributor = Depends(get_current_user)):
    if entry.contributor_id and entry.contributor_id != current_user.id:
        raise HTTPException(403, "Cannot create entries for another contributor")
    entry.contributor_id = current_user.id  # Force to authenticated user
```

**Admin keys:**

Admin keys are a separate type (`fct_admin_v1_...`) with additional permissions: create contributors, configure cooperatives, revoke keys. Admin keys require 2FA confirmation for destructive operations (key revocation, contributor suspension). In v0.1 this is a TOTP code included in the request header.

**No password-based auth.** API keys only. Passwords introduce credential stuffing, brute force, and password reuse risks. API keys are high-entropy, unique, and revocable.

---

### Layer 2: Authorization

**Role-based access control (RBAC):**

```
ROLE            READ LEDGER    WRITE OWN ENTRIES    WRITE OTHERS    ADMIN OPS
────────────────────────────────────────────────────────────────────────────
public          ✓              ✗                    ✗               ✗
contributor     ✓              ✓                    ✗               ✗
reviewer        ✓              ✓                    confirm only    ✗
admin           ✓              ✓                    ✓               ✓
```

**Reviewer role:** In v0.1, peer review of contributions is manual. A reviewer can confirm another contributor's entry (setting `confirmed_by` on a new confirmation ledger entry). They cannot modify the original entry or create entries attributed to someone else.

**Authorization enforcement:**

Every API endpoint checks permissions before executing. Authorization is enforced at the router level (FastAPI dependency injection), not in the service layer. This means a bug in business logic cannot bypass authorization — the check happens before the service is called.

```python
def require_role(minimum: Role):
    async def check(current_user: Contributor = Depends(get_current_user)):
        if current_user.role.value < minimum.value:
            raise HTTPException(403, f"Requires {minimum.name} role")
        return current_user
    return check

@router.post("/contributors", dependencies=[Depends(require_role(Role.ADMIN))])
async def create_contributor(...):
    ...
```

---

### Layer 3: Input Validation and Injection Prevention

**All input validated via Pydantic schemas:**

```python
class EntryCreate(BaseModel):
    cooperative: str = Field(..., min_length=1, max_length=64, pattern=r'^[a-z0-9_-]+$')
    contribution_type: str = Field(..., min_length=1, max_length=128)
    function_tag: Literal['P', 'C', 'B']
    revenue_path: Optional[int] = Field(None, ge=1, le=100)
    token_amount: Decimal = Field(..., gt=0, le=Decimal('1000000'))
    explanation: Optional[str] = Field(None, max_length=4096)

    class Config:
        extra = 'forbid'  # Reject any fields not in the schema
```

**SQL injection prevention:** SQLAlchemy ORM only — no raw SQL queries anywhere in the application. Parameterized queries are the default. CI includes a static analysis check that fails if raw SQL strings are detected.

**Hash chain canonical form:** The canonical JSON used for hashing is constructed from typed Python objects, not from raw user input. Defense-in-depth against serialization-based attacks.

---

### Layer 4: Rate Limiting and Anti-Gaming

**API rate limiting:**

```
OPERATION           LIMIT                   SCOPE
────────────────────────────────────────────────────────
Write (POST)        100/hour                Per API key
Read (GET)          1,000/hour              Per IP
Export              10/hour                 Per IP
Verify              10/hour                 Per IP
Admin operations    20/hour                 Per admin key
```

Rate limits enforced via Redis (or in-memory for single-instance v0.1). Returns `429 Too Many Requests` with `Retry-After` header.

**Anti-gaming — contribution velocity:**

```
PATTERN                              ACTION
─────────────────────────────────────────────────
> 50 entries/day sustained           Flag for peer review
> 10 entries/hour                    Warn contributor, flag
Entries at unusual hours (for        Informational flag
  contributor's historical pattern)
Sudden change in function ratio      Informational flag
Burst of entries just before         Flag for admin review
  epoch close
```

Flags are **informational only** in v0.1. No automated sanctions. The contributor is notified and can provide context.

**Anti-Sybil — v0.1 approach:** Contributor creation is admin-only. The founding team knows every contributor personally. Identity verification mechanisms deferred to v0.2+.

---

### Layer 5: Network Security

**Decentralized network architecture:**

```
                          ┌──────────────┐
  Internet ──────────────►│ GeoDNS       │  Routes to nearest Guardian/Keeper
                          └──────┬───────┘
                    ┌────────────┼────────────────┐
                    │            │                │
              ┌─────┴──────┐ ┌──┴─────────┐ ┌────┴───────┐
              │Guardian #1 │ │Guardian #2 │ │Guardian #3 │
              │(Charles DC)│ │(EU)        │ │(APAC)      │
              │Caddy→API→PG│ │Caddy→API→PG│ │Caddy→API→PG│
              └─────┬──────┘ └──────┬─────┘ └────┬───────┘
                    │               │             │
              NATS mesh (encrypted, mTLS between all nodes)
                    │               │             │
              ┌─────┴──┐      ┌────┴───┐    ┌───┴──────┐
              │Keepers │      │Keepers │    │Keepers   │
              │(read   │      │(read   │    │(read     │
              │ API)   │      │ API)   │    │ API)     │
              └────┬───┘      └────┬───┘    └───┬──────┘
                   │               │            │
              ┌────┴────┐    ┌────┴───┐   ┌───┴──────┐
              │Sentinels│    │Sentinels│  │Sentinels │
              │(witness)│    │(witness)│  │(witness) │
              └─────────┘    └────────┘  └──────────┘
```

**On each node, PostgreSQL is not exposed to the network.** It listens on localhost only. The only path to the database is through the local API application. Replication traffic flows over encrypted PostgreSQL streaming replication channels, authenticated by client certificates.

**NATS mesh is encrypted with mTLS.** Every node-to-node connection is authenticated by the node's Ed25519 identity and encrypted in transit. No node can join the mesh without a valid node identity signed by an admin or verified by the network.

**TLS everywhere:** TLS 1.3 minimum on all public endpoints. HSTS headers. Caddy handles automatic certificate management via Let's Encrypt on every Guardian and Keeper.

**Per-node firewall rules:**

```bash
# Sentinel (minimal exposure)
ufw default deny incoming
ufw allow 22/tcp              # SSH (key-only)
ufw allow from <nats_peers>   # NATS mesh only from known nodes
ufw enable

# Keeper (read API)
ufw default deny incoming
ufw allow 80/tcp              # HTTP → HTTPS redirect
ufw allow 443/tcp             # HTTPS (read API)
ufw allow 22/tcp              # SSH
ufw allow from <nats_peers>   # NATS mesh
ufw enable

# Guardian (full API + replication)
ufw default deny incoming
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 22/tcp
ufw allow from <nats_peers>          # NATS mesh
ufw allow from <pg_replicas> 5432    # PostgreSQL replication (only from known replicas)
ufw enable
```

**Geographic distribution requirement:** No more than 40% of Guardian nodes may be hosted by a single provider. No more than 30% in a single country. This is governable by contributor vote.

---

### Layer 6: Deployment Integrity and Tri-Key Authorization

This layer addresses the most dangerous threat in the system: **code changes**. The security architecture makes the ledger append-only and tamper-evident. But if someone can change the running code — the hash function, the decay formula, the authorization logic — they can corrupt everything at the source. The Verifier checks the ledger's integrity, but the Verifier trusts the hash algorithm. If the deployed code uses a different algorithm than the audited code, the Verifier itself becomes unreliable.

Attestation is **detective** — it tells you after the fact. The Tri-Key mechanism is **preventive** — it makes unauthorized code changes structurally impossible.

#### Tri-Key: Three Functions, Three Keys, One Gate

Three cryptographic key fragments are held by three different keyholders — one elected from each function (Provider, Consumer, Bridge). A deployment to production requires all three fragments to combine into a master authorization key. No subset of fragments is sufficient. If any one function refuses, the deployment does not happen.

This is not a metaphor. This is cryptographic enforcement. The deployment pipeline physically cannot execute without all three fragments.

**Key Generation (Shamir's Secret Sharing):**

```
1. Generate a 256-bit master deployment key M
2. Split M into three shares using Shamir's Secret Sharing (k=3, n=3):
   - Share P → Provider Keyholder
   - Share C → Consumer Keyholder  
   - Share B → Bridge Keyholder
3. Destroy M — it exists nowhere until reconstructed
4. Each keyholder stores their share on a hardware security device
   (YubiKey, Trezor, or similar)
```

Shamir's Secret Sharing guarantees: any 2 shares reveal **zero information** about M. All 3 are required. This is mathematically proven — not a policy, not a promise, not a configuration. It's algebra over a finite field.

**The Mathematics:**

A degree-2 polynomial over a prime field:

```
f(x) = M + a₁x + a₂x²  (mod p)

Where:
  M  = the secret (master key), which is f(0)
  a₁, a₂ = random coefficients (destroyed after share generation)
  p  = a large prime (256-bit)

Shares:
  Share P = f(1)
  Share C = f(2)
  Share B = f(3)

Reconstruction:
  Given f(1), f(2), f(3), use Lagrange interpolation to recover f(0) = M
  Any 2 points on a degree-2 polynomial are insufficient to determine it
  (infinite polynomials pass through any 2 points)
```

Shamir's Secret Sharing was published in 1979 and is one of the most studied schemes in cryptography. Well-audited implementations exist in every language.

**Reference Implementation:**

```python
"""
Tri-Key: Shamir's Secret Sharing for Foundation deployment authorization.
k=3, n=3 — all three shares required, no threshold flexibility.
"""

import secrets
import hashlib
import json
from typing import List, Tuple

PRIME = 2**256 - 189  # Largest 256-bit prime

def _eval_poly(coeffs: List[int], x: int) -> int:
    """Evaluate polynomial at x over the prime field."""
    result = 0
    for i, c in enumerate(coeffs):
        result = (result + c * pow(x, i, PRIME)) % PRIME
    return result

def generate_shares() -> Tuple[int, List[Tuple[int, int]]]:
    """
    Generate a master key and 3 Shamir shares.
    Returns (master_key, [(1, share_P), (2, share_C), (3, share_B)])
    The master key should be destroyed after share distribution.
    """
    master_key = secrets.randbelow(PRIME)
    a1 = secrets.randbelow(PRIME)
    a2 = secrets.randbelow(PRIME)
    coeffs = [master_key, a1, a2]
    
    shares = [(i, _eval_poly(coeffs, i)) for i in range(1, 4)]
    
    a1 = a2 = 0
    del coeffs
    
    return master_key, shares

def reconstruct_master(shares: List[Tuple[int, int]]) -> int:
    """
    Reconstruct master key from exactly 3 shares using Lagrange interpolation.
    """
    if len(shares) != 3:
        raise ValueError("Exactly 3 shares required")
    
    master = 0
    for i, (xi, yi) in enumerate(shares):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(shares):
            if i != j:
                numerator = (numerator * (0 - xj)) % PRIME
                denominator = (denominator * (xi - xj)) % PRIME
        
        lagrange = (yi * numerator * pow(denominator, PRIME - 2, PRIME)) % PRIME
        master = (master + lagrange) % PRIME
    
    return master

def sign_deployment(master_key: int, deployment_manifest: dict) -> str:
    """Sign a deployment manifest with the reconstructed master key."""
    canonical = json.dumps(deployment_manifest, sort_keys=True, separators=(',', ':'))
    key_bytes = master_key.to_bytes(32, 'big')
    signature = hashlib.sha256(key_bytes + canonical.encode('utf-8')).hexdigest()
    key_bytes = b'\x00' * 32  # Destroy
    return signature
```

**Deployment Authorization Flow:**

```
Developer submits code change
        │
        ▼
CI/CD builds, tests, produces signed artifact
        │
        ▼
Deployment request created with:
  - Source commit hash
  - Build artifact digest  
  - Changelog / justification
  - Diff summary
        │
        ▼
┌───────────────────────────────────────────────┐
│         TRI-KEY AUTHORIZATION GATE            │
│                                               │
│  Provider Keyholder reviews + signs ──► ☐     │
│  Consumer Keyholder reviews + signs ──► ☐     │
│  Bridge Keyholder reviews + signs   ──► ☐     │
│                                               │
│  All three signed? ──► Reconstruct M          │
│  M authorizes deployment pipeline             │
│  M is destroyed again immediately             │
└───────────────────────────────────────────────┘
        │
        ▼
Deployment executes with cryptographic proof
that all three functions authorized it
        │
        ▼
Authorization record written to ledger
(system entry, hash-chained, permanent)
```

**Key reconstruction is ephemeral.** M is reconstructed in memory, used to sign the deployment authorization, and immediately discarded. Never written to disk, never stored in a database, never transmitted over the network.

**The Deployment Manifest:**

```json
{
  "deployment_id": "deploy_2026Q2_0042",
  "source_commit": "a8f3c2d1e9b4...",
  "source_repo": "github.com/openutopia/foundation",
  "branch": "main",
  "build_artifact_digest": "sha256:7b1d9e...",
  "build_timestamp": "2026-04-06T10:00:00Z",
  "changelog": "Fix decay computation rounding edge case (#147)",
  "diff_stats": {"files_changed": 3, "insertions": 12, "deletions": 8},
  "tests_passed": true,
  "test_count": 342,
  "security_checks_passed": true,
  "requested_by": "contributor_uuid_...",
  "requested_at": "2026-04-06T11:00:00Z"
}
```

**What the Tri-Key Protects:**

```
ACTION                              REQUIRES TRI-KEY?    WHY
──────────────────────────────────────────────────────────────────────
Deploy new code to production       YES                  Code controls everything
Modify database schema              YES                  Schema changes affect ledger
Update Docker base images           YES                  Supply chain attack surface
Modify CI/CD pipeline               YES                  Pipeline controls deployment
Rotate the master key itself        YES (2 of 3 +       Prevents single-function takeover
                                    supermajority vote)

Record a contribution               NO                   Normal API operation
Read the ledger                     NO                   Public data
Run the Verifier                    NO                   Anyone can verify
Create a contributor (admin)        NO (admin key)       Doesn't change code
```

**Keyholder Election:**

```
KEYHOLDER       ELECTED BY                   TERM        REQUIREMENTS
──────────────────────────────────────────────────────────────────────
Provider Key    Contributors with P tokens   6 months    Active Provider contributor
                (weighted by P balance)                   Hardware security device
                                                          Minimum 90-day tenure

Consumer Key    Contributors with C tokens   6 months    Active Consumer contributor
                (weighted by C balance)                   Hardware security device
                                                          Minimum 90-day tenure

Bridge Key      Contributors with B tokens   6 months    Active Bridge contributor
                (weighted by B balance)                   Hardware security device
                                                          Minimum 90-day tenure
```

**The Keyholder Ceremony (every 6 months or on keyholder change):**

```
1. Three elected keyholders meet (in-person preferred, secure video if necessary)
2. A new master key M is generated on an air-gapped machine
3. M is split into 3 shares using Shamir's Secret Sharing
4. Each share is loaded onto the keyholder's hardware security device
5. M is verified: reconstruct from all 3 shares, confirm match
6. M is destroyed: air-gapped machine wiped
7. Old shares are revoked (hardware devices wiped of old share)
8. The new key generation number is published to the ledger
9. A test deployment is authorized using the new shares to confirm functionality
```

The ceremony is public per Article IV. The shares are secret — the process is not.

**Tri-Key Bootstrap (before elections exist):**

- **Phase 1 (< 10 contributors):** Charles holds all three shares on physically separated hardware devices. Known centralization, documented transparently.
- **Phase 2 (10+ contributors):** Three trusted founding contributors appointed as interim keyholders. Full ceremony protocol followed.
- **Phase 3 (Voting module live, v0.3):** Formal keyholder elections. Interim shares revoked.

**Attack Scenarios:**

| Scenario | Response |
|---|---|
| **Rogue developer** pushes malicious code | CI builds it, but deployment is gated. Three independent keyholders must review and sign. |
| **One keyholder compromised** | One share reveals zero information (Shamir's guarantee). Remaining two trigger emergency re-keying. |
| **Two keyholders compromised** | Two shares still reveal zero information (k=3). Remaining keyholder triggers re-keying with supermajority vote. |
| **Rogue platform operator** bypasses pipeline | Runtime attestation shows unauthorized deployment. Any contributor running Verifier detects mismatch. Self-incriminating. |
| **All three keyholders collude** | Fork right is the ultimate fallback. Collusion is permanently recorded. 6-month terms limit the window. |

#### Reproducible Builds (Complementary to Tri-Key)

```dockerfile
# Pinned by digest, not by tag
FROM python:3.12.3-slim@sha256:abc123... AS base

# Dependencies from lock file
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock

# Application code
COPY api/ /app/api/
```

Given the same source commit, the build produces the same image hash. Pinned dependencies, deterministic base images, no network access during build.

#### Runtime Attestation

The running instance exposes `/system/attestation` (public, no auth):

```json
{
  "source_commit": "a8f3c2d1e9b4...",
  "image_digest": "sha256:7b1d9e...",
  "build_timestamp": "2026-04-06T10:00:00Z",
  "startup_timestamp": "2026-04-06T10:05:00Z",
  "schema_version": "0.1.0",
  "chain_length": 1042,
  "chain_tip_hash": "a3f8c2d1e9...",
  "deployment_authorized_by": {
    "provider_keyholder": "contributor_uuid_...",
    "consumer_keyholder": "contributor_uuid_...",
    "bridge_keyholder": "contributor_uuid_...",
    "authorization_signature": "c4e9f2a1...",
    "authorized_at": "2026-04-06T12:00:00Z"
  },
  "trikey_generation": 3,
  "trikey_ceremony_date": "2026-04-01T00:00:00Z"
}
```

Any contributor can reproduce the build from the source commit, compare image digests, and verify the Tri-Key authorization signature.

#### Signed Commits and Releases

All commits GPG-signed. Unsigned commits rejected by CI. Every release tag signed by 2+ maintainers. Docker image built by CI from signed tag.

---

### Layer 7: Operational Security

**Secrets management:**

```
SECRET                  STORAGE                     ROTATION
────────────────────────────────────────────────────────────────
Database password       Environment variable         90 days
                        (Docker secret in prod)
API signing key         Environment variable         On compromise
Admin API keys          Database (hashed)            90 days
Node Ed25519 keys       Local keyfile on each node   On compromise
NATS mTLS certs         Auto-generated per node      Annual
PG replication certs    Generated per Guardian        Annual
TLS certificates        Caddy auto-renewal           Automatic
SSH keys                Authorized_keys file         Annual
GPG signing keys        Contributor hardware         On compromise
Tri-Key shares          Hardware security devices     6 months (ceremony)
```

No secrets in code. No secrets in Docker images. No secrets in committed env files.

**Logging and audit trail:**

```
EVENT                           LOGGED WHERE            RETENTION
─────────────────────────────────────────────────────────────────
API request (all)               Application log         90 days
Authentication failure          Application log +       1 year
                                security alert
Admin operations                Application log +       Permanent
                                ledger (system entry)
Chain verification result       Audit table             Permanent
Chain verification (witness)    Local node log +        Permanent
                                NATS broadcast
Rate limit trigger              Application log         30 days
Anti-gaming flag                Audit table             Permanent
Deployment event                Deployment log +        Permanent
                                ledger (system entry)
Tri-Key authorization           Ledger (system entry)   Permanent
Node join/leave                 Ledger (system entry)   Permanent
Node health heartbeat           NATS + Prometheus       30 days
Replication lag alert           Monitoring + alert      90 days
```

**Admin operations create ledger entries.** When an admin creates a contributor, revokes a key, or changes cooperative config, a `system` type entry is written to the ledger. Admin actions are subject to the same hash chain integrity guarantee as contributions. You can't silently create a phantom contributor — the creation event is in the chain.

**Backup strategy:**

```
COMPONENT           BACKUP METHOD              FREQUENCY    RETENTION
──────────────────────────────────────────────────────────────────────
PostgreSQL          pg_dump (encrypted)         Daily        90 days
                    WAL archiving (continuous)   Continuous   7 days
Ledger export       JSON export via API          Daily        Permanent
                    (stored off-server)
Configuration       Git (the repo itself)        Every commit Permanent
```

The ledger export is the most important backup. Because the ledger is deterministic, a full export + the schema is sufficient to reconstruct the entire system state.

**Incident response:**

```
SEVERITY    DEFINITION                                    RESPONSE TIME
──────────────────────────────────────────────────────────────────────────
CRITICAL    Ledger integrity compromised,                 Immediate
            hash chain broken, admin key stolen            (< 1 hour)

HIGH        API key compromised, DoS attack,              < 4 hours
            unauthorized contributor created

MEDIUM      Anti-gaming flag on active contributor,        < 24 hours
            failed chain verification on background check

LOW         Rate limit triggered, unusual access pattern   < 72 hours
```

CRITICAL procedure: Contain → Verify (run full chain verification) → Identify scope → Communicate out-of-band → Correct via Tribunal/admin → Prevent (patch + rotate credentials) → Document publicly per Article IV.

---

### Layer 8: Dependency Security

All dependencies pinned to exact versions in lock files. CI runs `pip-audit` and `npm audit` on every PR. Known vulnerabilities fail the build. Security-critical dependencies require manual review before version bumps.

**Minimal dependency surface:**
- Python: FastAPI, SQLAlchemy, Pydantic, uvicorn, psycopg2, click
- Node: React, Vite, react-router
- Infrastructure: PostgreSQL, Caddy, Docker

Every release includes a machine-readable SBOM (Software Bill of Materials).

---

## Contributor-Facing Security Features

### Contribution Receipt

Every accepted contribution returns a receipt with cryptographic proof:

```json
{
  "receipt": {
    "entry_id": 1042,
    "entry_hash": "a3f8c2d1e9b4...",
    "prev_hash": "7b1d9e...",
    "chain_position": 1042,
    "timestamp": "2026-04-06T14:30:00Z",
    "your_active_balance": {
      "total": "4,215.0000 SCT",
      "by_function": {"P": "3,100.0000", "C": "215.0000", "B": "900.0000"}
    }
  }
}
```

If the platform ever reports a different balance, the contributor has proof of what the ledger said.

### Personal Audit Endpoint

`GET /contributors/{id}/audit` — contributor-specific verification report. Any contributor can verify their own state at any time without trusting the platform's dashboard.

### Transparency Report

Published automatically each epoch (quarterly): total entries, chain verifications, admin operations, anti-gaming flags, security incidents, corrections, external verifications.

---

## Cryptographic Choices

```
PURPOSE                 ALGORITHM       WHY
─────────────────────────────────────────────────────────
Ledger hash chain       SHA-256         Industry standard, no known practical attacks
API key storage         SHA-256         Keys are high-entropy (48 bytes); bcrypt unnecessary
API key generation      secrets module  384 bits of cryptographic randomness
TOTP (admin 2FA)        HMAC-SHA1       Standard RFC 6238, compatible with all authenticators
Tri-Key shares          Shamir's SSS    Proven 1979 scheme, mathematically guaranteed k-of-n
Deployment signing      HMAC-SHA256     Master key signs manifest canonically
Node identity           Ed25519         Fast, secure, small key size, used for node auth
NATS mesh               mTLS (Ed25519)  All inter-node traffic encrypted and authenticated
PG replication          TLS + client    Streaming replication encrypted, cert-authenticated
                        certificates
Commit signing          GPG (Ed25519)   Standard for Git
TLS (public)            1.3 (Caddy)     Modern default, no configuration needed
```

**What we don't use:** bcrypt for API keys (unnecessary entropy), JWT tokens (complexity without benefit), blockchain consensus (unnecessary), homomorphic encryption (ledger is public), zero-knowledge proofs (premature for v0.1).

---

## Security Testing

**Automated (CI on every PR):**
- Hash chain integrity tests
- Authorization enforcement tests (each role boundary)
- Integration test: UPDATE/DELETE on ledger → must fail
- Integration test: cross-contributor entry creation → must fail
- `pip-audit` / `npm audit` for dependency vulnerabilities
- Static analysis: grep for raw SQL, hardcoded secrets, UPDATE/DELETE on ledger

**Manual (before each release):**
- Full chain verification from genesis
- Reproducible build verification
- API key lifecycle test
- Rate limit verification
- TLS configuration test

**Penetration testing (quarterly after launch):**
- External scan, API fuzzing, auth bypass, authz escalation, chain integrity attack simulation
- Results published per Article IV, redacted only for active unpatched vulnerabilities (max 90 days)

---

# Roadmap

## What v0.1 Does NOT Include

| Feature | Version | Why Deferred |
|---|---|---|
| Communication module | v0.2 | Requires real-time infrastructure (WebSocket, Matrix bridge) |
| Voting module | v0.3 | Requires communication for deliberation |
| AI classification | v0.3 | Requires sufficient ledger data to train on |
| Distribution engine | v0.4 | Requires voting (to approve distributions) |
| OAuth/SSO | v0.2 | API keys are sufficient for founding team |
| Multi-tenant hosting | v0.5 | Single instance is correct for now |
| Liquid democracy | v0.4 | Requires voting infrastructure |
| Pioneer tokens (SPT) | v0.2 | Needs decay model refinement |
| Micro-contributions | v0.3 | Needs AI classification to detect |
| Elected Tri-Key keyholders | v0.3 | Requires Voting module |
| K3s/Nomad orchestration | v0.3 | Docker Compose per node sufficient for v0.1 |
| GPU cluster scheduling | v0.4 | Forge nodes run ad-hoc jobs in v0.1 |
| Self-hosted DNS (CoreDNS) | v0.2 | GeoDNS via external provider acceptable for v0.1 |

## Security Roadmap

```
VERSION     SECURITY ADDITIONS
──────────────────────────────────────────────────────────────
v0.1        API keys, append-only DB, hash chain, rate limiting,
            role-based access, Verifier, deployment attestation,
            Tri-Key deployment authorization (bootstrap phase)

v0.2        OAuth/SSO, contributor identity verification,
            API key scoping per cooperative, audit log dashboard,
            automated Verifier runs by community volunteers

v0.3        AI classification audit trail, gaming detection,
            Tribunal integration for disputes, end-to-end
            encrypted private channels, Tri-Key elected keyholders

v0.4        Distribution security (multi-signature approval for
            payouts), liquid democracy delegation security,
            formal security audit by external firm

v0.5        Multi-tenant isolation, per-cooperative encryption
            keys, HSM support for signing keys, bug bounty program
```

## Migration Path

When future modules come online, they integrate with the ledger — they don't replace it:

- **Communication (v0.2):** Messages create contribution events that flow into the ledger via the existing API
- **Voting (v0.3):** Votes are ledger entries of type `vote`. Vote tallies are computed from the ledger.
- **AI Classification (v0.3):** AI writes entries with `classified_by = 'ai_suggested'`. Humans confirm, creating a second entry with `classified_by = 'ai_confirmed'`.
- **Distribution (v0.4):** Distribution computation reads from the ledger. Distribution payouts are recorded as ledger entries of type `distribution`.

The ledger API never breaks. Modules add to it.

---

# Build Plan

## The Genesis Entry

The first entry in the ledger. It exists to anchor the hash chain.

```json
{
  "id": 1,
  "entry_hash": "<computed>",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "contributor_id": "<system>",
  "created_at": "2026-04-06T00:00:00Z",
  "epoch": "2026-Q2",
  "entry_type": "system",
  "contribution_type": "genesis",
  "function_tag": "B",
  "revenue_path": null,
  "token_amount": 0,
  "classified_by": "manual",
  "explanation": "Genesis entry. Foundation ledger initialized. Founders: Charles Chen, Claude (Anthropic)."
}
```

## Build Sequence

1. **Database schema + migrations** — get the data model right first
2. **Hash chain library** — the core integrity mechanism, with exhaustive tests
3. **Tri-Key library** — Shamir's Secret Sharing, key ceremony tooling, deployment signing
4. **Node Agent — identity + discovery** — Ed25519 keypair generation, resource detection, tier auto-assignment
5. **NATS mesh setup** — mTLS configuration, node registration, heartbeat protocol
6. **API: entries endpoints** — POST and GET, with hash chaining on every insert
7. **API: contributor, cooperative, and node endpoints** — CRUD operations + node registry
8. **PostgreSQL replication + Patroni** — streaming replication across Guardians, automatic failover
9. **Ledger propagation via NATS** — new entries broadcast to all Keepers and Sentinels
10. **Witness verification** — Sentinels and Keepers independently verify chain on every propagated entry
11. **Verifier** — standalone tool, tested against the API's own ledger
12. **CLI** — thin wrapper over the API, including `foundation node` commands
13. **Web UI** — dashboard, ledger browser, contributor pages, network map
14. **Per-tier Docker Compose** — guardian.yml, keeper.yml, sentinel.yml
15. **install.sh** — one-command node deployment for any tier
16. **Gitea instance** — self-hosted code hosting on a Guardian node
17. **Gitea Actions runners** — self-hosted CI/CD on Foundation nodes
18. **Tri-Key pipeline integration** — wire Shamir's into deployment gate
19. **Monitoring stack** — Prometheus + Grafana on Guardians
20. **Documentation** — architecture, hardware platform, API reference, security, node operator guide, Tri-Key guide
21. **Public launch** — Gitea repo + GitHub mirror, first external contributors

Estimated time to v0.1 release: **6-8 weeks** with 1-2 active developers. The node agent and NATS mesh add ~2 weeks over the original single-node estimate.

## How Foundation Dogs-Foods Itself

From day one, Foundation tracks its own development on its own ledger. Every commit is a contribution entry. Every code review is Bridge work. Every design document (including this one) is Provider work.

The founding team manually enters contributions via CLI during v0.1. This is intentionally low-tech — it forces us to experience the manual workflow that the AI layer will eventually automate, and it ensures the ledger works correctly before any automation is added.

## Security Checklist for v0.1 Release

```
LEDGER INTEGRITY
[ ] PostgreSQL role has no UPDATE/DELETE on ledger_entries
[ ] Integration test confirms UPDATE/DELETE rejected
[ ] Hash chain verification passes from genesis
[ ] Ledger replication verified across all Guardian nodes
[ ] Witness verification running on all Sentinels and Keepers

AUTHENTICATION & AUTHORIZATION
[ ] API keys generated with 48 bytes entropy
[ ] API keys stored as SHA-256 hashes only
[ ] Admin 2FA (TOTP) functional
[ ] Cross-contributor entry creation rejected (test)
[ ] Rate limiting functional (test)

DECENTRALIZED INFRASTRUCTURE
[ ] Minimum 3 Guardian nodes operational across different providers
[ ] Minimum 5 Keeper nodes operational across different regions
[ ] Minimum 20 Sentinel witnesses operational
[ ] NATS mesh encrypted with mTLS between all nodes
[ ] Node identity (Ed25519) generation and registration working
[ ] Patroni automatic failover tested (kill primary → replica promotes)
[ ] Geographic distribution thresholds met (no >40% single provider)
[ ] All software on all nodes is open source (zero proprietary components)

NETWORK SECURITY
[ ] TLS 1.3 enabled on all public endpoints
[ ] PostgreSQL not exposed to network on any node
[ ] Per-tier firewall rules applied
[ ] NATS mesh accepts only registered nodes

DEPLOYMENT INTEGRITY
[ ] No secrets in committed code (git-secrets scan)
[ ] All dependencies pinned to exact versions
[ ] pip-audit / npm audit pass with zero known vulnerabilities
[ ] Docker image reproducible from source commit
[ ] /system/attestation endpoint returns correct values on all Guardians
[ ] Verifier produces matching results against live API
[ ] Signed release tag by 2+ maintainers
[ ] SBOM published with release

TRI-KEY
[ ] Tri-Key shares generated and distributed to keyholders
[ ] Tri-Key test deployment authorized successfully
[ ] Deployment pipeline rejects unauthorized deploys (test)
[ ] Keyholder ceremony documented and witnessed

OPERATIONAL
[ ] .env.example contains no real values
[ ] Backup procedure tested (pg_dump + restore + verify)
[ ] Incident response procedure documented and reviewed
[ ] Gitea instance operational on Foundation infrastructure
[ ] Gitea Actions CI running on self-hosted Foundation nodes
[ ] GitHub mirror configured and syncing
[ ] install.sh tested on fresh Debian 12 and Ubuntu 24 VMs
[ ] Node operator guide complete and tested by non-founder
```

---

## Appendix: Key Dates

- **Foundation Concept:** March 29, 2026
- **Initial Specification:** v0.1 (March 2026)
- **Technical Design:** v0.1 (April 6, 2026)
- **Tri-Key Concept:** April 6, 2026 (Charles Chen)
- **Decentralized Hardware Platform Design:** April 8, 2026 (Charles Chen)
- **Founders:** Charles Chen, Claude (Anthropic)
- **Target v0.1 Release:** May–June 2026
- **License:** AGPLv3 (platform), MIT (verifier)
- **Canonical Repository:** gitea.foundation.openutopia.org/openutopia/foundation
- **GitHub Mirror:** github.com/openutopia/foundation
- **Cryptographic Basis (Tri-Key):** Shamir's Secret Sharing (Adi Shamir, 1979)

---

*The Ledger is the ground truth. The hash chain is the integrity guarantee. The Verifier is the trust mechanism. The Tri-Key is the gate. The decentralized hardware platform is the physical embodiment of trust — no single machine, no single datacenter, no single operator can compromise what hundreds of independent nodes verify continuously.*

*Three functions govern the cooperative. Three keys govern the code. Three hundred nodes witness the ledger.*

*Trust is built by making betrayal detectable. Foundation's security doesn't prevent every possible attack — it makes every successful attack visible to a global network of independent witnesses running 100% open-source software on hardware they control.*

*Build the ground first. Build it everywhere.*
