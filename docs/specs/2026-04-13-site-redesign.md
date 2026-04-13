# SwarmTrap.net — Site Redesign Spec

> Date: 2026-04-13
> Status: Draft
> Replaces: 2026-04-13-landing-page-design.md

## Goal

Convert swarmtrap.net from a single-scroll manifesto into a multi-page site that recruits contributors to build Foundation. Every page drives toward signup. The live SOC dashboard is the proof that the system works. Signups are stored locally on VM 200 with bot protection.

## End Game

Visitors sign up. Signups become the founding contributors who build Foundation (the open-source cooperative platform). The site recruits them; the documents arm them; the SOC dashboard proves the system is real.

---

## Site Structure

```
/                    → main page (hero + 3 hook cards)
/thesis              → full thesis argument (separate page)
/proof               → pitch about the live system + "Enter the SOC" button
/join                → cooperative invitation + signup form
/welcome             → post-signup confirmation + document downloads
/dashboard/*         → PV1 SOC dashboard (read-only, reverse-proxied)
/docs/*              → founding documents (static files)
```

---

## Page Designs

### Main Page (`/`)

Hero section (same energy as current):
- SwarmTrap wordmark: `Swarm` + `Trap` (green accent)
- Tagline: "AI makes better attacks. Physics makes better traps."
- No scroll CTA — replaced by three hook cards below

Three hook cards in a row (or stacked on mobile). Each card: short teaser text + "Read more" link to the dedicated page.

**Card 1 — The Thesis**
- Hook line: *"This might be the only way to beat AI hackers."*
- One sentence: Not better signatures. Not faster patches. A structural advantage that AI can't overcome.
- Link: "Read the thesis →" → `/thesis`

**Card 2 — The Proof**
- Hook line: *"This isn't a whitepaper. The system is running."*
- One sentence: A live sensor network catching real attackers at wire speed. See it yourself.
- Link: "See the proof →" → `/proof`

**Card 3 — Own What You Build**
- Hook line: *"Contributors build it. Contributors own it."*
- One sentence: 90% of net revenue goes to the people who build, operate, and improve the system.
- Link: "Join the cooperative →" → `/join`

Footer: same as current.

### Thesis Page (`/thesis`)

Full-page narrative argument. This is the intellectual hook that makes security professionals stop and think.

**Opening:**
> *"This might be the only way to beat AI hackers."*
>
> Not better signatures. Not faster patches. Not another AI racing against AI. The only structural advantage defenders have is physics — and nobody's using it.

**Body — the TCP physics argument:**
- AI can generate infinite zero-day exploits, mutate malware past signatures, automate the full attack chain
- But TCP forces a mandatory sequence: scan → knock → exploit. This is protocol physics, not convention.
- The knock phase is where the attacker reveals their hand — they MUST send packets that show their technique BEFORE they can do damage
- Globally distributed honeypots capture every knock sequence in real time
- Every zero-day exploit AI generates becomes a signature the moment it touches a trap
- More AI attacks = more training data = better detection. Attackers fuel their own detection.
- The cost asymmetry: AI attacker's cost scales per novel attack. Defender's cost is near-zero marginal observation ($3/month VM captures whatever hits it).
- As AI accelerates zero-day discovery, more novel attacks land on honeypots. The arms race favors the defender with the largest observation network.

**Closing — why a cooperative:**
- Building a global sensor network takes hundreds of machines across every continent
- No company can afford to deploy and maintain that infrastructure alone
- Only a cooperative can — where every contributor who runs a $3/month honeypot VM earns a share of the intelligence it produces
- That's SwarmTrap.

**CTA at bottom:** "See the system running →" (link to `/proof`) and "Join the cooperative →" (link to `/join`)

Content source: SwarmTrap_Founding_Document_v4.md, section "The Core Technical Thesis — Why Honeypots Beat AI Attackers"

### Proof Page (`/proof`)

Short pitch — not the full SOC dashboard, but the gateway to it.

**Headline:** "The System Is Running"

**Subtext:** This isn't a demo. This is a production sensor network processing live internet traffic. Attackers are being caught right now.

**A few headline stats** (pulled from PV1 via existing `/api/stats` proxy):
- IPs tracked
- Confirmed attackers
- Honeypot sensors active
- Model accuracy
- Evidence events collected

These are the teaser — same as current, but framed as a preview.

**Primary CTA:** Large button: "Enter the live SOC dashboard →" → `/dashboard`

**Description of what they'll see:** Short list:
- Live attack map with GeoIP
- Real-time packet processing metrics
- IP kill chains (scan → knock → exploit progression)
- ML model performance and scoring throughput
- Full flow explorer with protocol/label filters
- GOD intelligence dashboard (the Two Gods in action)

**Secondary CTA at bottom:** "Join the cooperative →" (link to `/join`)

### SOC Dashboard (`/dashboard/*`)

The full PV1 SOC React app, served read-only through Caddy reverse proxy on VM 200.

**Proxied pages (read-only):**

| Route | Page | Public? |
|-------|------|---------|
| `/dashboard` | Overview | Yes |
| `/dashboard/god` | GOD Dashboard | Yes |
| `/dashboard/explorer` | Explorer | Yes (action buttons hidden) |
| `/dashboard/map` | Attack Map | Yes |
| `/dashboard/flows` | Flow Explorer | Yes |
| `/dashboard/flows/:id` | Flow Detail | Yes |
| `/dashboard/killchain` | Kill Chain | Yes |
| `/dashboard/ml` | ML Dashboard | Yes |
| `/dashboard/realtime` | Real-Time | Yes |
| `/dashboard/ip/*` | IP Profile | Yes |
| `/dashboard/campaigns` | Campaigns | Yes (action buttons hidden) |

**Hidden pages (not proxied):**

| Route | Page | Why hidden |
|-------|------|------------|
| `/dashboard/control` | Control Plane | Write operations (upsert, delete, annotate) |
| `/dashboard/vms` | VM Status | Internal infrastructure details |
| `/dashboard/audit` | Audit Log | Internal operations |

**Architecture:** Separate public build of the SOC React app, deployed as static files on VM 200. Data fetched from PV1 via Caddy reverse proxy (GET only).

- Copy PV1 SOC dashboard source (`/home/colo8gent/DFI2/backend_api/ui/soc-dashboard/`)
- Modify `vite.config.ts`: change `base` from `"/ui/"` to `"/dashboard/"`
- Remove hidden pages from `App.tsx` routes and sidebar: Control Plane, VM Status, Audit Log
- Remove write-action buttons from Explorer (D3/Watch) and Campaigns (bulk actions)
- Build → `/opt/swarmtrap/dashboard/dist/` on VM 200

**Data proxy:**
- Caddy proxies `/dashboard/data/*` → PV1 `192.168.0.100:8010/data/*` (GET only)
- Caddy injects `X-API-Key: {readonly_key}` header — visitors never see the key
- All POST/PUT/DELETE/PATCH to `/dashboard/data/*` blocked (Caddy returns 403)
- Hidden page URLs (`/dashboard/control`, `/dashboard/vms`, `/dashboard/audit`) redirect to `/dashboard`

**PV1 auth:**
- Create a read-only API key in PV1's backend config (add to the existing auth mechanism in `app.py`)
- Store the key in VM 200's environment as `SOC_READONLY_KEY`
- No other changes to PV1

### Join Page (`/join`)

The cooperative pitch + signup form.

**Headline:** "Own What You Build"

**Pitch (3-4 paragraphs):**
- SwarmTrap is not a company. It's a cooperative. 90% of net revenue goes to the people who build, operate, and improve the system.
- No investors extracting value. No stock options that vest in four years. You contribute, you earn — transparently, from day one.
- The first contributors build Foundation — the open-source platform that powers every Open Utopia cooperative. The ledger, the voting system, the distribution engine, the decentralized node network. You build the ground everything stands on.
- We need developers, data scientists, security researchers, honeypot operators, and anyone who believes cybersecurity intelligence should be built by the community that uses it.

**Signup Form:**

```html
<form action="/api/signup" method="POST">
  <input type="text" name="name" placeholder="Your name" required>
  <input type="email" name="email" placeholder="Email" required>

  <fieldset>
    <legend>What would you contribute?</legend>
    <label><input type="checkbox" name="roles" value="node_operator"> Node Operator</label>
    <label><input type="checkbox" name="roles" value="developer"> Developer</label>
    <label><input type="checkbox" name="roles" value="ml_data_scientist"> ML / Data Scientist</label>
    <label><input type="checkbox" name="roles" value="security_researcher"> Security Researcher</label>
    <label><input type="checkbox" name="roles" value="community_governance"> Community / Governance</label>
  </fieldset>

  <textarea name="why" placeholder="Why SwarmTrap? (optional)" maxlength="500"></textarea>

  <!-- Honeypot: hidden from humans, bots fill it -->
  <div style="position:absolute;left:-9999px" aria-hidden="true">
    <input type="text" name="website" tabindex="-1" autocomplete="off">
  </div>

  <button type="submit">Join the founding cohort</button>
</form>
```

Form submits via JS fetch (not traditional form POST) to avoid page reload. On success, redirect to `/welcome`.

### Welcome Page (`/welcome`)

**Headline:** "You're in the founding cohort."

**Body:**
- "The first contributors build Foundation — the platform every Open Utopia cooperative runs on. These documents are your blueprints."

**Document downloads (served as markdown from `/docs/`):**
- SwarmTrap Founding Document v4
- Foundation v0.1 Complete Design
- Open Utopia Framework v4

**Source code link:**
- Link to SwarmTrap GitHub repo (TBD — create `github.com/SwarmTrap` org before launch)

**Closing:** "Read the designs. Find what you want to build. We'll be in touch."

---

## Backend

### Signup API (VM 200)

Extend existing `proxy.py` (FastAPI on :8099).

**New endpoint:**

```
POST /api/signup
Content-Type: application/json

{
  "name": "string (required, max 128)",
  "email": "string (required, valid email, max 256)",
  "roles": ["string"] (at least one required),
  "why": "string (optional, max 500)",
  "website": "string (honeypot, must be empty)"
}

Response 200: {"status": "ok"}
Response 400: {"error": "description"}
Response 429: {"error": "rate limited"}
```

**Validation:**
- `name`: required, 1-128 chars, strip whitespace
- `email`: required, valid email format, max 256 chars, strip whitespace
- `roles`: required, at least one, each must be one of: `node_operator`, `developer`, `ml_data_scientist`, `security_researcher`, `community_governance`
- `why`: optional, max 500 chars
- `website`: honeypot — if non-empty, return 200 (fake success, don't store). Bot thinks it worked.

**Rate limiting:**
- Max 5 signups per IP per hour (in-memory dict with TTL)
- Returns 429 if exceeded

**Storage:**

SQLite at `/opt/swarmtrap/signups.db`:

```sql
CREATE TABLE signups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    roles TEXT NOT NULL,           -- JSON array
    why TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE UNIQUE INDEX idx_signups_email ON signups(email);
```

Duplicate email: return 200 with a note ("You've already signed up — we'll be in touch."). Don't leak whether the email exists to bots.

### Existing Endpoints (unchanged)

```
GET /api/stats    → cached PV1 stats (already exists in proxy.py)
```

---

## Caddy Configuration (VM 200)

```caddyfile
swarmtrap.net {
    # Block write methods on dashboard proxy
    @dashboard_write {
        method POST PUT DELETE PATCH
        path /dashboard/data/*
    }
    respond @dashboard_write 403

    # Block hidden SOC pages
    @hidden_soc {
        path /dashboard/control* /dashboard/vms* /dashboard/audit*
    }
    redir @hidden_soc /dashboard 302

    # SOC dashboard — static React build (public variant)
    handle_path /dashboard/data/* {
        reverse_proxy 192.168.0.100:8010 {
            header_up X-API-Key {env.SOC_READONLY_KEY}
            header_up Host {upstream_hostport}
            rewrite * /data/{path}
        }
    }

    handle_path /dashboard/* {
        root * /opt/swarmtrap/dashboard/dist
        try_files {path} /index.html
        file_server
    }

    handle /dashboard {
        redir /dashboard/ 302
    }

    # API proxy (signup + stats)
    handle /api/* {
        reverse_proxy localhost:8099
    }

    # Founding documents
    handle /docs/* {
        root * /opt/swarmtrap/docs
        file_server
    }

    # Static site
    handle {
        root * /opt/swarmtrap/site
        try_files {path} {path}.html {path}/index.html
        file_server
    }
}
```

---

## File Structure

```
/home/colo8gent/SwarmTrap/          (local source)
  site/
    index.html                       main page (hero + 3 hooks)
    thesis.html                      full thesis page
    proof.html                       proof teaser + SOC link
    join.html                        cooperative pitch + signup form
    welcome.html                     post-signup confirmation
    style.css                        shared styles (dark theme)
    main.js                          fetch stats, form submission
  proxy/
    proxy.py                         FastAPI (stats proxy + signup endpoint)
  dashboard/
    soc-dashboard/                   copy of PV1 React app source
      vite.config.ts                 modified: base="/dashboard/"
      src/App.tsx                    modified: hidden pages removed
      dist/                          built output for VM 200
  docs/
    SwarmTrap_Founding_Document_v4.md
    Foundation_v0_1_Complete_Design.md
    Open_Utopia_Framework_v4.md
    specs/
      2026-04-13-site-redesign.md    this file
```

**Deployed on VM 200:**

```
/opt/swarmtrap/
  site/                              static HTML/CSS/JS pages
  dashboard/dist/                    public SOC React build
  proxy/                             FastAPI app + venv
  docs/                              founding documents for download
  signups.db                         SQLite signup database
```

---

## Deployment Steps

1. Write new static pages locally (index, thesis, proof, join, welcome, updated CSS/JS)
2. Update `proxy.py` with signup endpoint + SQLite + rate limiting
3. Copy PV1 SOC dashboard source, modify `vite.config.ts` (base="/dashboard/"), remove hidden pages from sidebar/routes, build
4. Create read-only API key on PV1 for the SOC data proxy
5. SCP all files to VM 200
6. Update Caddyfile on VM 200
7. Copy founding documents to `/opt/swarmtrap/docs/`
8. Test:
   - All static pages render
   - Thesis/proof/join navigation works
   - `/dashboard` loads SOC React app
   - SOC data endpoints return data (via readonly key)
   - POST/PUT/DELETE to dashboard blocked (403)
   - Hidden pages redirect to `/dashboard`
   - Signup form submits, writes to SQLite
   - Honeypot field rejects bots silently
   - Rate limiting works
   - Document downloads work
9. DNS already points swarmtrap.net → 216.126.0.205 (no change needed)

---

## Visual Direction

Same dark theme as current, extended across all pages:
- Background: #0a0a0a
- Text: #e8e8e8, muted: #666
- Accent: #00ff88 (green)
- Monospace accents for technical content (Courier New)
- Serif body text (Georgia) for the thesis narrative
- High contrast, minimal, lots of whitespace
- Hook cards on main page: subtle border, hover effect
- SOC dashboard: keeps its own Tailwind dark theme (compatible palette)

---

## What Changes on PV1

- Create one read-only API key for the public SOC proxy. Add to PV1 backend's auth config (the `X-API-Key` check in `app.py`). This key only needs to authorize GET requests on `/data/*` endpoints.
- That's it. No code changes, no auth logic changes, no new endpoints.

---

## What's NOT in This Spec

- Email confirmation / verification (manual review for now)
- Notification when someone signs up (check SQLite manually or add later)
- Full Foundation platform (the signups BUILD that)
- User accounts / login on swarmtrap.net
- Mobile app
- Product pages / pricing
- Token economics details on-site (link to documents instead)
