# SwarmTrap.net — Landing Page Design Spec

> Date: 2026-04-13
> Status: Approved

## Purpose

Single-page manifesto landing page for SwarmTrap, the cybersecurity threat intelligence cooperative. Primary audience: potential contributors (developers, data scientists, honeypot operators). Tone: movement/manifesto — "join us and own what you build."

## Sections

### 1. Hero
- SwarmTrap wordmark/logo
- One-line thesis hook: conveys the TCP physics insight in a punchy sentence
- Scroll CTA to read the thesis

### 2. The Thesis
- Narrative argument (not bullet points), written to make a security professional stop and think
- Core argument from the founding document:
  - AI can generate infinite zero-day exploits
  - But TCP forces a mandatory sequence: scan → knock → exploit
  - The knock phase is observable — the attacker MUST reveal technique before damage
  - Globally distributed honeypots capture knock sequences before exploits reach real targets
  - More AI attacks = more training data = better detection (attackers fuel their own detection)
  - A cooperative is the only economic model that scales the sensor network (hundreds of $2-6/mo VMs incentivized by contribution tokens)

### 3. Live Proof
- Real-time stats from the running system, proving the thesis isn't theoretical
- Data pulled via JS fetch from a public API proxy on PV2
- Stats to display:
  - Total IPs tracked
  - Confirmed attackers (evidence-backed)
  - Honeypot sensors active
  - XGB model accuracy
  - Packets processed per second
  - Evidence events collected
- Minimal, impactful — numbers with short labels, not charts or tables

### 4. The Invitation
- Short cooperative pitch: contributors own what they build, 90/10 profit distribution
- Single CTA: join waitlist (email capture) or link to founding document
- Secondary links: GitHub, founding document PDF

## Tech Stack

- **Frontend:** Plain HTML + CSS + JS. No framework, no build step.
- **Hosting:** PV2 (192.168.0.215), served by Caddy or nginx
- **API Proxy:** Lightweight Python (FastAPI or Flask) on PV2, reads from PV1 backend (192.168.0.100:8010), exposes read-only public endpoints
- **Code location:** `/home/colo8gent/SwarmTrap/`

## Data Flow

```
PV1 backend (:8010, private)
    ↓ PV2 reads via internal network
PV2 API proxy (:443, public)
    ↓ CORS-enabled JSON
SwarmTrap.net browser JS
    ↓ fetch() on page load
Renders stats in Section 3
```

## File Structure

```
/home/colo8gent/SwarmTrap/
  site/
    index.html        — single page
    style.css         — dark theme styles
    main.js           — fetch stats, render
    assets/           — logo, fonts, images
  proxy/
    proxy.py          — FastAPI read-only proxy
    requirements.txt  — fastapi, uvicorn, httpx
  docs/
    specs/            — this file
```

## API Proxy Endpoints (PV2, public)

| Endpoint | Source | Returns |
|----------|--------|---------|
| GET /api/stats | PV1 /data/god/health + /data/god/training | Merged summary stats |

Single endpoint, cached 60s, CORS enabled. No authentication required. Read-only — no write operations exposed.

## Visual Direction

- Dark background (#0a0a0a or similar)
- Monospace accents for technical content
- High contrast text (white/green on dark)
- Minimal — lots of whitespace, no clutter
- Stats section: large numbers, subtle glow or accent color
- No stock photos, no illustrations — just words and numbers
- Movement energy: the typography and spacing do the work

## Deployment

1. Write site files locally in `/home/colo8gent/SwarmTrap/`
2. Set up API proxy on PV2
3. Set up web server (Caddy) on PV2
4. Point SwarmTrap.net DNS to PV2's public IP
5. TLS via Caddy automatic HTTPS

## Out of Scope (for now)

- User accounts / authentication
- Email capture backend (use external form service or mailto)
- Product pages, pricing, documentation
- Token economics details
- Full founding document on-site (link to PDF/external)
- Mobile app
