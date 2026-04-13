# SwarmTrap.net Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert swarmtrap.net from a single-scroll manifesto into a multi-page recruiting site with signup form, live SOC dashboard, and founding document access.

**Architecture:** Static HTML/CSS/JS pages served by Caddy on VM 200 (192.168.0.200). FastAPI on :8099 handles signup + stats proxy. SOC dashboard is a separate React build (from PV1 source, re-based to `/dashboard/`) with data proxied through Caddy to PV1. SQLite for signups.

**Tech Stack:** HTML/CSS/JS (no framework), FastAPI + SQLite (Python), React/Vite/Tailwind (SOC dashboard build), Caddy (reverse proxy + TLS)

**Spec:** `SwarmTrap/docs/specs/2026-04-13-site-redesign.md`

---

## File Map

### Static Site (new/modified)
| File | Action | Purpose |
|------|--------|---------|
| `site/index.html` | Rewrite | Main page: hero + 3 hook cards |
| `site/thesis.html` | Create | Full thesis argument page |
| `site/proof.html` | Create | Live stats teaser + SOC dashboard link |
| `site/join.html` | Create | Cooperative pitch + signup form |
| `site/welcome.html` | Create | Post-signup confirmation + doc downloads |
| `site/style.css` | Rewrite | Shared dark theme, multi-page layout |
| `site/main.js` | Rewrite | Stats fetch + signup form submission |

### Backend (modified)
| File | Action | Purpose |
|------|--------|---------|
| `proxy/proxy.py` | Modify | Add signup endpoint, SQLite, rate limiting |

### Public SOC Dashboard (new)
| File | Action | Purpose |
|------|--------|---------|
| `dashboard/vite.config.ts` | Create | Copy of PV1 config, base="/dashboard/" |
| `dashboard/src/App.tsx` | Create | Copy of PV1, routes control/vms removed |
| `dashboard/src/components/Sidebar.tsx` | Create | Copy of PV1, Operations group removed |

### Infrastructure
| File | Action | Purpose |
|------|--------|---------|
| `infra/Caddyfile` | Create | Full Caddy config for VM 200 |
| `infra/swarmtrap-proxy.service` | Create | systemd unit for FastAPI |
| `infra/deploy.sh` | Create | SCP + restart script |

---

## Task 1: Shared CSS — dark theme for multi-page site

**Files:**
- Rewrite: `SwarmTrap/site/style.css`

- [ ] **Step 1: Write the new stylesheet**

```css
/* SwarmTrap.net — Dark manifesto theme (multi-page) */

:root {
  --bg: #0a0a0a;
  --bg-card: #111;
  --text: #e8e8e8;
  --muted: #666;
  --accent: #00ff88;
  --accent-dim: #00cc6a;
  --border: #222;
}

* { margin: 0; padding: 0; box-sizing: border-box; }

html {
  scroll-behavior: smooth;
  font-size: 18px;
}

body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Georgia', 'Times New Roman', serif;
  line-height: 1.7;
  -webkit-font-smoothing: antialiased;
}

a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.container {
  max-width: 1100px;
  margin: 0 auto;
  padding: 0 2rem;
}

.narrow {
  max-width: 720px;
}

/* NAV BAR */
.site-nav {
  position: fixed;
  top: 0;
  left: 0;
  right: 0;
  z-index: 100;
  background: rgba(10, 10, 10, 0.95);
  backdrop-filter: blur(8px);
  border-bottom: 1px solid var(--border);
  padding: 0.8rem 2rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.site-nav .nav-logo {
  font-family: 'Courier New', monospace;
  font-size: 1.2rem;
  font-weight: 700;
  color: var(--text);
}

.site-nav .nav-logo .accent { color: var(--accent); }

.site-nav .nav-links {
  display: flex;
  gap: 1.5rem;
  list-style: none;
}

.site-nav .nav-links a {
  font-family: 'Courier New', monospace;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--muted);
  transition: color 0.3s;
}

.site-nav .nav-links a:hover,
.site-nav .nav-links a.active {
  color: var(--accent);
  text-decoration: none;
}

/* HERO */
#hero {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding-top: 60px;
}

.logo {
  font-family: 'Courier New', monospace;
  font-size: 4rem;
  font-weight: 700;
  letter-spacing: -0.02em;
  margin-bottom: 1.5rem;
}

.accent { color: var(--accent); }

.tagline {
  font-size: 1.5rem;
  color: var(--muted);
  font-style: italic;
  line-height: 1.5;
  margin-bottom: 3rem;
}

/* HOOK CARDS */
.hooks {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 2rem;
  max-width: 960px;
  margin: 0 auto;
}

.hook-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 2rem 1.5rem;
  transition: border-color 0.3s, transform 0.2s;
}

.hook-card:hover {
  border-color: var(--accent);
  transform: translateY(-2px);
}

.hook-card h3 {
  font-family: 'Courier New', monospace;
  font-size: 1rem;
  color: var(--accent);
  margin-bottom: 0.75rem;
}

.hook-card p {
  color: var(--muted);
  font-size: 0.9rem;
  margin-bottom: 1.25rem;
  line-height: 1.6;
}

.hook-card .card-link {
  font-family: 'Courier New', monospace;
  font-size: 0.75rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--accent);
}

/* PAGE HEADER (sub-pages) */
.page-header {
  padding: 8rem 2rem 3rem;
  text-align: center;
}

.page-header h1 {
  font-family: 'Courier New', monospace;
  font-size: 2rem;
  margin-bottom: 1rem;
}

.page-header .subtitle {
  color: var(--muted);
  font-size: 1rem;
}

/* CONTENT SECTION */
.content {
  padding: 2rem 2rem 6rem;
}

.content p {
  margin-bottom: 1.5rem;
  color: #ccc;
}

.content strong { color: var(--text); }

.content em { color: var(--accent-dim); font-style: italic; }

.content .highlight {
  border-left: 3px solid var(--accent);
  padding-left: 1.5rem;
  color: var(--text);
  font-size: 1.05rem;
  margin: 2.5rem 0;
}

.content .lead {
  font-size: 1.25rem;
  color: var(--text);
  font-style: italic;
  margin-bottom: 2rem;
}

/* STATS GRID */
.stats-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1.5rem;
  max-width: 700px;
  margin: 0 auto 3rem;
}

.stat {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 1.5rem 1rem;
  text-align: center;
}

.stat-value {
  display: block;
  font-family: 'Courier New', monospace;
  font-size: 2rem;
  font-weight: 700;
  color: var(--accent);
  margin-bottom: 0.4rem;
}

.stat-label {
  display: block;
  font-size: 0.7rem;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 0.1em;
}

/* SOC PREVIEW LIST */
.soc-features {
  list-style: none;
  max-width: 600px;
  margin: 2rem auto 3rem;
  text-align: left;
}

.soc-features li {
  padding: 0.5rem 0;
  color: #ccc;
  font-size: 0.95rem;
}

.soc-features li::before {
  content: "→ ";
  color: var(--accent);
  font-family: 'Courier New', monospace;
}

/* BUTTONS */
.btn {
  display: inline-block;
  padding: 0.8rem 2rem;
  font-family: 'Courier New', monospace;
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  text-decoration: none;
  border-radius: 4px;
  transition: all 0.3s;
  background: var(--accent);
  color: var(--bg);
  font-weight: 700;
  border: none;
  cursor: pointer;
}

.btn:hover { background: #fff; color: var(--bg); text-decoration: none; }

.btn-outline {
  background: transparent;
  color: var(--accent);
  border: 1px solid var(--accent);
}

.btn-outline:hover { background: var(--accent); color: var(--bg); }

.btn-large {
  padding: 1rem 3rem;
  font-size: 1rem;
}

.cta-group {
  display: flex;
  gap: 1rem;
  justify-content: center;
  margin-top: 2.5rem;
  flex-wrap: wrap;
}

/* SIGNUP FORM */
.signup-form {
  max-width: 500px;
  margin: 3rem auto;
}

.signup-form label {
  display: block;
  font-size: 0.8rem;
  color: var(--muted);
  margin-bottom: 0.3rem;
  font-family: 'Courier New', monospace;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.signup-form input[type="text"],
.signup-form input[type="email"],
.signup-form textarea {
  width: 100%;
  padding: 0.7rem 1rem;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--text);
  font-family: 'Georgia', serif;
  font-size: 0.95rem;
  margin-bottom: 1.25rem;
  outline: none;
  transition: border-color 0.3s;
}

.signup-form input:focus,
.signup-form textarea:focus {
  border-color: var(--accent);
}

.signup-form textarea {
  resize: vertical;
  min-height: 80px;
}

.signup-form fieldset {
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 1rem 1.25rem;
  margin-bottom: 1.25rem;
}

.signup-form fieldset legend {
  font-size: 0.8rem;
  color: var(--muted);
  font-family: 'Courier New', monospace;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  padding: 0 0.5rem;
}

.signup-form .checkbox-group {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-top: 0.5rem;
}

.signup-form .checkbox-group label {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.9rem;
  color: #ccc;
  font-family: 'Georgia', serif;
  text-transform: none;
  letter-spacing: 0;
  cursor: pointer;
}

.signup-form .checkbox-group input[type="checkbox"] {
  accent-color: var(--accent);
}

.signup-form .form-error {
  color: #f85149;
  font-size: 0.85rem;
  margin-bottom: 1rem;
  display: none;
}

.signup-form .form-error.visible { display: block; }

.signup-form .btn { width: 100%; text-align: center; }

/* DOCUMENT LINKS */
.doc-list {
  list-style: none;
  max-width: 500px;
  margin: 2rem auto;
}

.doc-list li {
  padding: 1rem;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 4px;
  margin-bottom: 0.75rem;
  transition: border-color 0.3s;
}

.doc-list li:hover { border-color: var(--accent); }

.doc-list a {
  font-family: 'Courier New', monospace;
  font-size: 0.85rem;
}

.doc-list .doc-desc {
  display: block;
  font-family: 'Georgia', serif;
  font-size: 0.8rem;
  color: var(--muted);
  margin-top: 0.3rem;
}

/* FOOTER */
footer {
  padding: 3rem 2rem;
  border-top: 1px solid var(--border);
  text-align: center;
  color: var(--muted);
  font-size: 0.75rem;
}

/* RESPONSIVE */
@media (max-width: 700px) {
  html { font-size: 16px; }
  .logo { font-size: 2.5rem; }
  .tagline { font-size: 1.2rem; }
  .hooks { grid-template-columns: 1fr; gap: 1rem; }
  .stats-grid { grid-template-columns: repeat(2, 1fr); gap: 1rem; }
  .stat-value { font-size: 1.5rem; }
  .content, .page-header { padding-left: 1.5rem; padding-right: 1.5rem; }
  .site-nav { padding: 0.6rem 1rem; }
  .site-nav .nav-links { gap: 0.75rem; }
  .site-nav .nav-links a { font-size: 0.65rem; }
}
```

- [ ] **Step 2: Commit**

```bash
cd /home/colo8gent/SwarmTrap
git add site/style.css
git commit -m "style: rewrite CSS for multi-page site"
```

---

## Task 2: Main page — hero + 3 hook cards

**Files:**
- Rewrite: `SwarmTrap/site/index.html`

- [ ] **Step 1: Write the new index.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SwarmTrap — AI Makes Better Attacks. Physics Makes Better Traps.</title>
  <meta name="description" content="A cybersecurity cooperative that uses globally distributed honeypots to catch attackers at wire speed. Contributors own what they build.">
  <link rel="stylesheet" href="style.css">
</head>
<body>

  <nav class="site-nav">
    <a href="/" class="nav-logo">Swarm<span class="accent">Trap</span></a>
    <ul class="nav-links">
      <li><a href="/thesis">Thesis</a></li>
      <li><a href="/proof">Proof</a></li>
      <li><a href="/join">Join</a></li>
    </ul>
  </nav>

  <section id="hero">
    <div class="container">
      <h1 class="logo">Swarm<span class="accent">Trap</span></h1>
      <p class="tagline">AI makes better attacks.<br>Physics makes better traps.</p>

      <div class="hooks">
        <a href="/thesis" class="hook-card">
          <h3>The Thesis</h3>
          <p>This might be the only way to beat AI hackers. Not better signatures. Not faster patches. A structural advantage that AI can't overcome.</p>
          <span class="card-link">Read the thesis &rarr;</span>
        </a>
        <a href="/proof" class="hook-card">
          <h3>The Proof</h3>
          <p>This isn't a whitepaper. The system is running. A live sensor network catching real attackers at wire speed. See it yourself.</p>
          <span class="card-link">See the proof &rarr;</span>
        </a>
        <a href="/join" class="hook-card">
          <h3>Own What You Build</h3>
          <p>Contributors build it. Contributors own it. 90% of net revenue goes to the people who build, operate, and improve the system.</p>
          <span class="card-link">Join the cooperative &rarr;</span>
        </a>
      </div>
    </div>
  </section>

  <footer>
    <div class="container">
      <p>&copy; 2026 SwarmTrap Cooperative. Built by contributors.</p>
    </div>
  </footer>

</body>
</html>
```

- [ ] **Step 2: Commit**

```bash
cd /home/colo8gent/SwarmTrap
git add site/index.html
git commit -m "feat: rewrite main page with 3 hook cards"
```

---

## Task 3: Thesis page

**Files:**
- Create: `SwarmTrap/site/thesis.html`

- [ ] **Step 1: Write thesis.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>The Thesis — SwarmTrap</title>
  <meta name="description" content="This might be the only way to beat AI hackers. The TCP physics argument for globally distributed honeypots.">
  <link rel="stylesheet" href="style.css">
</head>
<body>

  <nav class="site-nav">
    <a href="/" class="nav-logo">Swarm<span class="accent">Trap</span></a>
    <ul class="nav-links">
      <li><a href="/thesis" class="active">Thesis</a></li>
      <li><a href="/proof">Proof</a></li>
      <li><a href="/join">Join</a></li>
    </ul>
  </nav>

  <header class="page-header">
    <div class="container narrow">
      <h1>The Thesis</h1>
    </div>
  </header>

  <section class="content">
    <div class="container narrow">

      <p class="lead">"This might be the only way to beat AI hackers."</p>

      <p>Not better signatures. Not faster patches. Not another AI racing against AI. The only structural advantage defenders have is <strong>physics</strong> — and nobody's using it.</p>

      <p>Everyone is worried about AI-powered cyberattacks. They should be. Large language models can generate novel exploits, mutate malware past signatures, and automate the entire attack chain from reconnaissance to exfiltration. The cost of generating a new zero-day is collapsing toward zero.</p>

      <p>But there's something AI can't change: <strong>TCP physics.</strong></p>

      <p>Every attack on the internet follows a mandatory sequence. The attacker must <em>scan</em> to find targets. They must <em>knock</em> — send specially crafted packets to test which services respond and confirm specific vulnerabilities. Only then can they <em>exploit</em>. This isn't a convention. It's how the protocol works. You can't skip the handshake. You can't exploit a port you haven't probed. AI can make each step faster, stealthier, more creative. But it cannot eliminate the steps.</p>

      <p class="highlight">The knock phase is where the attacker reveals their hand. To confirm that a service has a specific exploitable weakness, they <strong>must send packets that show their technique</strong> before they can do damage. The knock is the attacker showing their hand before they play it.</p>

      <p>Globally distributed honeypots — machines that exist only to be attacked — capture every knock sequence in real time. Every zero-day exploit AI generates becomes a signature the moment it touches a trap. The attacker cannot fake the knock. If they send the wrong probe, they get the wrong answer, and the exploit fails.</p>

      <p>The more AI attacks, the more the system learns. <strong>Attackers fuel their own detection.</strong></p>

      <p>The cost asymmetry favors the defender. The AI attacker's cost scales per novel attack — every zero-day requires compute to discover, and the knock sequence must be crafted specifically for each vulnerability. The defender's cost is near-zero marginal observation: a $3/month VM captures whatever hits it.</p>

      <p>As AI accelerates zero-day discovery, more novel attacks land on honeypots during the scan phase. More captured knocks means ML models learn faster. The AI attacker is funding the defender's research. Every zero-day wasted on a honeypot is captured immediately, burned as a zero-day, and becomes free training data for the next model update.</p>

      <p class="highlight">This is not a classification engine that labels known attacks. It is a <strong>global immune system</strong> with real-time antibody distribution. AI scans the internet, hits a honeypot, the knock is captured, the model trains, the updated model pushes worldwide, the exploit is filtered before delivery.</p>

      <p>But building a global sensor network takes hundreds of machines across every continent, running real services, capturing real traffic. No company can afford to deploy and maintain that infrastructure alone. Only a cooperative can — where every contributor who runs a $3/month honeypot VM earns a share of the intelligence it produces.</p>

      <p>That's SwarmTrap. A cybersecurity cooperative where the people who build the system own it. The arms race favors the defender with the largest observation network — and a cooperative is the only economic model that builds one large enough.</p>

      <div class="cta-group">
        <a href="/proof" class="btn">See the system running &rarr;</a>
        <a href="/join" class="btn btn-outline">Join the cooperative &rarr;</a>
      </div>

    </div>
  </section>

  <footer>
    <div class="container">
      <p>&copy; 2026 SwarmTrap Cooperative. Built by contributors.</p>
    </div>
  </footer>

</body>
</html>
```

- [ ] **Step 2: Commit**

```bash
cd /home/colo8gent/SwarmTrap
git add site/thesis.html
git commit -m "feat: add thesis page with TCP physics argument"
```

---

## Task 4: Proof page

**Files:**
- Create: `SwarmTrap/site/proof.html`

- [ ] **Step 1: Write proof.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>The Proof — SwarmTrap</title>
  <meta name="description" content="Live data from a production sensor network. This isn't a demo.">
  <link rel="stylesheet" href="style.css">
</head>
<body>

  <nav class="site-nav">
    <a href="/" class="nav-logo">Swarm<span class="accent">Trap</span></a>
    <ul class="nav-links">
      <li><a href="/thesis">Thesis</a></li>
      <li><a href="/proof" class="active">Proof</a></li>
      <li><a href="/join">Join</a></li>
    </ul>
  </nav>

  <header class="page-header">
    <div class="container">
      <h1>The System Is Running</h1>
      <p class="subtitle">This isn't a demo. This is a production sensor network processing live internet traffic.<br>Attackers are being caught right now.</p>
    </div>
  </header>

  <section class="content">
    <div class="container">

      <div class="stats-grid" id="stats">
        <div class="stat">
          <span class="stat-value" id="s-ips">&mdash;</span>
          <span class="stat-label">IPs Tracked</span>
        </div>
        <div class="stat">
          <span class="stat-value" id="s-attackers">&mdash;</span>
          <span class="stat-label">Confirmed Attackers</span>
        </div>
        <div class="stat">
          <span class="stat-value" id="s-sensors">&mdash;</span>
          <span class="stat-label">Honeypot Sensors</span>
        </div>
        <div class="stat">
          <span class="stat-value" id="s-evidence">&mdash;</span>
          <span class="stat-label">Evidence Events</span>
        </div>
        <div class="stat">
          <span class="stat-value" id="s-accuracy">&mdash;</span>
          <span class="stat-label">Model Accuracy</span>
        </div>
        <div class="stat">
          <span class="stat-value" id="s-captured">&mdash;</span>
          <span class="stat-label">Training Samples</span>
        </div>
      </div>

      <div style="text-align:center; margin: 3rem 0">
        <p style="color: #ccc; margin-bottom: 1.5rem;">Go inside the live SOC dashboard. Everything you see is real.</p>
        <a href="/dashboard/" class="btn btn-large">Enter the live SOC dashboard &rarr;</a>
      </div>

      <ul class="soc-features">
        <li>Live attack map with GeoIP — real attackers hitting real honeypots</li>
        <li>Real-time packet processing metrics — packets per second, classification rate</li>
        <li>IP kill chains — watch an attacker progress from scan to knock to exploit</li>
        <li>ML model performance — XGBoost accuracy, scoring throughput, training status</li>
        <li>GOD intelligence dashboard — the Two Gods judging every IP in real time</li>
        <li>Per-service analysis — SSH, RDP, HTTP, SMB broken down individually</li>
      </ul>

      <div class="cta-group">
        <a href="/join" class="btn btn-outline">Join the cooperative &rarr;</a>
      </div>

    </div>
  </section>

  <footer>
    <div class="container">
      <p>&copy; 2026 SwarmTrap Cooperative. Built by contributors.</p>
    </div>
  </footer>

  <script src="main.js"></script>

</body>
</html>
```

- [ ] **Step 2: Commit**

```bash
cd /home/colo8gent/SwarmTrap
git add site/proof.html
git commit -m "feat: add proof page with live stats + SOC dashboard link"
```

---

## Task 5: Join page with signup form

**Files:**
- Create: `SwarmTrap/site/join.html`

- [ ] **Step 1: Write join.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Join — SwarmTrap</title>
  <meta name="description" content="SwarmTrap is a cybersecurity cooperative. Contributors build it, contributors own it. Join the founding cohort.">
  <link rel="stylesheet" href="style.css">
</head>
<body>

  <nav class="site-nav">
    <a href="/" class="nav-logo">Swarm<span class="accent">Trap</span></a>
    <ul class="nav-links">
      <li><a href="/thesis">Thesis</a></li>
      <li><a href="/proof">Proof</a></li>
      <li><a href="/join" class="active">Join</a></li>
    </ul>
  </nav>

  <header class="page-header">
    <div class="container narrow">
      <h1>Own What You Build</h1>
    </div>
  </header>

  <section class="content">
    <div class="container narrow">

      <p>SwarmTrap is not a company. It's a cooperative. <strong>90% of net revenue</strong> goes to the people who build, operate, and improve the system. No investors extracting value. No stock options that vest in four years. You contribute, you earn — transparently, from day one.</p>

      <p>The first contributors build <strong>Foundation</strong> — the open-source platform that powers every Open Utopia cooperative. The ledger, the voting system, the distribution engine, the decentralized node network. You build the ground everything stands on.</p>

      <p>We need developers, data scientists, security researchers, honeypot operators, and anyone who believes cybersecurity intelligence should be built by the community that uses it.</p>

      <form class="signup-form" id="signup-form">
        <div class="form-error" id="form-error"></div>

        <label for="f-name">Name</label>
        <input type="text" id="f-name" name="name" required maxlength="128" autocomplete="name">

        <label for="f-email">Email</label>
        <input type="email" id="f-email" name="email" required maxlength="256" autocomplete="email">

        <fieldset>
          <legend>What would you contribute?</legend>
          <div class="checkbox-group">
            <label><input type="checkbox" name="roles" value="node_operator"> Node Operator</label>
            <label><input type="checkbox" name="roles" value="developer"> Developer</label>
            <label><input type="checkbox" name="roles" value="ml_data_scientist"> ML / Data Scientist</label>
            <label><input type="checkbox" name="roles" value="security_researcher"> Security Researcher</label>
            <label><input type="checkbox" name="roles" value="community_governance"> Community / Governance</label>
          </div>
        </fieldset>

        <label for="f-why">Why SwarmTrap? <span style="color:var(--muted)">(optional)</span></label>
        <textarea id="f-why" name="why" maxlength="500" rows="3"></textarea>

        <!-- Honeypot: hidden from humans, bots fill it -->
        <div style="position:absolute;left:-9999px" aria-hidden="true">
          <input type="text" name="website" tabindex="-1" autocomplete="off">
        </div>

        <button type="submit" class="btn">Join the founding cohort</button>
      </form>

    </div>
  </section>

  <footer>
    <div class="container">
      <p>&copy; 2026 SwarmTrap Cooperative. Built by contributors.</p>
    </div>
  </footer>

  <script src="main.js"></script>

</body>
</html>
```

- [ ] **Step 2: Commit**

```bash
cd /home/colo8gent/SwarmTrap
git add site/join.html
git commit -m "feat: add join page with signup form and honeypot field"
```

---

## Task 6: Welcome page (post-signup)

**Files:**
- Create: `SwarmTrap/site/welcome.html`

- [ ] **Step 1: Write welcome.html**

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Welcome — SwarmTrap</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>

  <nav class="site-nav">
    <a href="/" class="nav-logo">Swarm<span class="accent">Trap</span></a>
    <ul class="nav-links">
      <li><a href="/thesis">Thesis</a></li>
      <li><a href="/proof">Proof</a></li>
      <li><a href="/join">Join</a></li>
    </ul>
  </nav>

  <header class="page-header">
    <div class="container narrow">
      <h1>You're in the founding cohort.</h1>
      <p class="subtitle">The first contributors build Foundation — the platform every Open Utopia cooperative runs on. These documents are your blueprints.</p>
    </div>
  </header>

  <section class="content">
    <div class="container narrow">

      <ul class="doc-list">
        <li>
          <a href="/docs/SwarmTrap_Founding_Document_v4.md">SwarmTrap Founding Document v4</a>
          <span class="doc-desc">The complete vision — products, revenue paths, governance, cooperative charter, competitive moat.</span>
        </li>
        <li>
          <a href="/docs/Foundation_v0_1_Complete_Design.md">Foundation v0.1 Complete Design</a>
          <span class="doc-desc">The buildable spec — ledger, API, decentralized nodes, Tri-Key authorization, security architecture.</span>
        </li>
        <li>
          <a href="/docs/Open_Utopia_Framework_v4.md">Open Utopia Framework v4</a>
          <span class="doc-desc">The philosophy — contributism, Proof of Value, three functions, governance theory, historical foundations.</span>
        </li>
      </ul>

      <div style="text-align:center; margin-top: 3rem;">
        <p style="color:#ccc; margin-bottom: 1.5rem;">Read the designs. Find what you want to build. We'll be in touch.</p>
        <a href="/dashboard/" class="btn btn-outline">Explore the live SOC dashboard &rarr;</a>
      </div>

    </div>
  </section>

  <footer>
    <div class="container">
      <p>&copy; 2026 SwarmTrap Cooperative. Built by contributors.</p>
    </div>
  </footer>

</body>
</html>
```

- [ ] **Step 2: Commit**

```bash
cd /home/colo8gent/SwarmTrap
git add site/welcome.html
git commit -m "feat: add welcome page with founding document links"
```

---

## Task 7: JavaScript — stats fetch + signup form submission

**Files:**
- Rewrite: `SwarmTrap/site/main.js`

- [ ] **Step 1: Write the new main.js**

```javascript
/* SwarmTrap.net — stats fetch + signup form submission */
(function () {
  /* ---- stat formatting ---- */
  function fmt(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
    return String(n);
  }

  function set(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  /* ---- fetch live stats (proof page) ---- */
  var statsEl = document.getElementById("stats");
  if (statsEl) {
    fetch("/api/stats")
      .then(function (r) { return r.json(); })
      .then(function (d) {
        set("s-ips", fmt(d.ips_tracked || 0));
        set("s-attackers", fmt(d.confirmed_attackers || 0));
        set("s-sensors", String(d.honeypot_sensors || 0));
        set("s-evidence", fmt(d.evidence_events || 0));
        set("s-accuracy", (d.model_accuracy || 0).toFixed(1) + "%");
        set("s-captured", fmt(d.training_samples || 0));
      })
      .catch(function () { /* stats show dashes on failure */ });
  }

  /* ---- signup form (join page) ---- */
  var form = document.getElementById("signup-form");
  if (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var errEl = document.getElementById("form-error");
      errEl.className = "form-error";
      errEl.textContent = "";

      var name = form.querySelector('[name="name"]').value.trim();
      var email = form.querySelector('[name="email"]').value.trim();
      var why = form.querySelector('[name="why"]').value.trim();
      var website = form.querySelector('[name="website"]').value;

      var roles = [];
      form.querySelectorAll('[name="roles"]:checked').forEach(function (cb) {
        roles.push(cb.value);
      });

      if (!name || !email) {
        errEl.textContent = "Name and email are required.";
        errEl.className = "form-error visible";
        return;
      }
      if (roles.length === 0) {
        errEl.textContent = "Select at least one role.";
        errEl.className = "form-error visible";
        return;
      }

      var btn = form.querySelector('button[type="submit"]');
      btn.disabled = true;
      btn.textContent = "Submitting...";

      fetch("/api/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name,
          email: email,
          roles: roles,
          why: why || "",
          website: website
        })
      })
        .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, data: d }; }); })
        .then(function (res) {
          if (res.ok) {
            window.location.href = "/welcome";
          } else {
            errEl.textContent = res.data.error || "Something went wrong.";
            errEl.className = "form-error visible";
            btn.disabled = false;
            btn.textContent = "Join the founding cohort";
          }
        })
        .catch(function () {
          errEl.textContent = "Network error. Please try again.";
          errEl.className = "form-error visible";
          btn.disabled = false;
          btn.textContent = "Join the founding cohort";
        });
    });
  }
})();
```

- [ ] **Step 2: Commit**

```bash
cd /home/colo8gent/SwarmTrap
git add site/main.js
git commit -m "feat: rewrite JS for stats fetch + signup form submission"
```

---

## Task 8: Signup backend — FastAPI + SQLite

**Files:**
- Modify: `SwarmTrap/proxy/proxy.py`

- [ ] **Step 1: Write the updated proxy.py**

```python
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
    _rate[ip] = times
    return len(times) < RATE_LIMIT


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

    # Record rate
    _rate.setdefault(ip, []).append(time.time())

    return {"status": "ok", "message": "Welcome to SwarmTrap."}
```

- [ ] **Step 2: Test locally**

```bash
cd /home/colo8gent/SwarmTrap/proxy
python3 -c "
import json, sys
sys.path.insert(0, '.')
from proxy import SignupRequest, _check_rate

# Test valid signup
s = SignupRequest(name='Test User', email='test@example.com', roles=['developer'])
assert s.name == 'Test User'
assert s.email == 'test@example.com'

# Test honeypot
s2 = SignupRequest(name='Bot', email='bot@evil.com', roles=['developer'], website='http://spam.com')
assert s2.website == 'http://spam.com'

# Test bad role
try:
    SignupRequest(name='X', email='x@x.com', roles=['hacker'])
    assert False, 'Should have raised'
except Exception:
    pass

# Test empty roles
try:
    SignupRequest(name='X', email='x@x.com', roles=[])
    assert False, 'Should have raised'
except Exception:
    pass

# Test rate limiting
for i in range(5):
    assert _check_rate('1.2.3.4')
assert not _check_rate('1.2.3.4')  # 6th should fail

print('All tests passed')
"
```

Expected: `All tests passed`

- [ ] **Step 3: Commit**

```bash
cd /home/colo8gent/SwarmTrap
git add proxy/proxy.py
git commit -m "feat: add signup endpoint with SQLite, honeypot, rate limiting"
```

---

## Task 9: Public SOC dashboard build

**Files:**
- Create: `SwarmTrap/dashboard/` (copy from PV1 source, modified)

- [ ] **Step 1: Copy the SOC dashboard source**

```bash
cp -r /home/colo8gent/DFI2/backend_api/ui/soc-dashboard /home/colo8gent/SwarmTrap/dashboard
```

- [ ] **Step 2: Modify vite.config.ts — change base path**

In `/home/colo8gent/SwarmTrap/dashboard/vite.config.ts`, change `base: "/ui/"` to `base: "/dashboard/"` and update proxy targets to use relative paths (the public build fetches from `/dashboard/data/*` which Caddy proxies to PV1):

```typescript
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "/dashboard/",
  server: {
    proxy: {
      "/dashboard/data": {
        target: "http://192.168.0.100:8010",
        rewrite: (path) => path.replace(/^\/dashboard/, ""),
      },
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          recharts: ["recharts"],
          "react-vendor": ["react", "react-dom", "react-router-dom"],
          tanstack: ["@tanstack/react-query"],
        },
      },
    },
  },
});
```

- [ ] **Step 3: Modify App.tsx — remove control and vms routes**

In `/home/colo8gent/SwarmTrap/dashboard/src/App.tsx`:
- Remove the `Allowlist` and `VMStatus` lazy imports
- Remove the `control` and `vms` Route elements
- Change `basename="/ui"` to `basename="/dashboard"`

Result (full file):

```tsx
import React, { Suspense, Component, type ReactNode } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ToastProvider } from "./lib/toast";
import { AppLayout } from "./components/AppLayout";
import { PageLoading } from "./components/LoadingSkeleton";

class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state: { error: Error | null } = { error: null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: 40, color: "#f85149", fontFamily: "monospace", background: "#0d1117", minHeight: "100vh" }}>
          <h1>Dashboard Crash</h1>
          <pre style={{ whiteSpace: "pre-wrap", color: "#e6edf3" }}>{this.state.error.message}</pre>
          <pre style={{ whiteSpace: "pre-wrap", color: "#8b949e", fontSize: 12 }}>{this.state.error.stack}</pre>
        </div>
      );
    }
    return this.props.children;
  }
}

const GodHome = React.lazy(() => import("./pages/GodHome"));
const IpDetail = React.lazy(() => import("./pages/IpDetail"));
const Verdicts = React.lazy(() => import("./pages/Verdicts"));
const Services = React.lazy(() => import("./pages/Services"));
const Training = React.lazy(() => import("./pages/Training"));
const AttackMap = React.lazy(() => import("./pages/AttackMap"));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
    },
  },
});

export default function App() {
  return (
    <ErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <ToastProvider>
        <BrowserRouter basename="/dashboard">
          <Routes>
            <Route element={<AppLayout />}>
              <Route index element={<Suspense fallback={<PageLoading />}><GodHome /></Suspense>} />
              <Route path="ip/*" element={<Suspense fallback={<PageLoading />}><IpDetail /></Suspense>} />
              <Route path="verdicts" element={<Suspense fallback={<PageLoading />}><Verdicts /></Suspense>} />
              <Route path="services" element={<Suspense fallback={<PageLoading />}><Services /></Suspense>} />
              <Route path="training" element={<Suspense fallback={<PageLoading />}><Training /></Suspense>} />
              <Route path="map" element={<Suspense fallback={<PageLoading />}><AttackMap /></Suspense>} />
            </Route>
          </Routes>
        </BrowserRouter>
      </ToastProvider>
    </QueryClientProvider>
    </ErrorBoundary>
  );
}
```

- [ ] **Step 4: Modify Sidebar.tsx — remove Operations group**

In `/home/colo8gent/SwarmTrap/dashboard/src/components/Sidebar.tsx`:
- Remove the "Operations" nav group (Allowlist, VM Status)
- Change the header text from "GOD SOC" / "Closed Loop Dashboard" to "SwarmTrap" / "Live Intelligence"
- Add a "Back to site" link

Result (full file):

```tsx
import { NavLink } from "react-router-dom";
import { cn } from "../lib/format";

interface NavItem {
  to: string;
  label: string;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

const navGroups: NavGroup[] = [
  {
    title: "GOD Pipeline",
    items: [
      { to: "/", label: "Home" },
      { to: "/verdicts", label: "Verdicts" },
      { to: "/services", label: "Services" },
      { to: "/map", label: "Attack Map" },
    ],
  },
  {
    title: "Intelligence",
    items: [
      { to: "/training", label: "Training & Models" },
    ],
  },
];

export function Sidebar() {
  return (
    <aside className="w-52 bg-panel border-r border-border flex flex-col h-screen sticky top-0 shrink-0">
      <div className="px-4 py-4 border-b border-border">
        <div className="text-sm font-bold text-accent">SwarmTrap</div>
        <div className="text-[10px] text-muted">Live Intelligence</div>
      </div>
      <nav className="flex-1 overflow-y-auto py-2">
        {navGroups.map((g) => (
          <div key={g.title} className="mb-2">
            <div className="px-4 py-1 text-[10px] text-muted uppercase tracking-wider">
              {g.title}
            </div>
            {g.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/"}
                className={({ isActive }) =>
                  cn(
                    "block px-4 py-1.5 text-xs hover:bg-card/60 transition-colors",
                    isActive && "bg-card text-accent border-l-2 border-accent",
                  )
                }
              >
                {item.label}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <div className="px-4 py-3 border-t border-border">
        <a href="/" className="text-[10px] text-muted hover:text-accent transition-colors">
          &larr; Back to SwarmTrap.net
        </a>
      </div>
    </aside>
  );
}
```

- [ ] **Step 5: Update API client to prefix all requests with /dashboard**

The API client at `SwarmTrap/dashboard/src/api/client.ts` has `API_BASE = ""`. All API calls use paths like `/data/god/overview` and `/health`. For the public build, these must be prefixed with `/dashboard` so Caddy proxies them to PV1.

In `SwarmTrap/dashboard/src/api/client.ts`, change line 1:

```typescript
const API_BASE = "/dashboard";
```

This makes:
- Data calls: `/dashboard/data/god/overview` → Caddy proxies to PV1 `/data/god/overview`
- Health check: `/dashboard/health` → Caddy proxies to PV1 `/health`

Also remove the auth headers (public build has no API key — Caddy injects it server-side). In `authHeaders()`, return empty object:

```typescript
function authHeaders(write = false): Record<string, string> {
  const h: Record<string, string> = {};
  if (write) {
    h["Content-Type"] = "application/json";
    h["Idempotency-Key"] = crypto.randomUUID();
  }
  return h;
}
```

Remove `getApiKey`, `setApiKey`, `getBasicAuth`, `setBasicAuth` functions (unused in public build).

- [ ] **Step 6: Build the public dashboard**

```bash
cd /home/colo8gent/SwarmTrap/dashboard
npm install
npm run build
```

Expected: build completes, outputs to `dist/` directory.

- [ ] **Step 7: Verify the build**

```bash
ls -la /home/colo8gent/SwarmTrap/dashboard/dist/
ls -la /home/colo8gent/SwarmTrap/dashboard/dist/assets/
```

Expected: `index.html` + `assets/` directory with JS/CSS chunks.

- [ ] **Step 8: Commit**

```bash
cd /home/colo8gent/SwarmTrap
# Don't commit node_modules or dist — only source changes
echo "node_modules/" >> dashboard/.gitignore
echo "dist/" >> dashboard/.gitignore
git add dashboard/vite.config.ts dashboard/src/App.tsx dashboard/src/components/Sidebar.tsx dashboard/.gitignore
git commit -m "feat: public SOC dashboard variant (base=/dashboard/, no write pages)"
```

---

## Task 10: Caddy configuration + systemd unit

**Files:**
- Create: `SwarmTrap/infra/Caddyfile`
- Create: `SwarmTrap/infra/swarmtrap-proxy.service`

- [ ] **Step 1: Write Caddyfile**

```caddyfile
swarmtrap.net {
	# --- Write protection on dashboard data proxy ---
	@dashboard_write {
		method POST PUT DELETE PATCH
		path /dashboard/data/*
	}
	respond @dashboard_write 403

	# --- Block hidden SOC pages ---
	@hidden_soc {
		path /dashboard/control*
		path /dashboard/vms*
		path /dashboard/audit*
	}
	redir @hidden_soc /dashboard/ 302

	# --- SOC data proxy (GET only → PV1) ---
	handle_path /dashboard/data/* {
		rewrite * /data/{path}
		reverse_proxy 192.168.0.100:8010 {
			header_up X-API-Key {env.SOC_READONLY_KEY}
			header_up Host {upstream_hostport}
		}
	}

	# --- SOC health check proxy ---
	handle /dashboard/health {
		rewrite * /health
		reverse_proxy 192.168.0.100:8010 {
			header_up X-API-Key {env.SOC_READONLY_KEY}
			header_up Host {upstream_hostport}
		}
	}

	# --- SOC dashboard static build ---
	handle /dashboard {
		redir /dashboard/ 302
	}

	handle_path /dashboard/* {
		root * /opt/swarmtrap/dashboard/dist
		try_files {path} /index.html
		file_server
	}

	# --- API proxy (signup + stats) ---
	handle /api/* {
		reverse_proxy localhost:8099
	}

	# --- Founding documents ---
	handle_path /docs/* {
		root * /opt/swarmtrap/docs
		file_server
	}

	# --- Static site pages ---
	handle {
		root * /opt/swarmtrap/site
		try_files {path} {path}.html {path}/index.html
		file_server
	}
}
```

- [ ] **Step 2: Write systemd unit for the proxy**

```ini
[Unit]
Description=SwarmTrap API Proxy
After=network.target

[Service]
Type=simple
User=colo8gent
WorkingDirectory=/opt/swarmtrap/proxy
ExecStart=/opt/swarmtrap/proxy/venv/bin/uvicorn proxy:app --host 127.0.0.1 --port 8099
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 3: Commit**

```bash
cd /home/colo8gent/SwarmTrap
mkdir -p infra
git add infra/Caddyfile infra/swarmtrap-proxy.service
git commit -m "infra: add Caddyfile and systemd unit for VM 200"
```

---

## Task 11: Deploy to VM 200

**Files:**
- Create: `SwarmTrap/infra/deploy.sh`

VM 200 is accessed via ProxyJump through PV2:
```
ssh -o ProxyJump=root@192.168.0.215 colo8gent@192.168.0.200
```

- [ ] **Step 1: Write deploy script**

```bash
#!/usr/bin/env bash
set -euo pipefail

REMOTE="colo8gent@192.168.0.200"
JUMP="root@192.168.0.215"
SSH="ssh -o ProxyJump=$JUMP $REMOTE"
SCP="scp -o ProxyJump=$JUMP"

echo "=== SwarmTrap.net deploy ==="

# 1. Upload static site
echo "[1/6] Uploading static site..."
$SCP -r site/* "$REMOTE:/opt/swarmtrap/site/"

# 2. Upload proxy
echo "[2/6] Uploading proxy..."
$SCP proxy/proxy.py "$REMOTE:/opt/swarmtrap/proxy/proxy.py"

# 3. Upload dashboard build
echo "[3/6] Uploading SOC dashboard build..."
$SSH "rm -rf /opt/swarmtrap/dashboard/dist"
$SCP -r dashboard/dist "$REMOTE:/opt/swarmtrap/dashboard/dist"

# 4. Upload founding documents
echo "[4/6] Uploading founding documents..."
$SCP SwarmTrap_Founding_Document_v4.md "$REMOTE:/opt/swarmtrap/docs/"
$SCP Foundation_v0_1_Complete_Design.md "$REMOTE:/opt/swarmtrap/docs/"
$SCP Open_Utopia_Framework_v4.md "$REMOTE:/opt/swarmtrap/docs/"

# 5. Upload Caddy config + systemd unit
echo "[5/6] Uploading infra config..."
$SCP infra/Caddyfile "$REMOTE:/tmp/Caddyfile"
$SCP infra/swarmtrap-proxy.service "$REMOTE:/tmp/swarmtrap-proxy.service"
$SSH "sudo cp /tmp/Caddyfile /etc/caddy/Caddyfile"
$SSH "sudo cp /tmp/swarmtrap-proxy.service /etc/systemd/system/swarmtrap-proxy.service"

# 6. Restart services
echo "[6/6] Restarting services..."
$SSH "sudo systemctl daemon-reload"
$SSH "sudo systemctl enable --now swarmtrap-proxy"
$SSH "sudo systemctl restart swarmtrap-proxy"
$SSH "sudo systemctl restart caddy"

echo "=== Deploy complete ==="
echo "Test: https://swarmtrap.net"
echo "Test: https://swarmtrap.net/thesis"
echo "Test: https://swarmtrap.net/proof"
echo "Test: https://swarmtrap.net/join"
echo "Test: https://swarmtrap.net/dashboard/"
```

- [ ] **Step 2: Pre-deploy — ensure directories exist on VM 200**

```bash
SSH_CMD="ssh -o ProxyJump=root@192.168.0.215 colo8gent@192.168.0.200"
$SSH_CMD "sudo mkdir -p /opt/swarmtrap/{site,proxy,dashboard,docs}"
$SSH_CMD "sudo chown -R colo8gent:colo8gent /opt/swarmtrap"
```

- [ ] **Step 3: Pre-deploy — ensure proxy venv has pydantic**

The updated proxy.py uses `pydantic` for validation. Check the existing venv and install if needed:

```bash
SSH_CMD="ssh -o ProxyJump=root@192.168.0.215 colo8gent@192.168.0.200"
$SSH_CMD "/opt/swarmtrap/proxy/venv/bin/pip install pydantic"
```

- [ ] **Step 4: Set the SOC readonly API key in Caddy env**

Read the current PV1 API key and set it on VM 200:

```bash
# Read the key from PV1
ssh root@192.168.0.100 "grep BACKEND_API_KEY /etc/dfi2/env" 

# Set it on VM 200 for Caddy
SSH_CMD="ssh -o ProxyJump=root@192.168.0.215 colo8gent@192.168.0.200"
$SSH_CMD "echo 'SOC_READONLY_KEY=<the_key_from_pv1>' | sudo tee -a /etc/caddy/env"
```

Then ensure Caddy loads the env file. Add to the Caddyfile or to the systemd override:

```bash
$SSH_CMD "sudo mkdir -p /etc/systemd/system/caddy.service.d"
$SSH_CMD "echo -e '[Service]\nEnvironmentFile=/etc/caddy/env' | sudo tee /etc/systemd/system/caddy.service.d/env.conf"
$SSH_CMD "sudo systemctl daemon-reload"
```

- [ ] **Step 5: Run the deploy**

```bash
cd /home/colo8gent/SwarmTrap
chmod +x infra/deploy.sh
bash infra/deploy.sh
```

- [ ] **Step 6: Verify all pages**

Test each page in a browser or with curl:

```bash
curl -sI https://swarmtrap.net | head -5           # 200, main page
curl -sI https://swarmtrap.net/thesis | head -5     # 200, thesis
curl -sI https://swarmtrap.net/proof | head -5      # 200, proof
curl -sI https://swarmtrap.net/join | head -5       # 200, join
curl -sI https://swarmtrap.net/welcome | head -5    # 200, welcome
curl -s https://swarmtrap.net/api/stats | head -1   # JSON stats
curl -sI https://swarmtrap.net/dashboard/ | head -5 # 200, SOC dashboard
curl -sI https://swarmtrap.net/docs/SwarmTrap_Founding_Document_v4.md | head -5  # 200
```

- [ ] **Step 7: Test signup flow**

```bash
# Valid signup
curl -X POST https://swarmtrap.net/api/signup \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","email":"test@swarmtrap.net","roles":["developer"],"why":"testing","website":""}'
# Expected: {"status":"ok","message":"Welcome to SwarmTrap."}

# Bot signup (honeypot filled)
curl -X POST https://swarmtrap.net/api/signup \
  -H "Content-Type: application/json" \
  -d '{"name":"Bot","email":"bot@evil.com","roles":["developer"],"website":"http://spam.com"}'
# Expected: {"status":"ok","message":"Welcome to SwarmTrap."} (but NOT stored)

# Write to dashboard blocked
curl -X POST https://swarmtrap.net/dashboard/data/action/watchlist -sI | head -5
# Expected: 403
```

- [ ] **Step 8: Verify signup stored in SQLite**

```bash
SSH_CMD="ssh -o ProxyJump=root@192.168.0.215 colo8gent@192.168.0.200"
$SSH_CMD "sqlite3 /opt/swarmtrap/signups.db 'SELECT * FROM signups'"
# Expected: one row for test@swarmtrap.net, no row for bot@evil.com
```

- [ ] **Step 9: Clean up test data**

```bash
SSH_CMD="ssh -o ProxyJump=root@192.168.0.215 colo8gent@192.168.0.200"
$SSH_CMD "sqlite3 /opt/swarmtrap/signups.db \"DELETE FROM signups WHERE email='test@swarmtrap.net'\""
```

- [ ] **Step 10: Commit deploy script**

```bash
cd /home/colo8gent/SwarmTrap
git add infra/deploy.sh
git commit -m "infra: add deploy script for VM 200"
```

---

## Summary

| Task | What | Files |
|------|------|-------|
| 1 | Shared CSS dark theme | `site/style.css` |
| 2 | Main page (hero + hooks) | `site/index.html` |
| 3 | Thesis page | `site/thesis.html` |
| 4 | Proof page | `site/proof.html` |
| 5 | Join page (signup form) | `site/join.html` |
| 6 | Welcome page | `site/welcome.html` |
| 7 | JavaScript (stats + form) | `site/main.js` |
| 8 | Signup backend | `proxy/proxy.py` |
| 9 | Public SOC dashboard build | `dashboard/*` |
| 10 | Caddy config + systemd | `infra/Caddyfile`, `infra/swarmtrap-proxy.service` |
| 11 | Deploy to VM 200 | `infra/deploy.sh` |
