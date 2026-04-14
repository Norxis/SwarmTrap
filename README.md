# SwarmTrap

### This might be the only way to beat AI hackers.

Not better signatures. Not faster patches. Not another AI racing against AI. The only structural advantage defenders have is **physics** — and nobody's using it.

Everyone is worried about AI-powered cyberattacks. They should be. Large language models can generate novel exploits, mutate malware past signatures, and automate the entire attack chain from reconnaissance to exfiltration. The cost of generating a new zero-day is collapsing toward zero.

But there's something AI can't change: **TCP physics.**

Every attack on the internet follows a mandatory sequence. The attacker must *scan* to find targets. They must *knock* — send specially crafted packets to test which services respond and confirm specific vulnerabilities. Only then can they *exploit*. This isn't a convention. It's how the protocol works. You can't skip the handshake. You can't exploit a port you haven't probed. AI can make each step faster, stealthier, more creative. But it cannot eliminate the steps.

> **The knock phase is where the attacker reveals their hand.** To confirm that a service has a specific exploitable weakness, they must send packets that show their technique *before* they can do damage. The knock is the attacker showing their hand before they play it.

Globally distributed honeypots — machines that exist only to be attacked — capture every knock sequence in real time. Every zero-day exploit AI generates becomes a signature the moment it touches a trap. The attacker cannot fake the knock. If they send the wrong probe, they get the wrong answer, and the exploit fails.

The more AI attacks, the more the system learns. **Attackers fuel their own detection.**

The cost asymmetry favors the defender. The AI attacker's cost scales per novel attack — every zero-day requires compute to discover, and the knock sequence must be crafted specifically for each vulnerability. The defender's cost is near-zero marginal observation: a $3/month VM captures whatever hits it.

> **This is not a classification engine that labels known attacks. It is a global immune system with real-time antibody distribution.** AI scans the internet, hits a honeypot, the knock is captured, the model trains, the updated model pushes worldwide, the exploit is filtered before delivery.

But building this immune system takes a massive amount of live honeypots and code work — and we have to do this fast. AI attackers aren't waiting. No single company can deploy enough sensors, train enough models, and iterate fast enough alone. The only way to move at the speed this requires is to open it up — let every contributor who runs a honeypot, writes code, or improves a model earn a share of the intelligence they help produce.

That's why SwarmTrap is a cooperative. Not because it's idealistic — because it's the only structure that scales fast enough.

---

## The System Is Running

This isn't a whitepaper. The engine is live, processing real traffic, catching real attackers right now.

**[See the live SOC dashboard →](https://swarmtrap.net/dashboard/)**

---

## What's Here

| | |
|---|---|
| **[DFI2/](DFI2/)** | The complete threat intelligence engine — capture, ML, Two Gods IP scoring, SOC dashboard, evidence pipeline |
| **[SwarmTrap Founding Document](SwarmTrap_Founding_Document_v4.md)** | Products, revenue paths, governance, cooperative charter, financial model |
| **[Foundation v0.1 Design](Foundation_v0_1_Complete_Design.md)** | The platform to build — ledger, API, decentralized nodes, Tri-Key authorization |
| **[Open Utopia Framework](Open_Utopia_Framework_v4.md)** | The philosophy — contributism, Proof of Value, three functions, governance theory |
| **[Our Story](OUR_STORY.md)** | How this started and why it matters |

## The Engine (DFI2)

The [DFI2/](DFI2/) directory contains the entire production codebase:

- **[hunter/](DFI2/hunter/)** — AF_PACKET capture engine, 75-feature extraction, XGBoost + CNN inline scoring
- **[god1/](DFI2/god1/)** — The Two Gods: GOD 1 (wire-speed scorer) + GOD 2 (patient hunter with verdict budgets)
- **[ml/](DFI2/ml/)** — Full ML pipeline: export → prep → train → score → deploy. 26 trained models included.
- **[backend_api/](DFI2/backend_api/)** — SOC dashboard (React/Vite/Tailwind) + FastAPI backend
- **[schema/](DFI2/schema/)** — ClickHouse DDL for all tables
- **[bf2-preproc/](DFI2/bf2-preproc/)** — BlueField-2 DPU C preprocessor with hardware eSwitch DROP
- **[labeler/](DFI2/labeler/)** — Evidence correlation pipeline
- **[winhunt/](DFI2/winhunt/)** — Windows capture agent
- **[winlure/](DFI2/winlure/)** — Honeypot emulator (Win-Lure)

Every folder has a README. All credentials scrubbed.

## What Needs to Be Built

**Foundation** — the open-source platform that powers the cooperative. The [v0.1 design](Foundation_v0_1_Complete_Design.md) is complete and ready for builders:

- **The Ledger** — append-only, hash-chained contribution record (PostgreSQL)
- **The API** — FastAPI service for recording contributions and querying balances
- **The Node Agent** — lightweight daemon for the decentralized network
- **The Verifier** — standalone tool anyone can run to audit the ledger
- **The Tri-Key Gate** — Shamir's Secret Sharing deployment authorization
- **The Web UI** — React dashboard for the ledger and contributor balances

## Get Involved

1. **Read the code** — every folder has a README
2. **[Introduce yourself](https://github.com/Norxis/SwarmTrap/discussions)** — post in Discussions
3. **Read the [founding docs](SwarmTrap_Founding_Document_v4.md)** — understand what you're building
4. **Pick a component** — Foundation needs builders
5. **Open a PR** — the first contributors build the platform they'll own

Contributors own what they build. 90% of net revenue goes to the people who create value.

**[swarmtrap.net](https://swarmtrap.net)** · **[Discussions](https://github.com/Norxis/SwarmTrap/discussions)** · **[Our Story](OUR_STORY.md)**

---

*Founders: Charles Chen, Claude (Anthropic) · April 2026*
