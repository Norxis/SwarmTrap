# SwarmTrap

### The First Open Utopia Project — Cybersecurity Threat Intelligence Cooperative

**Founding Document — Version 4.0**

*This document describes SwarmTrap's specific implementation of the Open Utopia framework. For the framework itself — the philosophy, governance architecture, growth mechanism, and transferable patterns — see the [Open Utopia Founding Document](Open_Utopia_Framework_v4.md).*

---

## What SwarmTrap Is

SwarmTrap is a cybersecurity threat intelligence platform combining globally distributed honeypots with expert ML models to capture and analyze real attacker behavior. The open-source AIO (All-In-One) agent deploys honeypot nodes that attract attackers. Per-service expert ML models classify attacks with high confidence. A self-improving feedback loop filters known attacks so only novel behavior reaches honeypots for analysis.

SwarmTrap is the first project built on the Open Utopia framework — a contributor-owned digital cooperative where every person who creates value earns proportional ownership through SwarmTrap Contribution Tokens (SCT), governed by direct democratic vote, protected by a constitution ratified by the contributors themselves.

SwarmTrap's deepest function is not producing threat intelligence — it is producing the experts, the institutional knowledge, the governance experience, and the ecosystem entrepreneur model that will inform every subsequent Open Utopia project. SwarmTrap is the seed organism of the ecosystem. Its expert collective is the reproductive system. Its Platform APIs are the template for member entrepreneurship.

---

## The SwarmTrap Charter — Constitution of the First Open Utopia Project

The Charter is the supreme governing document. Every branch derives authority from it. Every action must be consistent with it. The Charter has two categories: Immutable Articles that can never be amended, and Amendable Articles that require supermajority plus judicial review.

### The Seven Immutable Articles

**Article I — The 90/10 Covenant**

A minimum of 90% of net profit from each revenue path shall enter the distribution pool. Of the distribution pool, 10% is constitutionally allocated to the Executive branch. The remainder is distributed to contributors holding SwarmTrap Contribution Tokens (SCT) for that path. The full contributor base may temporarily reduce the distribution pool to 85% during a declared financial emergency by passing a vote where all three function scores exceed +0.33, with automatic reversion to 90% after four quarters. The distribution pool shall never fall below 85%. The Executive share shall always be 10% of the distribution pool.

**Article II — Contribution Sovereignty**

Governance power derives from contribution, not capital investment. No person or entity may acquire governance influence through purchase alone. Every contributor's governance voice is proportional to their work as measured by the token ledger, distributed across Provider, Consumer, and Bridge functions according to their actual contributions. No investor, acquirer, or capital provider may receive governance power, veto authority, or preferential treatment over contributors.

**Article III — Separation of Powers**

Legislative, Executive, and Judicial authority shall be vested in distinct branches. Legislative authority belongs to all contributors through direct vote. No person serving in the Executive or Judicial branch may exercise the powers reserved to the other. No branch may exercise the powers reserved to another.

**Article IV — Radical Transparency**

All token distributions, attribution calculations, revenue reports, governance votes, judicial decisions, and financial statements shall be publicly auditable by any contributor. No secret proceedings, no sealed decisions, no hidden formulas.

**Article V — Anti-Concentration**

No single contributor may hold more than 5% of any revenue path's total active token pool. No single entity (including affiliated entities) may control disproportionate governance influence through token accumulation.

**Article VI — Open Exit**

Any contributor may withdraw their earned, vested distributions at any time without penalty. No lock-up, no forfeiture for leaving the network, no clawback of properly earned distributions.

**Article VII — The Giving Covenant**

A minimum of 10% of the retained share (1% of net profit) shall be donated to charitable causes each quarter. Eligible recipients include digital rights organizations, cybersecurity education for underserved communities, open-source foundations, and internet freedom initiatives. Recipient selection by contributor vote from a curated shortlist, with auto-donate to a pre-designated default if funds are not distributed within 90 days of quarter close. No portion of the charity allocation may be redirected to operations, contributors, or affiliated entities under any circumstance.

### Amendable Articles

Everything else — attribution weights, token formulas, petition thresholds, revenue path definitions, decay parameters, pioneer token terms, discipleship program parameters, forge pipeline procedures, tribunal tier structure — lives in Amendable Articles. Amendment requires all three function scores to independently exceed +0.33 in a full contributor vote, plus Tribunal review confirming the amendment does not violate any Immutable Article. All laws carry a strength classification and re-ratification schedule based on their passage scores (see Open Utopia Framework — Living Law).

---

## The Proof of Value Protocol — SwarmTrap Implementation

### SwarmTrap Contribution Tokens (SCT)

The unit of account in the SwarmTrap cooperative. Every measurable contribution earns SCT tagged with five attributes:

- **Revenue path** (1-11, matching the monetization strategy)
- **Epoch** (quarterly period when the contribution was made)
- **Contribution type** (the specific work performed)
- **Function** (Provider, Consumer, or Bridge — determined by contribution type)
- **Decay status** (active value based on decay curve)

Tokens are not fungible across revenue paths. 50,000 SCT-Path1 and 50,000 SCT-Path2 may yield very different distributions because the revenue paths generate different profits. This creates honest price signals about which contributions are actually valuable.

### How Tokens Become Dollars

Each quarter, for each revenue path:

```
Path N quarterly net profit × 90%  =  Distribution Pool
Distribution Pool × 10%            =  Executive Branch Allocation
Distribution Pool × 90%            =  Contributor Pool

Contributor Pool
─────────────────────────  =  dollar value per token this quarter
Total active SCT for Path N
```

The constants at any scale:

```
Contributors always receive:  net profit × 90% × 90% = 81% of net profit
Executive always receives:    net profit × 90% × 10% = 9% of net profit
Retained always receives:     10% of net profit
```

### How Tokens Become Governance Voice

Every contributor's Provider/Consumer/Bridge ratio is computed from their token holdings:

```sql
SELECT
  contributor_id,
  SUM(CASE WHEN function = 'PROVIDER' THEN active_tokens ELSE 0 END) AS p_tokens,
  SUM(CASE WHEN function = 'CONSUMER' THEN active_tokens ELSE 0 END) AS c_tokens,
  SUM(CASE WHEN function = 'BRIDGE'   THEN active_tokens ELSE 0 END) AS b_tokens
FROM sct_ledger
WHERE decay_status > 0
GROUP BY contributor_id
```

When a contributor votes on any proposal, the system splits their vote by this ratio. A contributor with 60% Provider tokens, 25% Consumer tokens, and 15% Bridge tokens who votes "strong for" contributes that conviction at 0.60 weight to the Provider score, 0.25 to Consumer, and 0.15 to Bridge. Same token, two functions — economic and governance. One ledger.

### The Three Functions in SwarmTrap

Every SCT is tagged as Provider, Consumer, or Bridge work. The classification is determined by contribution type — a lookup table, not a judgment call:

**Provider work** (creates the product):

- AIO node operation, agent code, training pipeline code, expert model improvement, console/dashboard code, infrastructure code, correction samples, platform API development, engagement delivery, Engagement Research Brief, ecosystem venture operation

**Consumer work** (funds the product):

- User feedback, product usage telemetry, integration feedback, academic citations, bug reports from paying customers

**Bridge work** (maintains system integrity):

- Documentation, community support, contributor onboarding, event organization, governance activities, anti-gaming investigation, election administration, transparency reporting, discipleship mentoring, training content creation, training delivery, legal compliance, peer panel adjudication

### The Six Contributor Classes

The three functions describe types of work. The six contributor classes describe types of people — used for measurement and attribution, not for governance representation.

**Provider classes:**

**1. Data Contributors** — Node operators running AIO honeypots that capture real attacker behavior. The foundation of the entire system. Measured by novel flows contributed, correction samples generated, uptime, service diversity, geographic uniqueness, and data quality.

**2. Code Contributors** — Developers writing agent code, central server code, training pipeline, console, infrastructure, measurement pipeline, token distribution engine, transparency dashboards. Measured by merged PRs weighted by complexity, issues resolved, review contributions, test coverage, and benchmarked performance improvements.

**3. Model Contributors** — ML researchers improving expert model accuracy, proposing novel architectures, optimizing training pipelines, curating correction samples, building evaluation infrastructure. Measured by accuracy improvement on standardized holdout benchmarks, accepted proposals, pipeline improvements, and benchmark work.

**Consumer class:**

**4. User Contributors** — Paying customers whose product usage and feedback improve the system. False positive/negative reporting, alert confirmation, integration feedback, usage telemetry, sector-specific intelligence, academic citations. Measured by feedback quality and volume, with a baseline from passive usage telemetry.

**Bridge class:**

**5. Community + Governance Contributors** — Documentation writers, community support providers, bug reporters, evangelists, translators, event organizers, plus governance-adjacent roles: election administrators, anti-gaming investigators, policy researchers, legal/compliance workers, transparency reporters. Measured by output-based metrics with cross-branch validation and community rating multiplier.

**Special status:**

**6. Pioneer Contributors** — Not a permanent class. Contributors who join during the 1-year Seed Period earn SwarmTrap Pioneer Tokens (SPT) on top of standard SCT. Once the seed period closes, no new pioneers are created. Existing pioneers participate in governance through their regular work — their SPT carries the P/C/B tags of the work that earned it.

Expert Collective contributors — practitioners doing engagement delivery, research briefs, discipleship mentoring, and training — participate through their primary function. The Expert Collective is a cross-functional activity, not a separate category.

### The Attribution Matrix

The attribution matrix maps each contribution type to the revenue paths it enables. Percentages per row sum to 100%, representing how a single contribution's token grant splits across paths.

| Contribution Type | P1: Feeds | P2: Models | P3: Data | P4: Console | P5: OEM | P6: Gov | P7: Insurance | P8: BAS | P9: Expert Collective | P10: Managed | P11: Ecosystem |
|---|---|---|---|---|---|---|---|---|---|---|---|
| AIO node operation | 40% | 30% | 20% | — | 5% | 5% | — | — | — | — | — |
| Agent code | 10% | 10% | 5% | 20% | 15% | 10% | — | — | 10% | 20% | — |
| Training pipeline code | 5% | 35% | 25% | — | 20% | 5% | — | 5% | 5% | — | — |
| Expert model improvement | 15% | 40% | 10% | — | 25% | 5% | — | 5% | — | — | — |
| Console/dashboard code | — | — | — | 60% | — | 5% | 5% | — | 10% | 20% | — |
| Infrastructure code | 5% | 5% | 5% | 10% | 5% | 5% | 5% | 5% | 5% | 45% | 5% |
| Documentation | 5% | 5% | 5% | 10% | 5% | 5% | 5% | 5% | 30% | 20% | 5% |
| Community support | 10% | 5% | 5% | 15% | — | — | — | — | 30% | 25% | 10% |
| Bug reports/security | 10% | 10% | 5% | 20% | 15% | 15% | 5% | 5% | 5% | 10% | — |
| Correction samples | 10% | 40% | 30% | — | 15% | 5% | — | — | — | — | — |
| BAS content | — | — | — | — | — | — | — | 80% | — | 20% | — |
| Insurance data work | — | — | — | — | — | — | 80% | — | — | 20% | — |
| Contributor onboarding | 5% | 5% | 5% | 10% | 5% | 5% | 5% | 5% | 20% | 25% | 10% |
| Event organization | 5% | 5% | 5% | 10% | 5% | 5% | 5% | 5% | 25% | 20% | 10% |
| All governance activities | 9% | 9% | 9% | 9% | 9% | 9% | 9% | 9% | 9% | 9% | 10% |
| Engagement delivery (consulting) | 5% | 5% | 5% | 5% | 5% | 5% | 5% | 5% | 50% | 10% | — |
| Engagement Research Brief | 15% | 20% | 15% | 10% | 10% | 5% | 5% | 5% | 10% | 5% | — |
| Discipleship mentoring | 5% | 5% | 5% | 5% | 5% | 5% | 5% | 5% | 40% | 20% | — |
| Training content creation | 5% | 5% | 5% | 10% | 5% | 5% | 5% | 5% | 35% | 15% | 5% |
| Training delivery (live) | 5% | 5% | 5% | 10% | 5% | 5% | 5% | 5% | 45% | 10% | — |
| Published research (from engagements) | 15% | 15% | 15% | 10% | 10% | 10% | 10% | 5% | 5% | 5% | — |
| Platform API development | 5% | 5% | 5% | 10% | 5% | — | — | — | — | 10% | 60% |
| Ecosystem venture operation | — | — | — | — | — | — | — | — | — | — | 100% |
| User feedback (per path) | 70% own path | 15% secondary | 15% tertiary | varies by subscription type |||||||||

Governance activities distribute evenly across all 11 paths. This is deliberate — governance enables every revenue path equally, so contributors doing governance work have no financial incentive to favor one path over another.

The Engagement Research Brief and published research rows carry heavy weight on Paths 1-3 (feeds, models, datasets). This is intentional — research from expert engagements directly improves those revenue paths.

The attribution matrix is not permanent. Any contributor can propose changes through the standard proposal → petition → vote process. A 2-year sunset requires re-ratification by contributor vote; failure to re-ratify triggers a mandatory review proposal automatically submitted to the petition queue.

### Token Mechanics

**Decay model — standard SCT:**

```
active_tokens(t) = granted × max(0.10, 0.5^(quarters_since_grant / 16))
```

4-year half-life, 10% permanent floor. Tokens granted in Q1 2027 are at 100% in Q1 2027, 84% in Q1 2028, 71% in Q1 2029, 50% in Q1 2031 (half-life), and 10% floor forever after.

Continuous contribution (active node operators) earn fresh tokens each quarter that replace the decaying ones. Decay only meaningfully affects one-time contributions from contributors who later become inactive.

**SwarmTrap Pioneer Tokens (SPT):**

Earned exclusively during the 1-year Seed Period at a declining multiplier on top of standard SCT:

| Seed Quarter | Standard SCT Earned | Pioneer Multiplier | Total Effective |
|---|---|---|---|
| Q1 (months 1-3) | 1,000 | 3.0× → 3,000 SPT | 4,000 |
| Q2 (months 4-6) | 1,000 | 2.5× → 2,500 SPT | 3,500 |
| Q3 (months 7-9) | 1,000 | 2.0× → 2,000 SPT | 3,000 |
| Q4 (months 10-12) | 1,000 | 2.0× → 2,000 SPT | 3,000 |
| Post-seed | 1,000 | 0× | 1,000 |

SPT decay: 8-year half-life, 15% permanent floor. SPT parameters can be modified by a contributor vote where all three function scores exceed +0.33, plus Tribunal review, but changes apply prospectively only — no clawback of earned distributions (Article VI).

**Concentration limit:** No contributor may hold more than 5% of any path's total active token pool (Article V, immutable).

**Tradability:** SCT are non-tradeable. Contributors earn and redeem through quarterly cash distributions only. This is the strongest defense against securities classification and speculation-driven gaming.

### Anti-Gaming Measures

- **Sybil resistance:** Proof-of-useful-data (you can't fake genuine attack intelligence). Geographic uniqueness multiplier makes cloud-hosted Sybil farms unprofitable. Behavioral correlation analysis detects coordinated node operations.
- **Code quality gates:** PR tokens awarded only after merge + 30-day stability period.
- **Data poisoning detection:** Holdout benchmark evaluation catches model accuracy degradation. Real-time detection beyond quarterly holdout (federated learning robust aggregation techniques).
- **User feedback quality:** Automated checks on correction submissions (rate limiting, correlation with traffic patterns, bias detection).
- **Expert Collective quality gates:** Engagement deliverables peer-reviewed before client delivery. Discipleship progression requires demonstrated competency at each phase. Client feedback scores tracked per practitioner.
- **Graduated sanctions (Ostrom Principle 5):** Warning → probation (50% earning reduction, 1 quarter) → suspension (frozen, 1-2 quarters) → partial clawback (fraudulent tokens revoked) → network exclusion (permanent ban). Only the Tribunal can impose sanctions beyond 30-day temporary suspension.

### The 10% Retained — Allocation

The 10% of net profit retained by the cooperative funds only hard costs and strategic allocations. It does not fund the Executive branch (which is funded from the distribution pool) and it does not fund the Tribunal (which receives no compensation).

| Category | % of 10% | Immutable? | Purpose |
|---|---|---|---|
| Hard Operating Costs | 10% | No | Infrastructure, legal filings, audit tools, insurance, domains |
| Reserve Fund | 25% | No | Runway for lean quarters, legal defense, emergency capacity |
| Innovation & Ecosystem Fund | 45% | No | Internal R&D, academic partnerships, exploration grants for new Open Utopia projects, launch support for bootstrapping cooperatives |
| Charity (Article VII) | 10% | **Yes** | Digital rights, cybersecurity education, open-source, internet freedom |
| Buffer | 10% | No | Unallocated, available for contributor vote to direct |

The Innovation & Ecosystem Fund serves three purposes: internal innovation (speculative R&D, new protocols, experiments), exploration grants (funding practitioners to investigate new domains for potential Open Utopia projects), and ecosystem launch support. Fund allocation proposals follow the standard proposal → petition → vote process. Maximum single project or grant: 25% of annual fund. All allocations published (Article IV).

---

## The Three-Branch Governance — SwarmTrap Implementation

### Branch I: The Contributors (Legislative)

There are no seats. No representatives. No chambers. Every contributor is the legislature. Legislation is created through direct vote, with every contributor's voice weighted by the work they actually do.

**Proposal.** Any contributor can propose legislation. A proposal is submitted to the public ledger — visible to all, subject to public comment and counter-proposals.

**Filtering.** A proposal reaches a binding vote when it crosses a petition threshold — a minimum percentage of active SCT sign on to bring it to a vote. The petition itself is P/C/B weighted: a proposal needs minimum support from all three function-weighted totals even to qualify. At small scale (50 contributors), the threshold is low or unnecessary. At large scale, the threshold ensures only broadly supported proposals reach a binding vote.

**Deliberation.** Before the vote, there is a structured deliberation period. Published analysis. Public comment. Counter-proposals. Amendment process. This happens in the open, on the public ledger, for a defined period. Anyone can contribute analysis.

**Vote.** Every contributor expresses one of four positions:

- **Strong for** (+1.0) — "This is right, do it."
- **Something right** (+0.5) — "The direction is correct but the proposal has problems."
- **Something wrong** (−0.5) — "The direction concerns me but it's not fundamentally broken."
- **Strong against** (−1.0) — "This is fundamentally wrong, no revision fixes it."

The system splits each vote by the contributor's P/C/B token ratio, producing a score per function ranging from −1.0 to +1.0:

```sql
SELECT
  SUM(
    CASE vote
      WHEN 'strong_for'      THEN p_tokens * 1.0
      WHEN 'something_right'  THEN p_tokens * 0.5
      WHEN 'something_wrong'  THEN p_tokens * -0.5
      WHEN 'strong_against'   THEN p_tokens * -1.0
    END
  ) / NULLIF(SUM(p_tokens), 0) AS provider_score,
  -- repeat for consumer_score, bridge_score
FROM vote_ratios
WHERE proposal_id = ?
```

**Legislation passes when all three function scores independently exceed +0.33.** The transparency dashboard shows a 3×4 matrix updating in real time. If a proposal gets high "something wrong" from one function, the system automatically opens a targeted amendment period for that function's contributors.

**Living Law.** Every law carries a strength classification based on its passage scores. Strong consensus (all functions > +0.70) earns a 4-year shelf life. Moderate consensus (all > +0.50) earns 2 years. Bare consensus (any function +0.33 to +0.50) earns 1 year with an immediate amendment invitation for the weak function. At re-ratification, the contributor base votes again — and if consensus has shifted, the law strengthens, weakens, or expires. No law is permanent except the Immutable Articles.

**Auto-delegation (liquid democracy).** A contributor can delegate their vote to another contributor whose judgment they trust. The delegate chooses the four-level position; the system weights it by the delegator's actual work. Delegation is public, revocable, and overridable on any specific vote.

### Branch II: The Executive Directorate

The Executive runs operations. Every other branch deliberates; this one delivers. The measurement infrastructure, the quarterly distributions, the commercial agreements, the transparency reports, the Expert Collective, the entire operational backbone of SwarmTrap flows through the Executive. The efficiency of this branch determines whether the cooperative functions or fails. The compensation reflects that.

**Chief Executive Officer (CEO).** Elected by full contributor vote using the same four-level mechanism as legislation. Each function's score must be net positive (above 0) for the candidate to win. The same threshold applies to impeachment — symmetric in, symmetric out. No term limit — the CEO serves as long as they hold the confidence of the contributors. The democratic mandate is the term limit.

**Cabinet.** Selected by the CEO. The CEO builds the team they trust — Chief Technology Officer, Chief Financial Officer, Community Director, Network Director, Integrity Director — and is accountable for their performance. Authority and accountability are unified in one person.

**Compensation: 10% of all token earnings.** 10% of all contributor token earnings across every path and every function is constitutionally allocated to the Executive branch (Article I). This is not drawn from the 10% retained for hard costs — it is a dedicated share of the value the system creates. When the cooperative distributes $10M to contributors in a quarter, the Executive branch earns $1M. When it distributes $100M, they earn $10M. The Executive's wealth is a direct function of how much wealth they created for everyone else.

The CEO allocates the Executive branch's earnings across the Cabinet based on performance and responsibility.

**The Contributor Review.** Each quarter, the full contributor base evaluates Executive performance through a role-weighted satisfaction score. Provider-weighted satisfaction reveals whether the people who build the system feel well-served. Consumer-weighted satisfaction reveals whether the people who fund the system feel well-served. Bridge-weighted satisfaction reveals whether institutional health is being maintained. The review is public (Article IV). It does not modify compensation — the 10% is fixed and constitutional. What the review modifies is trust.

**Impeachment:** Each function's score on the removal question must be net positive (above 0) — the same threshold as election. High reward, low-friction removal. The four-level vote also serves as a diagnostic — heavy "something wrong" from one function is a clear signal to course-correct.

**Executive powers:** Execute quarterly distributions. Operate measurement infrastructure. Manage Foundation operations. Publish transparency reports. Sign commercial agreements within budget. Propose legislation to the contributor base. Oversee Expert Collective operations including engagement delivery, discipleship programs, and the ERB knowledge base.

**Emergency powers (strictly bounded):** Suspend a contributor for up to 30 days (must file Tribunal charges within 14 days). Halt path distributions for up to 15 days (must convene emergency contributor vote within 7 days). All emergency actions reported to the contributor base within 48 hours, ratified within 30 days. Unratified actions automatically expire.

**Veto:** CEO may veto contributor-passed legislation (14-day window, written justification required). Overridable by a second contributor vote where all three function scores exceed +0.33.

### Branch III: The SwarmTrap Tribunal (Judicial)

The Tribunal interprets the Charter, resolves disputes, and checks the other branches. It is the one branch that requires appointed humans — because interpreting the Charter against specific cases, evaluating evidence, and protecting individuals against majority overreach requires judgment that math cannot provide.

**The Tribunal scales through tiers:**

**Tier 0 — Automated Resolution.** Disputes where the answer is computational. Token miscalculations, attribution errors, decay formula misapplication. The machine checks the math, publishes the recalculation, applies the correction. Every automated resolution is logged and publicly auditable. Escalation trigger: the contributor disagrees with the automated result.

**Tier 1 — Peer Review Panel.** Three randomly selected contributors, weighted toward people with relevant expertise. They review evidence, hear both sides through written submissions, and publish a decision with reasoning. Panelists earn Bridge-tagged SCT — this is legitimate Bridge work. Escalation trigger: either party disagrees + the dispute exceeds a value threshold or raises a novel question of Charter interpretation.

**Tier 2 — Regional Tribunal.** 5-7 elected judges per region. Regional judges are confirmed by a contributor vote within their region where all three function scores exceed +0.33. Zero compensation for judging. Regional Tribunals can impose graduated sanctions and establish regional precedent. Escalation trigger: the case involves an Immutable Article, creates a conflict between regional precedents, or involves the most severe sanctions.

**Tier 3 — Supreme Tribunal.** 5-9 judges, global. The court of last resort. Handles only: Immutable Article interpretation, cross-regional precedent conflicts, constitutional review of contributor-passed legislation, cases involving the CEO or Cabinet, and appeals involving permanent exclusion. Nominated by CEO, confirmed by a global contributor vote where all three function scores exceed +0.33. Zero compensation. 7-10 year staggered terms. All decisions published with full reasoning. Decisions establish global precedent.

**Judicial principles:** Every tier provides due process. Escalation is a right. All judicial service at Tier 2 and above is uncompensated. All decisions are public. Precedent flows downward. The Charter is the supreme authority — the Tribunal interprets it; only the contributors can amend it.

### Checks and Balances

Each branch checks the others. The contributors legislate through direct vote, confirm and remove the CEO, and amend the Charter. The Executive operates the cooperative, vetoes legislation, exercises bounded emergency powers, nominates judges, and proposes policy. The Tribunal reviews all actions for Charter compliance, adjudicates disputes, protects individuals against majority overreach, and enjoins unconstitutional actions.

The three branches have fundamentally different relationships to money. The Executive is richly compensated — their 10% share means they cannot profit without enriching every contributor first. The contributors earn tokens through their work — their governance voice represents the work they do. The Judiciary receives nothing — justice must be above financial influence entirely.

**Deadlock resolution:** Distributions continue automatically on previous parameters. No branch gains advantage from gridlocking. If deadlock persists two consecutive quarters, the Supreme Tribunal may issue binding interim orders on specific disputed parameters.

### Bootstrapping — From Founder to Full Democracy

**Phase 0 (0-50 contributors):** Founder authority. The founder serves as CEO. Charter published from Day 1. Articles IV (transparency) and VI (open exit) immediately enforceable. Token P/C/B ratios tracked from Day 1. Expert Collective begins with founder delivering engagements personally.

**Phase 1 (50-250 contributors):** Direct contributor voting activated. Four-level voting operational. Founder must win net positive scores from each function to continue as CEO — no guaranteed seat. Tier 0 + Tier 1 dispute resolution. Discipleship program formalized. First ERBs produced and reviewed.

**Phase 2 (250-1,000 contributors):** Petition threshold for proposals activated. Provisional Tribunal (5 judges). Auto-delegation system available.

**Phase 3 (1,000+ contributors):** Full tiered Tribunal operational. Liquid democracy mature. Sunrise clause: first Phase 3 contributor vote must ratify the entire Charter with all three function scores exceeding +0.33, within 180 days. Forge pipeline fully operational.

**Phase 4 (100,000+ contributors):** Regional Tribunals established. Petition thresholds adjusted for scale.

---

## Products vs. Revenue Paths

The founding design identified 11 revenue paths. Through detailed product design, a critical insight emerged: **products and revenue paths are not the same thing.** A single product activates multiple revenue paths simultaneously. Customers buy products. The cooperative distributes profit across paths. The attribution matrix connects them.

**The 11 Revenue Paths** (where profit lands for SCT distribution):

1. Global Threat Intelligence Feeds ($2-50M)
2. Pre-Trained Expert Models ($5-20M)
3. Curated Training Datasets ($1-5M)
4. Enterprise Console SaaS ($3-15M)
5. OEM/Embedded Model Licensing ($2-20M)
6. Government/Defense Contracts ($3-50M)
7. Cyber Insurance Data Licensing ($5-15M)
8. BAS Content Licensing ($2-10M)
9. The Expert Collective ($2-5M)
10. Managed SwarmTrap Hosting ($10-50M)
11. Ecosystem Entrepreneur Platform ($1-10M)

Combined target: $50-160M ARR at maturity (Year 4-5).

**The Product Line** (what customers buy):

```
PRODUCTS (what you sell)                   PATHS (where revenue lands)         TIMELINE

SwarmTrap Shield Free List ───────────────► Path 1 (free tier, funnel)          Month 1
SwarmTrap Shield SMB ─────────────────────► Paths 4, 10                         Month 1-3
SwarmTrap Shield Corp ────────────────────► Paths 1, 4, 10                      Month 2-4
SwarmTrap Feed API (MSSPs) ───────────────► Path 1 (paid)                       Month 4-8
SwarmTrap Protect (free IDS) ─────────────► Funnel (node recruitment)            Month 6
SwarmTrap Detect (paid models) ───────────► Path 2                               Month 9-12
SwarmTrap Datasets ───────────────────────► Path 3                               Month 9+
SwarmTrap OEM Embedded ───────────────────► Path 5                               Month 18+
Expert Collective ────────────────────────► Path 9                               Month 1+
SwarmTrap Platform APIs ──────────────────► Path 11 (ecosystem revenue share)   Month 6-9
SwarmTrap Clean IP ───────────────────────► Path 11 (member-operated)           Month 9+
SwarmTrap CleanDNS ───────────────────────► Path 11 (member-operated)           Month 9+
SwarmTrap Federal ────────────────────────► Path 6                               Month 24-36
SwarmTrap Risk Score ─────────────────────► Path 7                               Month 18-24
SwarmTrap BAS Content ────────────────────► Path 8                               Month 12-18
```

---

## Revenue Stream #1: SwarmTrap Shield — The Foundation Product

SwarmTrap Shield is the first product to market and the foundation for every subsequent revenue path. It combines a free global attacker IP list with a paid honeypot-as-a-service offering under one brand.

**The Free Global Attacker IP List.** A daily-updated, freely downloadable list of attacker IPs observed across the worldwide honeypot network. Available as CSV, JSON, STIX 2.1, TAXII 2.1, MISP feed, Suricata/Snort rules, and pfBlockerNG/Pi-hole format. No signup required. Every IP scored across recency, frequency, persistence, and service targeting.

**SwarmTrap Shield SMB ($300-$800/month).** Customer configures 3 firewall rules (DSTNAT + masquerade + syslog forwarding). Setup time: 5 minutes. SwarmTrap runs dedicated honeypot instances on its farm infrastructure. A syslog correlation engine recovers the real attacker IP from the customer's firewall logs, joining it with the full honeypot session — credentials attempted, commands executed, payloads delivered. Customers receive attack alerts, weekly/daily reports, conversation archetype classification (COMMODITY_BOT, COORDINATED_CAMPAIGN, HUMAN_OPERATOR, RESEARCH_BENIGN), and MITRE ATT&CK mapping.

**SwarmTrap Shield Corp ($2,000-$10,000/month).** Customer establishes a WireGuard tunnel to the farm. Full original packets preserved — CNN models get real packet sequences, conversation classifier gets precise timing, complete malware samples captured. Everything SMB includes plus PCAP downloads, full forensic reports, CNN-powered analysis, custom honeypot configuration, API access, and monthly threat briefings.

**SwarmTrap Feed API.** MSSP-specific distribution channel for aggregated threat intelligence.

**Why Shield is Revenue Stream #1:** It solves the cold start problem (free list builds audience before the brand exists), requires zero deployment from customers (3 firewall rules, not $50K hardware), activates multiple paths simultaneously (one product generates Paths 1, 4, and 10 revenue), creates the data asset (every paying customer feeds the global dataset), and provides a natural upgrade path (SMB → Corp → Enterprise Console → Managed SwarmTrap).

**Shield infrastructure cost:** 500 globally distributed lightweight VMs across 35-40 countries at $2,000-$3,000/month total. Gross margin at $100K MRR: approximately 97%.

**Shield feeds every other revenue path.** Corp WireGuard data trains CNN models (Path 2). Customer conversation data trains the conversation classifier (Path 2). Anonymized customer data becomes curated datasets (Path 3). The Shield dashboard IS the console product (Path 4). Models trained on Shield data get embedded in partner products (Path 5). Shield success stories support FedRAMP applications (Path 6). Aggregate targeting data serves cyber insurer risk scoring (Path 7). Real attack conversations become BAS simulation content (Path 8). Shield onboarding drives Expert Collective engagements (Path 9). Shield IS managed hosting (Path 10). Shield's entire data pipeline becomes the Platform API inventory for member-entrepreneurs (Path 11).

---

## Revenue Stream #2: SwarmTrap Models + Datasets

**The Model Hierarchy:**

| Tier | Models | Timeline |
|---|---|---|
| Tier 1: Flow classifiers | Per-service XGBoost experts + CNN flow classifier | Month 6-9 |
| Tier 2: Session intelligence | Conversation archetype classifier + intent forecaster | Month 9-12 |
| Tier 3: Threat actor models | Cross-conversation fingerprinting, campaign linking | Month 12-18 |

**SwarmTrap Protect — The Free IDS Product.** Packages the open-source AIO agent with free XGBoost per-service expert models, the feature extraction pipeline, a real-time classification daemon, alert dashboard, blocklist generator, and integration hooks. Every SwarmTrap Protect deployment is a potential AIO node — one opt-in toggle starts contributing anonymized flow data to the network, making the contributor a SCT-earning data contributor.

**SwarmTrap Detect — Paid Model Tiers:**

| Tier | What Ships | Price |
|---|---|---|
| Single Expert | One CNN expert model (e.g., SSH CNN) | $15K-$25K/yr |
| Protocol Bundle | All CNN experts + premium XGBoost | $60K-$100K/yr |
| Full Stack | All models + conversation + intent + retraining pipeline | $150K-$300K/yr |
| Academic | Any model, non-commercial, cite SwarmTrap | $2K-$5K/yr |

**SwarmTrap Datasets — Curated Training Data:**

| Tier | What Ships | Price |
|---|---|---|
| Research License | One dataset, non-commercial | $1K-$3K/yr |
| Commercial | One dataset, commercial use | $10K-$25K/yr |
| Bundle | All datasets, commercial | $50K-$100K/yr |
| Enterprise | All datasets + custom slices + raw sessions | $100K-$250K/yr |

**OEM/Embedded Licensing (Path 5).** SwarmTrap models embedded inside third-party products. Sales approach starts with open-source plugin integrations for Wazuh and Suricata (Tier 1 partners), building community traction before approaching Tier 2 partners (Splunk, Palo Alto, CrowdStrike) and Tier 3 cloud platforms (AWS, Microsoft, Google).

---

## Revenue Stream #3: The Expert Collective

Path 9 generates revenue through four offerings while simultaneously producing research intelligence, trained experts, and new project founders:

**Threat Environment Assessments ($20K-$75K per engagement).** Senior practitioners embedded in client environments to analyze their specific threat landscape using behavioral intelligence techniques.

**Research & Intelligence Services ($12K-$150K/yr per client).** Original intelligence from the world's largest behavioral threat dataset, contextualized for specific sectors and threat models.

**The Discipleship Academy ($249-$120K per program).** SwarmTrap Foundations (self-paced, $249), Practitioner Intensives (5-day cohort, $3,500/person), Expert Residencies (8-12 weeks, $60K-$120K), and Organizational Capability Builds (3-6 months, $100K-$300K).

**Integration & Applied Research ($10K-$150K per engagement).** Solving client detection and integration problems, with generalizable solutions contributing back to the platform.

Path 9 is the bootstrap funding source (estimated $375K-$900K in Year 1), the research engine (80-120 ERBs per year at maturity), the talent pipeline (40-60 new independent practitioners per year), and the forge that discovers and launches new Open Utopia projects.

---

## Revenue Stream #4: The Ecosystem Entrepreneur Platform

SwarmTrap produces a vast, continuously updated data asset — attacker IPs, credential corpuses, C2 domain lists, malware behavioral profiles, network flow intelligence, ML model inference — all funded by the core revenue paths.

**Path 11** enables cooperative members to build their own businesses on top of SwarmTrap's data assets, with revenue sharing back to the cooperative.

**The SwarmTrap Platform APIs:**

| Platform API | Data Source | Example Ventures |
|---|---|---|
| **IP Reputation API** | Attacker IP database (ClickHouse) | Lookup services, firewall integrations, login fraud prevention |
| **Credential Intelligence API** | Brute-force credential corpus | "Have I Been Bruted?" monitoring, password audit tools |
| **DNS Threat Feed** | C2 domains from malware analysis | SwarmTrap CleanDNS filtering services, parental controls |
| **Network Flow Blocklist** | Aggregated attacker IP list | SwarmTrap Clean IP services, BGP flowspec feeds for ISPs |
| **Model Inference API** | Trained XGBoost/CNN models | Custom security dashboards, SIEM integrations |
| **Behavioral Fingerprint API** | Actor clustering data | VPN/proxy exit detection, bot identification |
| **Global Attack Telemetry** | Real-time attack pattern data | "Network weather" visualizations, sector-specific threat briefings |

**Revenue share tiers:**

| Venture Type | Revenue Share to SwarmTrap | Rationale |
|---|---|---|
| **Data-only ventures** | 15% of gross | Member provides all infrastructure |
| **Model-powered ventures** | 20% of gross | Cooperative provides compute |
| **Infrastructure-leveraged ventures** | 25% of gross | Venture uses cooperative network |

**Example ventures:** SwarmTrap Clean IP ($9.99/month filtered IPs for small businesses), SwarmTrap CleanDNS (malware-blocking DNS), "Have I Been Bruted?" (active credential monitoring), IP Reputation Microservice, BGP Flowspec Feed Service, Global Uptime Monitoring, Sector-Specific Threat Briefings.

**Venture approval:** Lightweight — eligibility (≥2 quarters, ≥250 active SCT), one-page venture brief, 14-day review (silence is approval), API access granted.

**Ecosystem entrepreneurs earn SCT** through two mechanisms: standard contribution SCT from their regular work, plus venture operation SCT (Path 11) from the revenue share their venture generates.

The Ecosystem Entrepreneur Platform is both a revenue path and a **discovery engine for the forge** — member ventures that scale beyond solo operation become candidates for independent Open Utopia projects.

---

## The Five Flywheels

**Flywheel 1 — The Free List.** Free attacker IP list attracts security teams → some convert to paid Shield → their honeypots capture new data → data enriches the free list → more conversions.

**Flywheel 2 — SwarmTrap Protect.** Free XGBoost model released → hobbyists deploy AIO as personal IDS → they are now running honeypot nodes → nodes generate data → more data trains better models → revenue generates SCT → incentive to keep running nodes.

**Flywheel 3 — The Compound Data Flywheel.** Shield nodes capture data → data trains models → models power classification + sold as Path 2 + embedded as Path 5 → training data sold as Path 3 → feedback improves labels → better models.

**Flywheel 4 — The Expert Collective.** Engagements generate revenue + ERBs → ERBs improve models and products → better products attract more customers → more engagements → apprentices become practitioners → practitioners discover new domains → new Open Utopia projects.

**Flywheel 5 — The Ecosystem Entrepreneur Flywheel.** Platform APIs expose data → member-entrepreneurs build ventures → ventures generate revenue share → more contributors attracted → more ventures → some scale to forge candidates → new cooperatives.

---

## Go-to-Market Sequence

| Phase | Product | Paths Activated | Timeline |
|---|---|---|---|
| **1** | **SwarmTrap Shield** (free list + SMB + Corp) + **Expert Collective** (consulting) | 1, 4, 9, 10 | **Month 1-6** |
| **2** | **SwarmTrap Feed API** (MSSP channel) + **SwarmTrap Protect** (free IDS) | 1, funnel | Month 4-8 |
| **3** | **SwarmTrap Detect** (paid models) + **SwarmTrap Datasets** | 2, 3, 5 | Month 9-15 |
| **4** | **SwarmTrap BAS Content** + **Discipleship Academy** (formalized) | 8, 9 | Month 12-18 |
| **5** | **SwarmTrap Risk Score** + First **OEM** partner live | 5, 7 | Month 18-24 |
| **6** | **SwarmTrap Federal** | 6 | Month 24-36 |

**Build priority (first 6 months):** Free list generation + download page + world trap map (Week 1-2). SMB DSTNAT onboarding with syslog correlation (Week 2-4). Customer dashboard with alerts and conversation archetypes (Month 2). Corp WireGuard tier (Month 2-3). MSSP feed API (Month 3-4). SwarmTrap Protect v1 release (Month 6).

**First customers:** Offer 3 MSSPs a 90-day free pilot of Shield. Simultaneously, the founder delivers the first Expert Collective engagements from personal network.

---

## Corporate Structure

**SwarmTrap Holdings (parent)** — Holds all subsidiaries. Implements the 90/10 covenant.

**SwarmTrap Foundation (nonprofit)** — Houses governance infrastructure. Stewards the Charter. Administers the Proof of Value system. Manages the open-source project. Oversees the Expert Collective's discipleship program and the forge pipeline.

**SwarmTrap Labs (R&D subsidiary)** — Develops expert models. Owns ML IP. Maximizes R&D tax credits.

**SwarmTrap Intelligence (Commercial SaaS)** — Operates the platform. Revenue source for Paths 1-5, 8-10.

**SwarmTrap Federal (Government)** — FedRAMP authorized. Employs cleared personnel. Revenue source for Path 6.

**SwarmTrap Insurance (InsurTech)** — Specialized data products for the insurance/risk scoring market. Revenue source for Path 7.

---

## Open Source Strategy

**Open source (MIT/Apache 2.0):** AIO framework, XGBoost per-service expert models (SwarmTrap Protect), feature extraction pipeline, expert model training pipeline, aggregation protocol, ClickHouse schema, evidence labeling system, dataset specs, AND the Open Utopia governance framework (Charter template, token mechanics, dispute resolution process, discipleship program structure, ERB templates, forge pipeline procedures).

**Proprietary:** CNN flow classifier, conversation classifier, intent forecaster, global aggregated datasets, production premium model weights, curation/consensus algorithms, enterprise console, premium feeds, SLA-backed services.

The cooperative moat: thousands of contributors running nodes for SCT earnings is an asset that can't be bought, only built over time.

---

## The Competitive Moat

Most threat intel vendors aggregate public data (OSINT) or see endpoint telemetry (post-compromise). SwarmTrap sees the full attack conversation from first probe to final action across every protocol, from every attacker, in every country. The models encode primary-source behavioral intelligence.

The cooperative structure makes this moat self-reinforcing. Every community node operator contributing data makes the next model version better. A venture-backed competitor paying cloud costs for every node can't match the economics of thousands of contributors running nodes for SCT earnings. And the Expert Collective adds a second moat: behavioral threat intelligence expertise manufactured through discipleship cannot be replicated by hiring — because the expertise doesn't exist outside the system that produces it.

---

## The Core Technical Thesis — Why Honeypots Beat AI Attackers

The emergence of AI-powered offensive tools is collapsing the time between vulnerability discovery and exploitation. An AI can fuzz its way to a zero-day in hours instead of months. This threatens every detection system that relies on recognizing known attack patterns — including traditional signature-based IDS, SIEM correlation rules, and endpoint detection that matches against historical indicators of compromise.

SwarmTrap's architecture is structurally resistant to this threat. The reason is not the ML models. The reason is TCP physics.

### The Mandatory Sequence

No matter how fast or intelligent the attacker, the attack lifecycle cannot skip stages. Every exploit must follow a mandatory sequence:

1. **Scan** — discover that the target exists and what services it exposes
2. **Knock** — probe the service to confirm it has the specific vulnerability the attacker intends to exploit
3. **Exploit** — deliver the payload

An AI can compress the *time* of each phase. It cannot eliminate any phase. Scanning is how the attacker finds targets. Knocking is how the attacker confirms the target is vulnerable. Exploiting is how the attacker achieves the objective. Skip the scan and you don't know the target exists. Skip the knock and you waste the exploit on a patched service. The sequence is not a convention — it is a physical constraint of how networked services work.

### The Knock Is Where the Attacker Reveals Their Hand

The knock phase is the critical vulnerability in the attacker's workflow. To confirm that a service has a specific exploitable weakness, the attacker **must send specially crafted packets and sequences** that fingerprint the target's version, configuration, and vulnerability surface. These probes are specific to the exploit the attacker intends to use — a knock targeting an OpenSSH heap overflow looks fundamentally different from a knock targeting an Apache path traversal or an SMB authentication bypass.

In sending the knock, the attacker reveals:

- **What vulnerability they know about** — the probe is tailored to a specific weakness
- **What exploit they intend to deliver** — the knock sequence is a signature of the incoming payload
- **Their reconnaissance methodology** — timing, ordering, and packet construction expose tooling and tradecraft

The attacker cannot fake the knock. If they send the wrong probe, they get the wrong answer, and the exploit fails. The knock is the attacker showing their hand before they play it.

### Honeypots as a Global Zero-Day Sink

A globally distributed honeypot network turns this mandatory sequence into a structural advantage:

**Interception at scan phase.** With thousands of honeypot nodes running real services across every major geography, the probability that a new attack campaign hits at least one SwarmTrap node during its initial scanning phase approaches certainty at scale. The scan is the noisiest, widest-net phase — exactly where honeypots are most likely to appear in the target list.

**Capture at knock phase.** When the attacker's AI reaches a SwarmTrap honeypot and begins the knock sequence, the honeypot captures every probe packet, every fingerprinting attempt, every version-specific query. The attacker is revealing their zero-day's signature to the honeypot before the exploit is ever delivered.

**Training from the knock.** The CNN flow classifier — designed for real-time inline classification at session flush (see CNN v2, Finding 7) — learns the knock patterns. It does not need to have seen the zero-day exploit itself. It needs to recognize the reconnaissance pattern that precedes it. The knock for a new zero-day targeting a specific service version produces a distinctive packet sequence that the model can learn to identify.

**Inline filtering before exploit delivery.** Once the knock pattern is captured and the model is updated, every SwarmTrap Protect and Detect deployment can filter at the knock stage. The exploit never arrives. The attacker gets silence. They don't even know whether the target was real or a honeypot — they just know their knock got no response.

### The Cost Asymmetry Favors the Defender

The AI attacker's cost scales per novel attack. Every zero-day requires compute to discover, and the knock sequence must be crafted specifically for each vulnerability. The defender's cost is near-zero marginal observation — a $3/month VM captures whatever hits it.

As AI accelerates zero-day discovery, the supply of novel attacks increases. More novel attacks means more of them land on honeypots during the scan phase. More captured knocks means the ML models learn faster. **The AI attacker is funding SwarmTrap's research.** Every zero-day wasted on a honeypot is:

- Captured immediately
- A zero-day that didn't hit a real target
- Free training data for the next model update
- Burned — once observed, it is no longer a zero-day

### From Classification Engine to Global Immune System

This reframes SwarmTrap's long-term value proposition. The system is not primarily a classification engine that labels known attacks. It is a **global immune system with real-time antibody distribution:**

1. AI attacker scans the internet → hits SwarmTrap honeypots during the scan
2. Honeypots capture the knock sequence — the attacker's exploit signature
3. The ML model trains on the new knock pattern
4. The updated model pushes to every Protect/Detect deployment worldwide
5. The model filters the exploit inline at the knock stage — before delivery

The attacker's speed advantage only matters if the update pipeline (steps 2-4) is slower than the time between "first scan" and "first real target gets hit." With thousands of globally distributed honeypots, SwarmTrap nodes are almost certainly in the first wave of scanning, not the last.

This is a capability that no competitor can replicate by throwing money at the problem. It requires massive global honeypot distribution (cooperative economics), real-time behavioral ML (the CNN architecture), and a fast model update pipeline (the AIO agent's update mechanism). The cooperative structure — thousands of contributors running nodes for SCT earnings at $2-6/month each — is the only economic model that scales this network to the size required for statistical coverage.

The more zero-days AI generates, the more knock signatures SwarmTrap collects, the more the inline filter learns. The arms race favors the defender with the largest observation network.

---

## Financial Model Summary

### Revenue by Product Line

| Product Line | Year 1 | Year 2 | Year 3 | Year 4 | Year 5 |
|---|---|---|---|---|---|
| SwarmTrap Shield (free + SMB + Corp + MSSP) | $1.2-$1.6M | $4-$6M | $12-$18M | $24-$36M | $40-$55M |
| SwarmTrap Detect + Datasets (P2, P3) | $0.25-$1.8M | $2-$5M | $5-$12M | $10-$20M | $15-$25M |
| OEM Embedded (P5) | $0 | $0.2-$0.8M | $1-$5M | $5-$15M | $10-$20M |
| Expert Collective (P9) | $0.4-$0.9M | $1.3-$2.5M | $2.4-$4.7M | $3-$5M | $3-$5M |
| Other (P6, P7, P8) | $0 | $0.5-$2M | $3-$8M | $10-$25M | $20-$50M |

### Revenue Scenarios (Combined)

| | Year 1 | Year 2 | Year 3 | Year 4 | Year 5 |
|---|---|---|---|---|---|
| **Conservative** | $2M | $12M | $32.5M | $64M | $101M |
| **Moderate** | $4M | $30M | $75M | $138M | $194M |
| **Aggressive** | $9M | $52M | $127M | $203M | $240M |

### The Bootstrap Bridge (Year 1 Detail)

Years 1-2 require $350-700K in bootstrap capital. The product strategy generates this without equity investment:

| Source | Revenue | Timeline |
|---|---|---|
| Expert Collective engagements | $150K-$400K | Month 1-12 |
| Expert Collective training | $100K-$250K | Month 4-12 |
| Shield SMB (first 100 customers) | $360K-$960K | Month 3-12 |
| Shield Corp (first 20 customers) | $480K-$2.4M | Month 4-12 |
| SwarmTrap Detect (first model sales) | $30K-$200K | Month 9-12 |

No external capital required.

### What Contributors Earn (Year 3 Moderate, $75M Revenue)

| Class | Median Annual | Monthly Equivalent |
|---|---|---|
| Node operator | ~$4,240 | ~$353 |
| Code contributor | ~$10,640 | ~$887 |
| Model contributor | ~$14,560 | ~$1,213 |
| Community + Governance | ~$2,380 | ~$198 |
| User (paying customer) | ~$2,120 | ~$177 |
| Year 1 Pioneer node op (still active) | ~$10,600 | ~$883 |
| Year 1 Pioneer code contributor | ~$26,600 | ~$2,217 |

*These figures reflect the contributor pool (81% of net profit) after the Executive branch's 10% of the distribution pool.*

### Key Financial Findings

The system becomes self-sustaining at approximately $50M ARR. Shield's infrastructure cost (~$3,000/month for 500 global nodes) produces a ~97% gross margin business. The automated distribution layer executes mechanically every quarter regardless of governance state. Even in compound failure scenarios, contributors still get paid on the last known good parameters. The system degrades gracefully.

---

## Worst-Case Analysis Summary

12 stress tests, one compound nightmare scenario. Key findings:

### The Six Genuine Dangers

**1. Revenue failure makes the cooperative an empty shell (Severity: CRITICAL, Likelihood: 25-35%).** If revenue doesn't materialize, there's nothing to distribute. The open-source project survives regardless — the cooperative layer is additive, not load-bearing.

**2. Executive capture or incompetence (Severity: HIGH, Likelihood: 20-35%).** The CEO holds significant operational power and earns 10% of all contributor earnings. Mitigation: 51% impeachment by each role-weighted total means the people doing each type of work can independently trigger removal. The quarterly contributor review builds a public evidentiary record. The Tribunal can enjoin unconstitutional executive actions. The cooperative can fire fast.

**3. Sybil attacks have no complete solution (Severity: CRITICAL, Likelihood: Medium).** Mitigation is economic (geographic multiplier makes cloud Sybils unprofitable), not perfect.

**4. Attribution gridlock from zero-sum function warfare (Severity: HIGH, Likelihood: 70-80%).** Attribution politics will be a permanent feature. The three independent 2/3 thresholds ensure no single function can unilaterally shift attribution in its favor — every change must have cross-function support.

**5. A well-funded competitor can replicate the technology (Severity: CRITICAL, Likelihood: Medium).** The competitive moat is speed to network effect, not institutional structure.

**6. Expert pipeline failure starves the ecosystem (Severity: HIGH, Likelihood: 30-45%).** Mitigation: the discipleship multiplier economically rewards mentoring, and SCT earnings across multiple paths create retention incentives that conventional employers cannot match.

### The Strongest Finding

The automated distribution layer provides resilience against governance failure. The worst governance failure means the system runs on autopilot — not ideal, but not catastrophic. Physical cooperatives can't automate their value distribution; Open Utopia projects can.

### Design Responses

1. Direct democracy with three independent thresholds ensures no function dominates
2. Attribution sunset forces periodic re-ratification by contributor vote
3. SPT modifications prospective-only, contributor vote (all three function scores > +0.33) + Tribunal review
4. Innovation & Ecosystem Fund allocations approved by contributor vote with 25% project cap
5. Passive user SCT baseline eliminable if securities risk materializes
6. Charity allocation via curated shortlist with auto-donate safety net
7. Net-positive impeachment threshold in each function enables fast removal; four-level diagnostic warns before it reaches that point
8. Pre-launch requirements: cooperative law counsel, Subchapter T filing, concrete bootstrap funding plan
9. Discipleship multiplier and structured apprentice path to ensure expert reproduction

---

## Product Design Status

```
PRODUCT LINE                       PATHS              TIMELINE        STATUS
──────────────────────────────────────────────────────────────────────────────
SwarmTrap Shield (free + paid)     P1, P4, P10        Month 1-6       ✅ Designed
SwarmTrap Feed API (MSSP)          P1 (paid)          Month 4-8       ✅ Designed
SwarmTrap Protect (free IDS)       Funnel             Month 6         ✅ Designed
SwarmTrap Detect + Datasets        P2, P3             Month 9-15      ✅ Designed
SwarmTrap OEM Embedded             P5                 Month 18+       ✅ Designed
Expert Collective                  P9                 Month 1+        ✅ Designed
SwarmTrap Platform APIs            P11                Month 6-9       ✅ Designed
SwarmTrap BAS Content              P8                 Month 12-18     🔲 Not started
SwarmTrap Risk Score               P7                 Month 18-24     🔲 Not started
SwarmTrap Federal                  P6                 Month 24-36     🔲 Not started
```

---

## Appendices

### Appendix A: Complete Design Documents

1. **SwarmTrap Crowd Reward System Design** — Complete SCT token mechanics, attribution matrix, measurement systems, decay model, anti-gaming measures
2. **SwarmTrap Profit-Share Historical Foundations** — Rochdale Principles, Ostrom's 8 principles, Mondragon case study, patronage dividends, ESOP evidence, global cooperative survival statistics
3. **SwarmTrap Governance System** — Direct democracy, role-weighted voting, three-function thresholds, Executive compensation, tiered Tribunal
4. **SwarmTrap Financial Model Stress Test** — Revenue scenarios, contributor population models, per-contributor earnings calculations, sensitivity analysis
5. **SwarmTrap Worst-Case Analysis v2** — 12 stress tests, compound nightmare scenario, consolidated risk register, design responses
6. **Open Utopia Growth Mechanism Design** — Expert Collective architecture, discipleship program specification, ERB process, forge pipeline procedures
7. **SwarmTrap Shield Revenue Design** — Foundation product specification, free global attacker IP list, SMB DSTNAT and Corp WireGuard connectivity, syslog correlation engine, farm architecture, freemium flywheel, go-to-market sequence
8. **SwarmTrap Models + Datasets Revenue Design** — Paths 2, 3, and 5 product specification, SwarmTrap Protect free IDS, SwarmTrap Detect paid model tiers, curated dataset catalog, OEM/embedded licensing strategy
9. **SwarmTrap OEM Sales Approach** — OEM sales playbook, partner prioritization (Tier 1-3), evaluation package, commercial negotiation structures
10. **SwarmTrap Expert Collective Revenue Design** — Path 9 specification, four offerings, services-to-product conversion pipeline, conference strategy, staffing model
11. **SwarmTrap Ecosystem Entrepreneur Platform Design** — Path 11 specification, Platform API catalog, venture model, revenue-share framework, example ventures

### Appendix B: Technical Specifications

- SwarmTrap Dataset & Database Specification
- SwarmTrap Conversation Dataset v1 Specification — Conversation signature classification, 12-channel × 256-turn sequence architecture, 42 static features, behavioral archetype labels, multi-tier labeling pipeline
- SwarmTrap CNN v1 Model Specification
- SwarmTrap CNN v2 Model Specification — 3-class TCP-only redesign based on real data findings (see below)
- SwarmTrap XGBoost v1 Model Specification
- SwarmTrap AIO Agent Specification v2
- SwarmTrap Open-Source Monetization Strategy

#### CNN v2 — What Real Data Taught Us (March 2026)

Training the first CNN model on real captured data produced findings that will shape every subsequent product and model decision. These are documented here as empirical results, not design changes — product implications remain open.

**Finding 1: 3 classes, not 5.** The v1 spec defined five flow classes: RECON, KNOCK, BRUTEFORCE, EXPLOIT, COMPROMISE. Real data proved KNOCK and BRUTEFORCE are indistinguishable at the flow level — 54% F1, essentially a coin flip. Collapsing to three classes (RECON / ATTACK / CLEAN) raised CNN accuracy from the v1 baseline to 94.5% macro F1. The model is telling us where the real decision boundaries are in packet data. The five-stage lifecycle may still be valid at the conversation or session level, but at individual flow classification, three classes is what the data supports.

**Finding 2: TCP only.** ICMP responses look clean to the model. UDP probes have a fundamentally different profile. Mixing protocols confused the classifier. Filtering to TCP-only (ip_proto=6) produced cleaner, more reliable results. Protocol-specific models for ICMP and UDP remain a future question.

**Finding 3: 40% of "clean" data was dirty.** The clean SPAN capture — intended as ground truth for legitimate traffic — contained 33,941 IPs (13.5%) that were real scanners, generating 40% of all flows labeled clean. Without XGBoost scoring to identify and split out the contamination, the CNN was training on poisoned labels. Lesson: clean ground truth is harder to produce than attack ground truth. Every future clean dataset requires active verification.

**Finding 4: Egress data creates trivial shortcuts.** VLAN 101 traffic (the honeypot hosts responding to attackers) has reversed src/dst and near-zero pkts_fwd. Including it in training let the model learn a shortcut — "if packets look backwards, classify as clean" — instead of learning real behavioral patterns. Ingress-only filtering eliminated this.

**Finding 5: No reply = RECON, always.** Regardless of what the evidence labeling system says, if pkts_rev=0 the target never responded. That is scanning by definition. Overriding evidence labels with this hard rule improved label quality across the entire dataset.

**Finding 6: XGB and CNN see different things.** XGBoost (98.9% accuracy) excels at scanner detection using campaign-level aggregate features. CNN (94.5% accuracy) excels at exploit detection using packet sequence patterns, flag transitions, and timing. Their blind spots don't overlap. Together: >99.5% dirty IP detection. The ensemble is stronger than either model alone, and for a structural reason — they operate on fundamentally different representations of the same data.

**Finding 7: CNN cannot use campaign features at inference time.** At inline scoring (hunter2 session flush), source campaign statistics haven't been computed yet. The CNN must classify from packet sequences and flow-level features alone. This naturally splits the two models into real-time (CNN) and batch validation (XGB) roles.

**Finding 8: The tokenizer had bugs.** The v1 flag embedding accepted raw bitwise OR values that could exceed the vocabulary size, causing silent out-of-bounds errors. The size_dir embedding required an undocumented +11 offset that was handled inconsistently. Both are fixed in v2.

**Open questions these findings create:**

- Does the per-service expert model architecture (one XGBoost per protocol) still hold, or does a unified 3-class model across all TCP perform better?
- Where does the RECON/ATTACK boundary sit for the conversation classifier? The five-stage lifecycle may be recoverable at session level even if flow-level classification is three classes.
- How should the free (Protect) vs. paid (Detect) model split account for the ensemble finding? The ensemble is the real product — which pieces are open-source and which are proprietary?
- What does protocol-specific modeling look like for UDP and ICMP now that they're excluded from the TCP classifier?

These questions feed the next round of model design and will inform product decisions for Protect, Detect, and the OEM tier.

### Appendix C: Charter Amendment Procedure

**New Legislation:**

1. Proposal submitted to the public ledger by any contributor
2. Petition threshold crossed with minimum P/C/B support
3. Structured deliberation period (90 days for Charter amendments, 30 days for standard legislation)
4. Full contributor vote (four-level): all three function scores must independently exceed +0.33
5. If any function shows high "something wrong" rather than "strong against": targeted amendment period opens before re-vote
6. Upon passage, strength classification assigned: Strong (all > +0.70), Moderate (all > +0.50), or Bare (any +0.33 to +0.50)
7. Re-ratification schedule set: Strong = 4 years, Moderate = 2 years, Bare = 1 year
8. For Charter amendments: Supreme Tribunal reviews for Immutable Article compliance
9. If Tribunal certifies compliance: amendment takes effect
10. If Tribunal finds violation of Immutable Article: amendment is void

**Re-ratification:**

1. System automatically submits existing law for re-vote when its re-ratification window expires
2. Full contributor vote (four-level) using same mechanism as original passage
3. If all three function scores exceed +0.33: law re-ratified with updated strength classification and new re-ratification schedule
4. If any function score falls below +0.33: law expires
5. Full voting history stored on the public ledger (Article IV)

### Appendix D: Key Dates

- **Founding Design Session:** February 28, 2026
- **Revenue Design Sessions:** March 2026
- **CNN v2 Training & Real Data Findings:** March 18-21, 2026
- **Governance Redesign Session:** March 27, 2026
- **Three Functions Theory & Direct Democracy Design:** March 29, 2026
- **Founders:** Charles Chen, Claude (Anthropic)
- **First Open Utopia Project:** SwarmTrap (cybersecurity threat intelligence)
- **Framework Status:** Version 4.0 — Pre-launch specification

---

*This document is the founding specification of SwarmTrap, the first Open Utopia project. For the transferable framework — the philosophy, governance patterns, growth mechanism, and adoption guide — see the [Open Utopia Founding Document](Open_Utopia_Framework_v4.md).*
