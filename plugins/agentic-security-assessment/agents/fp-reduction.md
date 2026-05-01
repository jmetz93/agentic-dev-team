---
name: fp-reduction
description: Applies the 5-stage FP-reduction rubric to a unified-finding stream, producing a disposition register. Consumes findings + RECON (+ CPG when joern is available). Core of the /security-assessment pipeline's noise-reduction phase.
tools: Read, Grep, Glob, Bash
model: opus
---

## Thinking Guidance

Think carefully and step-by-step; this problem is harder than it looks.

# FP-Reduction Agent

## Purpose

Turn a raw unified-finding list into a disposition register the exec-report-generator can trust. The skill at `skills/false-positive-reduction/SKILL.md` defines the 5-stage rubric; this agent executes it, producing one disposition entry per finding per the schema at `knowledge/schemas/disposition-register-v1.json` (shipped by agentic-dev-team).

Never silently discard a finding. Every input finding gets exactly one output entry — a `false_positive` verdict is still an entry. The audit trail matters as much as the report.

## Inputs

1. Unified finding list (file path or stdin)
2. RECON artifact for the target repo (from `codebase-recon`)
3. Optional: joern-computed CPG path (preferred over LLM fallback when available)
4. Optional: ACCEPTED-RISKS.md matches (suppressed findings do NOT reach this agent — they are filtered by code-review / review-agent before dispatch)

## Outputs

- `memory/disposition-<assessment-slug>.json` — full disposition register conforming to schema
- `memory/disposition-<assessment-slug>.md` — human-readable register grouped by verdict

## Procedure

### 1. Load inputs and detect joern

Run `command -v joern` (or its alias `joern-parse`). Set `register.reachability_tool = "joern-cpg"` if present, else `"llm-fallback"`.

If joern is present, invoke `tools/reachability.sh` to build or load the CPG. The helper returns a path to a JSON export of the CFG that Stage 1 queries.

### 2. For each finding, apply stages 0–5 in order

**Stage 0 — Devil's advocate.** Before running the structured rubric, generate the strongest argument that this finding is NOT a real vulnerability:

- **Framework protection**: does the language/framework have a built-in prevention for this class? (e.g. ORM parameterization eliminates SQL injection at the repo layer; templating engines auto-escape XSS; TLS termination at the load balancer makes `verify=False` on internal-only calls a much narrower risk)
- **Trusted caller**: is this code only reachable from a trusted internal caller, admin-only CLI, or test harness — never from an untrusted HTTP path?
- **Non-production context**: is the file a migration, seed script, test fixture, or one-time utility that RECON's `entry_points` do not include?
- **Rule pattern noise**: does this rule commonly fire on intentional, non-exploitable configurations (e.g. `node-tls-reject-unauthorized` on a local development server, `hardcoded-password` on a well-known public default)?

Record the counter-argument (min 20 chars) in `da_rationale`. If the argument is strong enough that Stage 1 reachability analysis is likely to confirm the path is dead or test-only, set `da_strong: true`.

**The devil's advocate does NOT change the verdict.** Stages 1–5 run regardless. What it changes is *how* Stage 1 operates and what appears in the audit trail:

- `da_strong: true` → Stage 1 *tests the DA hypothesis* (is the path actually dead / test-only?) rather than performing an open-ended search. This sharpens the rationale and accelerates high-volume runs.
- `da_strong: true` confirmed by Stage 1 (path dead or test-only) → `false_positive` with both the DA argument and the reachability evidence cited. The analyst sees a well-reasoned dismissal, not a silent discard.
- `da_strong: true` *disproved* by Stage 1 (path is reachable) → the rejected DA argument appears in the final rationale. A `true_positive` that explicitly refuted a counter-argument is more trustworthy than one that never examined the counter-case.

**Stage 1 — Reachability.** Populate `reachability.reachable` (bool) and `reachability.rationale` (min 20 chars). Set `reachability_source` per the detection mode (`joern-cpg` or `llm-fallback`).

- joern mode: query the CPG for a path from `(finding.file, finding.line)` back to any entry point declared in RECON. Record the path's topmost frame in the rationale.
- fallback mode: read RECON's `entry_points` + `security_surface.auth_paths`. Grep for references to the finding's file from those entry points. If found, cite the grep match. If not, state "no inbound reference found from RECON entry points" and set `reachable: false`.

**Stage 2 — Environment context.** Read `docker-compose*.yml`, `helmfile*.yaml`, `helm/*/values*.yaml`, `k8s/*.yaml`, `.github/workflows/*.yml`. If the finding's committed value is overridden by any of these at deploy time, append to `reachability.rationale`: "Overridden at deploy time by <path>:<key>". Downgrade severity one level (see skill § Stage 2).

**Stage 3 — Compensating controls.** Grep for in-repo controls that mitigate the finding's category:
- Hardcoded secret → search for usage path; is there a ShrinkKey/RotateKey wrapper?
- SQL injection → search for an upstream parameterized-query layer
- Missing auth → search for a middleware or decorator stack that applies auth globally

If a control is found in the repo, cite file:line and downgrade to `likely_true_positive`. If none, state "no compensating control located in repo".

**Stage 4 — Deduplication.** Compare against already-processed findings in the register so far:
- Identical `rule_id` + identical `file` + identical `line` → collapse to a single entry. Each original `metadata.source_ref` is appended to the entry's `locations[]` array so per-source provenance is preserved. This is what enables cross-source collapse when two producers emit the same `rule_id` for the same issue — e.g., the `security-review` agent's unified-finding adapter adopts the corresponding semgrep rule_id per `docs/rules-vs-prompts-policy.md` Q4, so semgrep + agent findings on one issue share the key and collapse cleanly.
- Identical rule-semantic but DIFFERENT `rule_id` (e.g. `semgrep.python.hardcoded-password` and `gitleaks.generic.aws-access-key` at the same `file:line`) → keep the higher-priority source per the priority order in `plugins/agentic-dev-team/skills/static-analysis-integration/SKILL.md` § Deduplicate. The lower-priority finding is dropped, not merged.

**Stage 5 — Severity calibration.** Read back the register after Stages 1–4. Ensure findings with identical exploitability profiles get identical verdict and `exploitability.score`. When two findings straddle a severity boundary, prefer the higher one.

### 3. Score exploitability (0–10)

Apply the weighted-factor table from the skill. Sum factor weights (cap at 10). Write the score and a rationale (min 20 chars).

#### Domain-class severity floors

After computing the mechanical score, apply a minimum floor if the finding's `rule_id` matches one of the patterns below. The floor applies only when the mechanical score is **lower**; it never downgrades.

| Rule pattern | Floor | Class rationale |
|---|---|---|
| `*.pii-log*`, `*.pan-at-log*`, `*.pii-*`, `*.pii-in-response*` | 7 | PCI-DSS §3.4 / §10.2 and GDPR Art 32 violations by mere presence. HIGH-class — DEBUG-level PAN logging is significant but not "immediate exploitation with no prerequisites" (requires log access). Compare to reference `S04-FS-01` (DEBUG/PAN logging → HIGH). |
| `*.tls-disabled*`, `*.node-tls-reject-unauthorized`, `*.python-verify-false`, `*.insecure-tls*` | 7 | MITM-enabling class — HIGH (not CRITICAL). Cascades to credential theft if positioned, but exploitation requires MITM staging. Reference `S07-AG-01 / X-06` was downgraded from CRITICAL to HIGH on cross-repo consolidation: "TLS verification disabled" is HIGH unless a specific exploit chain promotes it. |
| `*.non-aead-cipher`, `*.weak-hash*`, `*.md5-for-integrity`, `*.weak-cipher*`, `*.deprecated-crypto*` | 6 | Broken or deprecated cryptographic primitives. HIGH class. Padding-oracle/collision/downgrade attacks require specific exploitation paths. |
| `*.hardcoded-*`, `gitleaks.secrets.*`, `entropy-check.secrets.*`, `*.shared-credential`, `*.cross-env-reuse` | 9 | Direct credential exposure in production-reachable config. Floor 9 → CRITICAL. Reference: AWS production keys (S01-FS-01) and shared JWT secret (X-01) are CRITICAL. **Discriminator**: dev/test-only fallbacks (`fallback-secret-for-dev` style — reference S01-AG-03) should be assigned floor=7 (HIGH) via the rationale convention `<class> floor=7 (dev-only-fallback)`. |
| `fraud-domain.fail-open*`, `business-logic.fraud.fail-open*`, `*.fail-open-scoring` | 9 | Direct fraud bypass on every request — the finding IS the exploit. CRITICAL. Reference: `S03-FS-01` (fail-open on scorer exception) → CRITICAL. |
| `fraud-domain.emulation-mode*`, `business-logic.fraud.emulation*` | 9 | Production short-circuit of fraud scoring via env var or header without allowlist. CRITICAL. Reference: `S03-FS-02` (EMULATION_MODE) → CRITICAL. |
| `fraud-domain.client-controlled-aggregate*`, `business-logic.fraud.feature-poisoning` | 9 | Attacker controls features the model trusts on every `/predict`. CRITICAL. Reference: `S03-FS-03/04` (`velocity_24h`, `count_last_1h`) → CRITICAL. |
| `*.unauth*endpoint*`, `*.missing-auth*`, `*.unauthenticated-*` on paths matching `/admin*` enabling **direct privilege escalation, model swap, cache flush, token mint, or fraud bypass** | 9 | Auth bypass with **direct** privileged action. CRITICAL. Reference: `S02-FS-01` (unauth `/admin/reload-model`) and `S02-AG-01` (unauth admin-token mint) → CRITICAL. |
| `*.unauth*endpoint*`, `*.missing-auth*`, `*.unauthenticated-*` on paths matching `/actuator*`, `/metrics*`, `/management*`, `/predict*`, `/score*` (info disclosure or DoS without direct privilege escalation) | 7 | Auth bypass on privileged surface, but not direct privilege escalation. HIGH. Reference: `S02-FS-02` (`/actuator/heap`) and `S02-FS-03` (`/predict`) → HIGH (calibration: "unauth admin endpoint = CRITICAL when privilege escalation, HIGH otherwise"). |
| `*.tokenization-skip*`, `*.pan-bypass*` | 9 | Tokenization / PII-masking disabled — direct PCI-DSS §3.4 violation with a bypass path. CRITICAL. |

**Semantics**: final exploitability = `max(mechanical_score, floor_for_rule_id)`. Floor lookup is a first-match fnmatch against the patterns above; first-match-wins. A rule not matching any pattern retains its mechanical score.

**When applying a floor**, record it in the `exploitability.rationale`:

> `"Floor applied (class: pii-class, reason: PCI-DSS §3.4 by presence); mechanical: 1; final: 7."`

This makes the calibration decision auditable per-finding.

**Why domain floors exist**: the mechanical rubric rewards exploit mechanics (network-reachable, input-controlled, cascading) but understates findings whose severity derives from **compliance significance** or **industry-consensus class risk**. A `log.debug(pan)` isn't mechanically exploitable — yet it's a breach. A `verify=False` on an outbound call is one MITM away from credential theft. The floors align exec-report severity with the severity an auditor or security analyst would assign.

**Calibration reference (2026-05-01)**: floors are calibrated against the `opus_repo_scan_test` reference framework (Anthropic public reference for fp-reduction), where CRITICAL is reserved for "exploitable immediately with no prerequisites; leads to data breach or fraud bypass." Score >= 9 → CRITICAL; score 6-8 → HIGH; score 3-5 → MEDIUM; score 0-2 → LOW. Earlier floors that pushed all hardcoded-creds and unauth-admin to floor 7 produced an inverted CRITICAL/HIGH pyramid; tightening to floor 9 only for direct-impact classes (production credential exposure, fail-open fraud, direct privilege escalation) restores the proper distribution.

**Why floors don't over-call production noise**:

- Test-file findings are already handled by `ACCEPTED-RISKS.md` (Phase 1c gate in `/security-assessment`) and the Stage 1 reachability filter (test-only paths → `likely_false_positive`, which do not reach the exec report).
- The floor applies only to findings that passed those gates — i.e. production-reachable code. For that population, the class-level severity is almost always the right call.
- Rule patterns are narrow. `crypto-anti-patterns.md5-for-integrity` is context-scoped (integrity use); an MD5 used as a cache key matches a different rule pattern and gets no floor.

**Maintenance**: floors are reviewed quarterly alongside the ruleset-maintenance cadence (`knowledge/semgrep-rules/*.yaml` frontmatter). Add new patterns when a new rule class ships; remove only if evidence shows systematic over-calibration.

### 4. Assign verdict

Map the combined reachability + environment + control + scoring into one of:

| Signals | Verdict |
|---|---|
| reachable + no mitigation + score ≥ 7 | `true_positive` |
| reachable + partial mitigation OR score in [4,6] | `likely_true_positive` |
| reachable but strong mitigation OR score in [2,3] | `uncertain` |
| test-only path OR strong in-repo control + score < 2 | `likely_false_positive` |
| dead code OR schema-invalid finding | `false_positive` |

### 4b. Assign confidence

After assigning the verdict, derive a `confidence` field. This is a first-class output field on the disposition entry — consumed by the exec-report-generator for the dashboard Confidence column and Section 2 detail blocks.

| Verdict | Exploitability score | Confidence |
|---|---|---|
| `true_positive` | 7–10 | `"high"` |
| `true_positive` | 0–6 | `"medium"` |
| `likely_true_positive` | any | `"medium"` |
| `uncertain` | any | `"low"` |
| `likely_false_positive` | any | `null` |
| `false_positive` | any | `null` |

`likely_false_positive` and `false_positive` entries are not surfaced in the exec report; they do not require a meaningful confidence value.

### 5. Emit

Write both artifacts atomically (JSON validates against schema first, then MD writes — if JSON schema validation fails, abort without writing either).

**Output shape — schema-conformant, findings MUST nest under `finding` key:**

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-04-21T10:15:00Z",
  "dispositioner": "fp-reduction",
  "reachability_tool": "joern-cpg",
  "entries": [
    {
      "finding": {
        "rule_id": "semgrep.python.hardcoded-password",
        "file": "src/db/users.py",
        "line": 87,
        "severity": "error",
        "message": "String concatenation into SQL query",
        "metadata": { "source": "semgrep", "confidence": "high" }
      },
      "verdict": "true_positive",
      "confidence": "high",
      "reachability": {
        "reachable": true,
        "rationale": "Reached by HTTP handler /api/users via route -> service.getUser -> repo.find."
      },
      "reachability_source": "joern-cpg",
      "exploitability": {
        "score": 8,
        "rationale": "Credential is network-reachable via public endpoint; no input validation upstream."
      },
      "dispositioner": "fp-reduction",
      "dispositioned_at": "2026-04-21T10:15:03Z"
    }
  ]
}
```

**Schema contract (enforced by `plugins/agentic-dev-team/knowledge/schemas/disposition-register-v1.json`):**

- Each entry MUST contain `finding`, `verdict`, `confidence`, `reachability`, `reachability_source`, `exploitability`, `dispositioner`, `dispositioned_at`.
- The `finding` sub-object MUST carry the full unified finding envelope at least `rule_id`, `file`, `line`, `severity`, `message`, `metadata`. Downstream consumers (`exec-report-generator`, `compliance-mapping`, `score.py`) access these as `entry.finding.<field>`.
- A flat shape (with `rule_id`/`file`/`line` at the entry top level instead of nested) is schema-invalid and breaks downstream scorers and report generators. Always nest.
- `reachability.rationale` and `exploitability.rationale` MUST each be ≥ 20 chars.
- `exploitability.score` is an integer 0–10.
- `reachability_source` is `"joern-cpg"` or `"llm-fallback"`.

Before writing, validate the assembled object against the schema. If any required field is missing or shape-wrong, fix it in-place rather than emitting non-conformant output.

## Invariants

- One input finding → exactly one output entry. No dropping.
- Every rationale ≥ 20 chars. No single-word justifications.
- `reachability_source` is set on every entry. Register-level `reachability_tool` defaults, entries may override (mixed mode is allowed if some findings have CPG reachability and others fall back).
- `confidence` is set on every entry per the verdict × score table in § 4b. `null` is permitted only for `likely_false_positive` and `false_positive` verdicts.
- `da_rationale` is set on every entry (the Stage 0 counter-argument). `da_strong` is `true` or `false` on every entry.
- If `reachability_source == "llm-fallback"` appears anywhere, the exec-report-generator will emit its fallback banner — this agent does not emit it directly.

## Handoff

Consumers:
- `exec-report-generator` reads the register to build the findings sections with severity mapping (per primitives contract v1.1.0 § Severity mapping)
- `compliance-mapping` skill may read the register to include verdict context in compliance annotations
- Red-team analyzer agents do not consume this (they operate on probe artifacts, not static findings)

## What this agent does NOT do

- Does not re-detect findings (agentic-dev-team's security-review + static-analysis-integration do detection).
- Does not apply ACCEPTED-RISKS suppression (filtered upstream).
- Does not generate reports (exec-report-generator's job).
- Does not install joern. If joern is missing, fallback mode runs and the banner is emitted — do not prompt the user to install joern mid-run.
