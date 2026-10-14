# Exposure Intelligence (EI)

**Passive information-disclosure research assistant** for authorized bug-bounty / VDP work.

You enter a target domain in GitHub Actions → EI queries **public indexes only** → you download an artifact → you open **`HUMAN_QUEUE.md`** first.

---

## What this is

| EI does | EI does **not** |
| --- | --- |
| Search public GitHub code, URLScan, and web archives for **mentions / files** related to a host | Confirm vulnerabilities or production impact |
| Keep **honest** provider status (`PARTIAL`, `RATE_LIMITED`, `ERROR`) | Replace TruffleHog, Nuclei, or a full recon stack |
| Triage noise (examples, localhost, third-party noise) | Probe the target host by default |
| Produce a short **human queue** of leads worth opening | Guarantee bounty payouts |

**Sister project for active recon/scan:** [BugBountyCI](https://github.com/Tawffik/BugBountyCI) — do not mix the two.

---

## Operator path (phone / Actions)

1. Open **Actions** → **Exposure Intelligence Research**
2. **Run workflow**
3. Inputs:
   - `target` = hostname only (e.g. `example.com`)
   - `research_mode` = `passive` (live indexes) or `demo` (fixtures)
   - `authorization_status` = usually `UNKNOWN` (no host probing)
4. Wait for the run → download the artifact
5. Open **`HUMAN_QUEUE.md` first**
6. Only if needed: full `research-queue.md`, `provider-status.json`, `export-v1.json`

### How to read `HUMAN_QUEUE.md`

- **0 items** does **not** mean “safe” — check the provider table (rate limits / errors)
- Each item is a **lead** (`confirmed_vulnerability: false` always)
- Follow **Safe next step**; do not use any leaked keys
- Optional secret verification: install TruffleHog locally and use `ei.optional_secret_verify` (off by default)

---

## Architecture (one diagram)

```text
target host
    → GitHub Code Search (needs token)
    → URLScan search (public API)
    → Internet Archive CDX (public API)
    → normalize + DNS-boundary attribution
    → classify + evidence review
    → HUMAN_QUEUE.md  +  full audit files
```

Live application-host probes exist in the library behind **ACTIVE** authorization and are **not** enabled by the default Actions workflow.

---

## Local CLI

```bash
git clone https://github.com/Tawffik/exposure-intelligence.git
cd exposure-intelligence
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Offline demo (fixtures only)
python -m ei.cli demo -o /tmp/ei-demo
# then open /tmp/ei-demo/HUMAN_QUEUE.md if present (via Actions path / report bundle)
```

Tests:

```bash
pytest
```

---

## Status

- **Version:** 0.5.x on `main`
- **Product stance:** READY_WITH_LIMITATIONS — useful passive triage, not a hunter replacement
- **Charter / Notion:** research method docs under `docs/`

### Explicit non-goals

- Autonomous exploitation or key use  
- Copying BugBountyCI’s full pipeline into this repo  
- Claiming precision/recall from a small benchmark alone  

---

## License

MIT
