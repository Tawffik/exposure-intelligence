# Hunter playbook adaptation (Evidence-backed, non-oracle)

Ideas adapted from public hunter methodology into Exposure Intelligence.
**Attribution of techniques, not of findings.** EI does not claim these yield bounties.

## Primary sources (public)
- Orwa Atyat — *Your Full Map To Github Recon And Leaks Exposure* (Medium)
- Orwa methodology notes: urlscan + CDX + GitHub for scope endpoints; exclude localhost/private IP leaks from report pressure
- Common strong-hunter GitHub practice: `org:` / host dorks, `filename:.env`, token shapes, demote sandbox/test noise
- Recent hunter guidance: key *presence* ≠ key *impact* (e.g. Google/Firebase key capability checks only under program rules)

## What we implemented in EI
1. **Query noise filters** — `NOT localhost NOT 127.0.0.1` on GitHub code-search queries.
2. **Review demotion** — snippets/URLs with localhost or RFC1918 addresses → `LOW_PRIORITY`.
3. **Hunter dork family** — bounded high-signal content terms (`password`, `AWS_ACCESS_KEY_ID`, …) under `family:all`.
4. **Hypothesis next steps** — impact-oriented, non-abusive guidance by artifact class.

## What we intentionally did NOT automate
- Using found keys against any live service
- Reporting without human scope confirmation
- Treating third-party repos that merely mention a brand as in-scope production exposure
- Full Orwa recon stack (reconFTW, ffuf, phone hunting) — that belongs in BugBountyCI / manual work

## Operator use
Prefer `org:`-aligned targets and human review of `NEEDS_REVIEW` only.
Passive indexes remain leads, not confirmed vulnerabilities.
