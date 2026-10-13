# Shopify passive research cycles (v0.5.x)

Target: shopify.com (public HackerOne program). Mode: passive public indexes only.

## External ideas adapted (not copied as deps)

| Source | Idea adapted |
|--------|----------------|
| Secret scanners (gitleaks/truffle-style patterns) | Expanded SECRET_PATTERNS: shopify tokens, google API, JWT-like |
| JSProbeX-style JS secret hunt | Already have source map + openapi families; env path boost |
| URLScan path search | Supplemental `domain:X AND filename:.env` passive search |
| Multi-dork practice | Interleaved org: + host-scoped families with per-query caps |

## Verified live outcomes

- org:shopify filename:.env returned official Shopify repo paths (e.g. shopify_django_app/.env.local)
- Fixture/test paths demoted to LOW_PRIORITY
- Rate limits remain the main operational constraint on GitHub code search

## Not claimed

- No confirmed vulnerability on shopify.com production
- No active host probing without ACTIVE authorization
