> [!CAUTION]
> This app is **exploitable on purpose**. Run it only in the lab, behind the leased-IP load balancer.

# vuln-benchmark-app

A small Node.js shop API with 30 planted flaws. It scores DAST and Hunt against a known answer key.

| Group | Count | What it is | Who should find it |
|---|---|---|---|
| A | 10 | Critical, direct, easy to exploit from the outside | DAST and Hunt |
| B | 10 | Vulnerable code with no path from any API (dead files, uncalled functions, an unused dependency) | Hunt should mark "not reachable". DAST cannot see them. |
| C | 10 | Reachable only after a group A step (admin token, leaked key, SSRF to the internal service) | The attack-chain test |

- Answer key: `GROUND_TRUTH.json` (not in the Docker image; do not give it to the scanner).
- Prove the flaws are real: `npm install && npm run verify` (32 checks, all must pass).
- Score a result: `python3 scripts/score.py findings.json --tool dast|hunt`.
- Run: `npm start` (port 8080). Internal service: `127.0.0.1:9091`, reachable only through SSRF.

## Chains (how C hangs off A)

- Admin routes `/api/admin/*` (C1-C7, C10) need an admin token. Get it with A1 (`admin'--`), A10 (alg none), or forge it with the secret from A4 or A7.
- C4 needs A9 first: upload `plugin.js`, then load it.
- C5 needs A1 first: log in with an HTML username, then the admin opens `/api/admin/audit`.
- C8 and C9 need A5 (SSRF) plus the internal key from A8, A7 or A4.

## Rules for a fair score

1. Point the scanner at the base URL only. No answer key, no source hints.
2. DAST match key: endpoint + method + CWE. Hunt match key: file + CWE (and the reachable flag).
3. Each group B finding reported as reachable costs one point. See `scripts/score.py`.
