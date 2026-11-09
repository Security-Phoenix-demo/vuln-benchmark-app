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

## Chains (each C has a designated A parent)

| C flaw | Reached through | How |
|---|---|---|
| C1 export SQLi | A10 | forge a token with `alg none` |
| C2 log traversal | A3 | command injection `cat` the secrets file, forge an HS256 admin token |
| C3 template injection | A4 | path traversal reads the secrets file, forge an admin token |
| C4 plugin RCE | A9 + A1 | upload `plugin.js`, SQLi login gives the admin token, load it |
| C5 stored XSS | A1 | a failed login with an HTML username lands in the audit log |
| C6 file write | A7 | debug env returns the JWT secret, forge an admin token |
| C7 webhook SSRF | A6 | `eval` reads the JWT secret, forge an admin token |
| C8 internal command injection | A5 + A8 | A8 leaks the key, A5 SSRF calls `/internal/run` |
| C9 internal user dump (MD5) | A5 + A8 | same key, SSRF calls `/internal/users` |
| C10 prototype pollution | A2 | UNION dumps the admin MD5 hash, crack it, log in |

`npm run verify` walks each chain using only its parent. It also checks the C routes stay closed without a parent step.

## Rules for a fair score

1. Point the scanner at the base URL only. No answer key, no source hints.
2. DAST match key: endpoint + method + CWE. Hunt match key: file + CWE (and the reachable flag).
3. Each group B finding reported as reachable costs one point. See `scripts/score.py`.
