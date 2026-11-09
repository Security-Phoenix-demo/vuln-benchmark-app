#!/usr/bin/env python3
"""Score a DAST or Hunt result against GROUND_TRUTH.json.

Input: a JSON list of findings: [{"endpoint": "/api/login", "cwe": "CWE-89", "method": "POST",
"title": "...", "reachable": true}]. "reachable" is optional (Hunt sets it; DAST leaves it out).
Usage: python3 scripts/score.py findings.json [--tool dast|hunt]

Match rule: the finding endpoint path equals the truth endpoint (query string ignored)
and the CWE equals the truth CWE. Group B has no endpoint, so a B hit is a finding whose
file or title names the dead file or symbol.
"""
import json, re, sys
from pathlib import Path

truth = json.loads((Path(__file__).parent.parent / "GROUND_TRUTH.json").read_text())["findings"]
found = json.loads(Path(sys.argv[1]).read_text())
tool = sys.argv[sys.argv.index("--tool") + 1] if "--tool" in sys.argv else "dast"

def cwe(s):
    m = re.search(r"\d+", str(s or ""))
    return m.group(0) if m else ""

def path_of(s):
    return re.sub(r"[?#].*$", "", str(s or "")).rstrip("/")

def hit(t, f):
    if t["group"] in ("A", "C"):
        return path_of(f.get("endpoint")) == t["endpoint"] and cwe(f.get("cwe")) == cwe(t["cwe"])
    text = json.dumps(f)
    return t["file"] in text or t.get("symbol", "\0") in text

rows, used = [], set()
for t in truth:
    m = [i for i, f in enumerate(found) if hit(t, f)]
    used.update(m)
    rows.append((t, bool(m), m and found[m[0]]))

print(f"Tool: {tool}\n")
for g, label in (("A", "A direct, easy"), ("B", "B unreachable"), ("C", "C attack chain")):
    grp = [r for r in rows if r[0]["group"] == g]
    n = sum(1 for r in grp if r[1])
    print(f"Group {label}: reported {n}/{len(grp)}")
    for t, ok, _ in grp:
        print(f"  {'FOUND  ' if ok else 'MISSED '} {t['id']:<4} {t['cwe']:<9} {t.get('endpoint') or t['file']}")

a = sum(1 for r in rows if r[0]["group"] == "A" and r[1])
c = sum(1 for r in rows if r[0]["group"] == "C" and r[1])
b_rep = [r for r in rows if r[0]["group"] == "B" and r[1]]
# For group B the right behaviour is: do NOT report it, or report it as not reachable.
b_bad = [r for r in b_rep if r[2].get("reachable") is not False]
unmatched = len(found) - len(used)
score = (a * 1.0 + c * 2.0 - len(b_bad) * 1.0) / (10 * 1.0 + 10 * 2.0) * 100
print(f"\nGroup B reported as reachable (wrong): {len(b_bad)}/10")
print(f"Findings that match nothing in the answer key: {unmatched}")
print(f"Benchmark score: {score:.1f} / 100  (A=1 pt, C=2 pt, each wrong B = -1 pt)")
