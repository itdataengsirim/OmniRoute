"""Turn raw scan outputs into a verdict (FAIL / REVIEW / OK) against the reviewed baseline.

Usage:
  python -I summarize.py <report_dir> <baseline_json> [--write-baseline]

FAIL   = malware/tamper signal that must block deploy until a human clears it.
REVIEW = new since the reviewed baseline; a human reads it, then runs `run.sh --accept`.
"""
import json, os, re, sys

rep, base_path = sys.argv[1], sys.argv[2]
write_baseline = "--write-baseline" in sys.argv
J = lambda n, d=None: json.load(open(os.path.join(rep, n), encoding="utf-8")) if os.path.exists(os.path.join(rep, n)) else d
scan = J("files.json", {})
meta = J("meta.json", {})
gl = J("gitleaks.json", []) or []
tv = J("trivy.json", {}) or {}
osv = J("osv.json", {}) or {}

TESTISH = re.compile(r"(^|/)(tests?|__tests__|fixtures|e2e|examples?)/|\.(test|spec)\.[a-z]+$|\.example$|\.md$|(^|/)docs/")
DOCISH = re.compile(r"(^|/)docs/|\.mdx?$|(^|/)(i18n|locales|messages)/|\.json$")
# Hard = essentially never legitimate in an app repo. env_dump / pipe_to_shell / powershell_dl /
# eval / vm are REVIEW: they have common legitimate uses (child-process env, install hints, detectors).
HARD_PATTERNS = {"decode_then_exec", "charcode_blob", "obfuscator", "miner", "reverse_shell",
                 "stealer_target", "exfil_endpoint", "py_exec_decoded", "py_import_os_system"}

keys = {
    "unicode": sorted({f"{u['f']}|{u['type']}|{u['cp']}" for u in scan.get("unicode", [])}),
    "binaries": sorted({f"{b['f']}|{b['size']}" for b in scan.get("binaries", [])}),
    "blobs": sorted({f"{b['f']}|{b['len']}" for b in scan.get("blobs", [])}),
    "long_lines": sorted({l["f"] for l in scan.get("long_lines", [])}),
    "wasm": sorted({f"{w['f']}|{w.get('sha256')}" for w in scan.get("wasm", [])}),
    "wasm_imports": sorted({i for w in scan.get("wasm", []) for i in w.get("imports", [])}),
    "patterns": sorted({f"{p['f']}|{p['pattern']}" for p in scan.get("patterns", []) if not p["test"]}),
    "hosts": sorted(scan.get("hosts", {}).keys()),
    "lifecycle": sorted({f"{h['f']}|{h['hook']}|{h['cmd']}" for h in scan.get("lifecycle", [])}),
    "svg_active": sorted({f"{s['f']}|{','.join(s['markers'])}" for s in scan.get("svg_active", [])}),
    "gitleaks": sorted({f"{g['File'].replace('/repo/', '')}|{g['RuleID']}" for g in gl}),
    "trivy": sorted({f"{v['PkgName']}@{v['InstalledVersion']}|{v['VulnerabilityID']}"
                     for r in (tv.get("Results") or []) for v in (r.get("Vulnerabilities") or [])}
                    | {f"{r['Target']}|{m['ID']}" for r in (tv.get("Results") or [])
                       for m in (r.get("Misconfigurations") or []) if m.get("Status") == "FAIL"}),
}

if write_baseline:
    keys["_commit"] = meta.get("head")
    json.dump(keys, open(base_path, "w", encoding="utf-8"), indent=1)
    print(f"baseline written for {meta.get('head')}")
    sys.exit(0)

base = json.load(open(base_path, encoding="utf-8")) if os.path.exists(base_path) else {}
new = {k: sorted(set(v) - set(base.get(k, []))) for k, v in keys.items()}
fail, review = [], []

# --- tamper / integrity
if meta.get("fsck_rc", 0) != 0:
    fail.append(f"git fsck reported errors (rc={meta['fsck_rc']})")
if meta.get("fork_only_commits"):
    review.append(f"{len(meta['fork_only_commits'])} commit(s) exist in origin but NOT in upstream "
                  f"(possible tampering in the fork): " + "; ".join(meta["fork_only_commits"][:10]))
if meta.get("upstream_error"):
    review.append(f"could not compare with upstream: {meta['upstream_error']}")
if meta.get("local_modified"):
    review.append(f"{len(meta['local_modified'])} tracked file(s) modified locally after checkout "
                  f"(not in any commit): " + ", ".join(meta["local_modified"][:15]))
if meta.get("head_not_on_remote"):
    review.append("local HEAD is not on the remote branch (unpushed/foreign commits): "
                  + "; ".join(meta["head_not_on_remote"][:10]))

# --- unicode
for u in scan.get("unicode", []):
    t, f = u["type"], u["f"]
    if t in ("BIDI_OVERRIDE", "TAG", "PUA", "VARSEL_OTHER"):
        fail.append(f"hidden-unicode {t} {u['cp']} x{u['count']} in {f}:{u['line']}")
    elif t == "BIDI_MARK" and not DOCISH.search(f):
        fail.append(f"bidi mark {u['cp']} in code file {f}:{u['line']}")
for k in new["unicode"]:
    f, t, cp = k.split("|")
    if t in ("ZEROWIDTH", "CTRL", "BIDI_MARK") and not DOCISH.search(f):
        review.append(f"new invisible char {t} {cp} in {f}")

# --- binaries / stego
for e in scan.get("exec_like", []):
    (fail if f"{e['f']}|{e['size']}" in new["binaries"] else review).append(
        f"executable/archive {e['kind']} {e['f']} ({e['size']} B)" + ("" if f"{e['f']}|{e['size']}" in new["binaries"] else " [in baseline]"))
for s in scan.get("stego", []):
    fail.append(f"stego signal in {s['f']}: {s}")
for k in new["binaries"]:
    review.append(f"new/changed binary file {k}")
for s in scan.get("svg_active", []):
    fail.append(f"active content in SVG {s['f']}: {s['markers']}")

# --- encoded payloads / wasm
for w in scan.get("wasm", []):
    if w.get("error"):
        review.append(f"embedded WASM in {w['f']} could not be parsed: {w['error']}")
        continue
    if w["suspicious_strings"]:
        fail.append(f"embedded WASM {w['f']} contains suspicious strings: {w['suspicious_strings'][:5]}")
    extra = sorted(set(w["imports"]) - set(base.get("wasm_imports", [])))
    if extra and not base:   # first scan: nothing reviewed yet — a human must read the import list
        review.append(f"embedded WASM {w['f']} imports (review once, then --accept): {extra}")
    elif extra:
        fail.append(f"embedded WASM {w['f']} imports host functions outside the reviewed set: {extra}")
for k in new["wasm"]:
    review.append(f"new/changed embedded WASM {k}")
for k in new["blobs"]:
    review.append(f"new/changed encoded blob {k}")
for k in new["long_lines"]:
    review.append(f"new very long line (minified/obfuscated?) in {k}")

# --- code patterns
for p in scan.get("patterns", []):
    if p["test"]:
        continue
    k = f"{p['f']}|{p['pattern']}"
    if p["pattern"] in HARD_PATTERNS and k in new["patterns"]:
        fail.append(f"{p['pattern']} in {p['f']}:{p['line']}  `{p['snippet'][:80]}`")
for k in new["patterns"]:
    f, pat = k.split("|")
    if pat not in HARD_PATTERNS:
        review.append(f"new {pat} usage in {f}")

# --- supply chain
for l in scan.get("lockfile", []):
    fail.append(f"lockfile {l['issue']}: {l['pkg']} -> {l['resolved']} ({l['f']})")
DL_EXEC = re.compile(r"(curl|wget)[^|]{0,200}\|\s*(ba|z)?sh\b|download-and-execute|ADD from remote URL|iex\s*\(|Invoke-Expression", re.I)
for k in new["lifecycle"]:
    if "AUTO-RUNS WHEN FOLDER IS OPENED" in k:
        fail.append(f"new editor task that runs automatically when the folder is opened: {k}")
    elif DL_EXEC.search(k):
        fail.append(f"new auto-run point that downloads and executes remote code: {k}")
    else:
        review.append(f"new/changed auto-run point (install/build/open/commit/CI): {k}")
for k in new["hosts"]:
    review.append(f"new outbound domain in runtime code: {k}")

# --- secrets (tracked files only: an untracked local .env is the operator's own config, not repo content)
tracked = set(scan.get("tracked", []))
gl = [g for g in gl if not tracked or g["File"].replace("/repo/", "") in tracked]
for g in gl:
    f = g["File"].replace("/repo/", "")
    if not TESTISH.search(f):
        fail.append(f"possible secret ({g['RuleID']}) in runtime file {f}:{g['StartLine']}")

# --- dependencies
mal, advis = [], 0
for r in osv.get("results", []):
    for p in r.get("packages", []):
        for v in p.get("vulnerabilities", []):
            advis += 1
            if v["id"].startswith("MAL-"):
                mal.append(f"{v['id']} {p['package']['name']}@{p['package']['version']}")
for m in mal:
    fail.append(f"KNOWN MALICIOUS PACKAGE {m}")
hc = []   # all current HIGH/CRIT findings (counted in the header); only NEW ones need review
known = set(base.get("trivy", []))
for r in tv.get("Results", []) or []:
    for v in r.get("Vulnerabilities") or []:
        hc.append(v)
        if f"{v['PkgName']}@{v['InstalledVersion']}|{v['VulnerabilityID']}" not in known:
            review.append(f"trivy: {v['Severity']} {v['PkgName']}@{v['InstalledVersion']} {v['VulnerabilityID']} (fix: {v.get('FixedVersion') or 'none'})")
    for m in r.get("Misconfigurations") or []:
        if m.get("Status") == "FAIL":
            hc.append(m)
            if f"{r['Target']}|{m['ID']}" not in known:
                review.append(f"trivy: misconfig {r['Target']}: {m['ID']} {m['Title']}")
for tool in ("gitleaks", "trivy", "osv"):
    if meta.get(f"{tool}_rc") not in (0, 1, None) or not os.path.exists(os.path.join(rep, f"{tool}.json")):
        review.append(f"{tool} did not complete (rc={meta.get(f'{tool}_rc')}) — that check is MISSING, not clean")

verdict = "FAIL" if fail else ("REVIEW" if review else "OK")
L = [f"# Security scan — {verdict}", "",
     f"- Repo: `{meta.get('repo')}`  · origin `{meta.get('origin_url')}`",
     f"- Commit scanned: `{meta.get('head')}` on `{meta.get('branch')}`  (baseline: `{base.get('_commit')}`)",
     f"- Upstream `{meta.get('upstream_ref')}`: `{meta.get('upstream_head')}`  · fork-only commits: {len(meta.get('fork_only_commits', []))}",
     f"- Files scanned: {scan.get('file_count')}  · changed since last scan: {len(meta.get('changed_files', []))}",
     f"- Dependencies: osv advisories {advis}, malicious {len(mal)} · trivy HIGH/CRIT findings {len(hc)}",
     f"- gitleaks hits {len(gl)} (runtime files: {sum(1 for g in gl if not TESTISH.search(g['File'].replace('/repo/', '')))})",
     "", f"## FAIL ({len(fail)})"] + [f"- {x}" for x in fail] + \
    ["", f"## REVIEW — new since baseline ({len(review)})"] + [f"- {x}" for x in review] + \
    ["", "## Sensitive files changed since last scan (read these diffs)"] + \
    [f"- {x}" for x in meta.get("sensitive_changed", [])] + [""]
open(os.path.join(rep, "summary.md"), "w", encoding="utf-8").write("\n".join(L))
print("\n".join(L))
sys.exit(2 if fail else (1 if review else 0))
