#!/usr/bin/env bash
# repo-security-scan — full malware / hidden-code / tamper / secrets / dependency rescan of a git checkout.
# Run it after EVERY pull, BEFORE installing, building or opening the code in an editor.
#
#   bash scan.sh <repo_path>                          # scan; upstream auto-detected for GitHub forks
#   bash scan.sh <repo_path> --upstream <git_url>     # force the canonical repo to compare against
#   bash scan.sh --accept <report_dir>                # after a human/agent reviewed summary.md: new baseline
#
# Exit: 0 OK · 1 REVIEW (new items since the reviewed baseline) · 2 FAIL (do not install/build/run) · 3 scanner error
# Needs: git, python 3.8+, docker (gitleaks / trivy / osv-scanner run as pinned containers, repo mounted read-only).
# The scanned repo is never modified, and no code from it is executed.
set -uo pipefail
export PYTHONIOENCODING=utf-8
abspath() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }   # C:/… on Git Bash so native tools accept it
HERE="$(abspath "$(dirname "$0")")"
PY="python"; command -v python >/dev/null 2>&1 || PY="python3"
pyj() { "$PY" -I -c 'import json,sys;print(json.dumps(sys.argv[1]))' "$1"; }   # shell string -> JSON string
lines_json() { "$PY" -I -c 'import json,sys;print(json.dumps([l.rstrip("\n") for l in sys.stdin if l.strip()]))'; }

if [ "${1:-}" = "--accept" ]; then
  RD="${2:-}"; [ -f "$RD/files.json" ] || { echo "usage: scan.sh --accept <report_dir>"; exit 3; }
  "$PY" -I "$HERE/summarize.py" "$RD" "$(cat "$RD/baseline_path")" --write-baseline; exit $?
fi
[ -d "${1:-}/.git" ] || { echo "usage: scan.sh <repo_path> [--upstream <git_url>]"; exit 3; }
REPO="$(abspath "$1")"; shift
UPSTREAM_URL=""; [ "${1:-}" = "--upstream" ] && UPSTREAM_URL="${2:-}"
g() { git -C "$REPO" -c core.fsmonitor=false -c core.hooksPath=/dev/null "$@"; }

ORIGIN_URL="$(g remote get-url origin 2>/dev/null || echo "")"
SLUG="$(echo "$ORIGIN_URL" | sed -E 's#^.*github\.com[:/]##; s#\.git$##')"            # owner/repo (GitHub) or url
ID="$(printf '%s' "${SLUG:-$(basename "$REPO")}" | tr -c 'A-Za-z0-9._-' '_')"
STATE="$HERE/state/$ID"; mkdir -p "$STATE/reports"
BASELINE="$STATE/baseline.json"
HEAD_SHA="$(g rev-parse HEAD)"; BRANCH="$(g branch --show-current)"; BRANCH="${BRANCH:-HEAD}"
OUT="$STATE/reports/$(date +%Y%m%d-%H%M%S)_${HEAD_SHA:0:10}"; mkdir -p "$OUT"
echo "$BASELINE" >"$OUT/baseline_path"
echo "== $REPO @ $HEAD_SHA ($BRANCH)"; echo "== report: $OUT"

# 1. tamper ---------------------------------------------------------------------------------
# 1a. canonical upstream: given, else the GitHub fork parent
if [ -z "$UPSTREAM_URL" ] && echo "$ORIGIN_URL" | grep -q github.com; then
  UPSTREAM_URL="$("$PY" -I -c '
import json,sys,urllib.request
try:
    d=json.load(urllib.request.urlopen(urllib.request.Request("https://api.github.com/repos/"+sys.argv[1],headers={"User-Agent":"repo-security-scan"}),timeout=20))
    print((d.get("parent") or {}).get("clone_url",""))
except Exception: print("")' "$SLUG")"
fi
UP_REF=""; UP_HEAD=""; UP_ERR=""; FORK_ONLY="[]"
if [ -n "$UPSTREAM_URL" ]; then
  g fetch --quiet --no-tags "$UPSTREAM_URL" "+refs/heads/$BRANCH:refs/scan-upstream/$BRANCH" 2>"$OUT/upstream.err" \
    && UP_REF="refs/scan-upstream/$BRANCH" || UP_ERR="branch $BRANCH not fetched from $UPSTREAM_URL: $(tail -1 "$OUT/upstream.err")"
  if [ -n "$UP_REF" ]; then
    UP_HEAD="$(g rev-parse "$UP_REF")"
    FORK_ONLY="$(g log --format='%h %an: %s' "$UP_REF..HEAD" | lines_json)"
  fi
else
  UP_ERR="no upstream (not a fork, or GitHub API unreachable) — only origin consistency checked"
fi
# 1b. is every local commit actually on the remote?
g fetch --quiet --no-tags origin 2>/dev/null
NOT_ON_REMOTE="$(g log --format='%h %an: %s' HEAD --not --remotes 2>/dev/null | lines_json)"
# 1c. tracked files edited after checkout (tampering that no commit shows)
LOCAL_MOD="$(g status --porcelain --untracked-files=no | cut -c4- | lines_json)"
# 1d. object-store integrity
g fsck --no-dangling >"$OUT/fsck.txt" 2>&1; FSCK_RC=$?

# 2. what changed since the last reviewed commit ------------------------------------------------
LAST="$("$PY" -I -c 'import json,sys;print(json.load(open(sys.argv[1])).get("_commit",""))' "$BASELINE" 2>/dev/null || true)"
CHANGED="[]"; SENS="[]"
if [ -n "$LAST" ] && g cat-file -e "$LAST^{commit}" 2>/dev/null; then
  g diff --no-ext-diff --no-textconv --name-only "$LAST" HEAD >"$OUT/changed_files.txt"
  CHANGED="$(lines_json <"$OUT/changed_files.txt")"
  SENS="$(grep -E '(^|/)(package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|requirements[^/]*\.txt|pyproject\.toml|setup\.py|Cargo\.(toml|lock)|go\.(mod|sum)|build\.rs|Makefile|Dockerfile[^/]*|docker-compose[^/]*|\.npmrc|conftest\.py)$|^(scripts|bin|\.github/workflows|\.husky|\.githooks|\.devcontainer|\.vscode)/|\.(sh|ps1|bat|cmd)$' "$OUT/changed_files.txt" | lines_json)"
fi

# 3. full file scan ---------------------------------------------------------------------------
"$PY" -I "$HERE/scan_files.py" "$REPO" "$OUT/files.json" || { echo "scan_files.py failed"; exit 3; }

# 4. secrets · CVEs + Dockerfile misconfig · known-malicious packages (pinned, read-only mounts) --
export MSYS_NO_PATHCONV=1
if command -v docker >/dev/null 2>&1; then
  docker run --rm -v "$REPO:/repo:ro" -v "$OUT:/out" zricethezav/gitleaks:v8.21.2 \
    dir /repo --no-banner --redact -f json -r /out/gitleaks.json --exit-code 0 >"$OUT/gitleaks.log" 2>&1; GL_RC=$?
  docker run --rm -v "$REPO:/repo:ro" -v "$OUT:/out" -v repo-security-scan-trivycache:/root/.cache aquasec/trivy:0.58.1 \
    fs --timeout 30m --scanners vuln,misconfig --misconfig-scanners dockerfile --severity HIGH,CRITICAL \
    --skip-dirs /repo/.git --skip-dirs /repo/node_modules --skip-dirs /repo/vendor \
    -f json -o /out/trivy.json /repo >"$OUT/trivy.log" 2>&1; TV_RC=$?
  docker run --rm -v "$REPO:/repo:ro" ghcr.io/google/osv-scanner:v2.2.4 scan source -r /repo --format json \
    >"$OUT/osv.json" 2>"$OUT/osv.log"; OSV_RC=$?
else
  GL_RC=127; TV_RC=127; OSV_RC=127; echo "docker not found: secrets/CVE/malicious-package checks SKIPPED"
fi
unset MSYS_NO_PATHCONV

cat >"$OUT/meta.json" <<EOF
{"repo":$(pyj "$REPO"),"origin_url":$(pyj "$ORIGIN_URL"),"head":"$HEAD_SHA","branch":$(pyj "$BRANCH"),
 "upstream_ref":$(pyj "$UPSTREAM_URL $BRANCH"),"upstream_head":"$UP_HEAD","upstream_error":$(pyj "$UP_ERR"),
 "fork_only_commits":$FORK_ONLY,"head_not_on_remote":$NOT_ON_REMOTE,"local_modified":$LOCAL_MOD,
 "fsck_rc":$FSCK_RC,"changed_files":$CHANGED,"sensitive_changed":$SENS,
 "gitleaks_rc":$GL_RC,"trivy_rc":$TV_RC,"osv_rc":$OSV_RC}
EOF

# 5. verdict -----------------------------------------------------------------------------------
"$PY" -I "$HERE/summarize.py" "$OUT" "$BASELINE"; RC=$?
echo; echo "report: $OUT/summary.md   (exit $RC: 0 OK · 1 REVIEW · 2 FAIL · 3 error)"
[ -f "$BASELINE" ] || echo "first scan of this repo: review everything above, then: bash $HERE/scan.sh --accept $OUT"
exit $RC
