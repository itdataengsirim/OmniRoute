"""Full-tree file scan: invisible/bidi unicode, binaries/executables, stego (data after image EOF,
odd PNG chunks), active SVG content, long lines, encoded blobs, embedded WASM (import audit),
malicious code patterns, outbound hosts, install-time hooks, lockfile sources.

Usage: python -I scan_files.py <repo_root> <out_json>
Pure read-only. Never imports or executes anything from the scanned repo.
"""
import base64, collections, json, math, os, re, struct, subprocess, sys

root, out = sys.argv[1], sys.argv[2]
ls = subprocess.run(["git", "-C", root, "-c", "core.fsmonitor=false", "ls-files", "-z"],
                    capture_output=True, check=True).stdout.decode("utf-8", "replace")
files = [f for f in ls.split("\0") if f]

CODE_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".py", ".ps1", ".bat", ".cmd",
            ".rs", ".go", ".yml", ".yaml", ".toml", ".nix", ""}
TESTISH = re.compile(r"(^|/)(tests?|__tests__|fixtures|e2e)/|\.(test|spec)\.[a-z]+$")
DOCISH = re.compile(r"(^|/)docs/|\.mdx?$|(^|/)(i18n|locales|messages)/")

# Suspicious code points. FE0F (emoji presentation) and LRM/RLM in RTL text are normal;
# they are still recorded, the summary decides what is a finding.
SUSP = re.compile(
    "[‪-‮⁦-⁩‎‏؜"          # bidi
    "​-‍⁠-⁤﻿᠎­͏ᅟᅠㅤﾠ឴឵"  # zero-width
    "︀-️\U000e0100-\U000e01ef"                       # variation selectors
    "\U000e0000-\U000e007f"                                    # tag chars (ASCII smuggling)
    "-\U000f0000-\U0010ffff"                       # private use
    "\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")                    # control chars


def cp_type(cp):
    if cp in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069):
        return "BIDI_OVERRIDE"
    if cp in (0x200E, 0x200F, 0x061C):
        return "BIDI_MARK"
    if 0xE0000 <= cp <= 0xE007F:
        return "TAG"
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return "VARSEL_FE0F" if cp == 0xFE0F else "VARSEL_OTHER"
    if 0xE000 <= cp <= 0xF8FF or cp >= 0xF0000:
        return "PUA"
    if cp < 0x20 or 0x7F <= cp <= 0x9F:
        return "CTRL"
    return "ZEROWIDTH"


SIG = [(b"\x89PNG", "png"), (b"\xff\xd8\xff", "jpg"), (b"GIF8", "gif"), (b"MZ", "PE-EXE"),
       (b"\x7fELF", "ELF"), (b"\xcf\xfa\xed\xfe", "MACHO"), (b"\xca\xfe\xba\xbe", "MACHO/CLASS"),
       (b"PK\x03\x04", "zip"), (b"\x1f\x8b", "gzip"), (b"%PDF", "pdf"), (b"\x00asm", "WASM"),
       (b"wOF2", "woff2"), (b"wOFF", "woff"), (b"\x00\x00\x01\x00", "ico"), (b"icns", "icns"),
       (b"RIFF", "riff")]
EXEC_KINDS = {"PE-EXE", "ELF", "MACHO", "MACHO/CLASS", "WASM", "zip", "gzip"}
PNG_STD = {b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP",
           b"pHYs", b"bKGD", b"sBIT", b"tIME", b"eXIf", b"acTL", b"fcTL", b"fdAT", b"tEXt",
           b"zTXt", b"iTXt"}

B64 = re.compile(rb"[A-Za-z0-9+/=]{400,}")
HEXESC = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){40,}")
WASM_B64 = re.compile(rb"AGFzbQ[A-Za-z0-9+/=]{100,}")
URLHOST = re.compile(r"https?://([a-zA-Z0-9.-]+\.[a-z]{2,})")
PATTERNS = {
    "eval": re.compile(r"\beval\s*\("),
    "new_function": re.compile(r"new\s+Function\s*\("),
    "vm_exec": re.compile(r"vm\.(runIn\w+|Script)\b"),
    "decode_then_exec": re.compile(r"(eval|Function)\s*\(\s*(atob|Buffer\.from)"),
    "charcode_blob": re.compile(r"fromCharCode\([^)]{80,}"),
    "obfuscator": re.compile(r"_0x[0-9a-f]{4,6}\b"),
    "miner": re.compile(r"stratum\+tcp|xmrig|coinhive|cryptonight", re.I),
    # interactive shell wired to a socket; plain `/dev/tcp/host/port` port probes are NOT matched
    "reverse_shell": re.compile(r"(ba|z)?sh\s+-i\s*[>&]+\s*/dev/tcp/|/dev/tcp/\S+\s+0>&1|\bnc(at)?\s+(-\w*\s+)*-[ec]\s+/bin/|mkfifo[^\n]{0,80}\bnc\s"),
    # browser/wallet/ssh credential stores referenced as paths (case-sensitive: "local state" in prose is not it)
    "stealer_target": re.compile(r"Login Data[\"'/\\]|[\"'/\\]Local State[\"']|wallet\.dat|\.ssh[/\\]id_(rsa|ed25519|ecdsa)\b|Cookies\.binarycookies|login\.keychain|Exodus[/\\]exodus\.wallet|Local Extension Settings[/\\]nkbihfbeogaeaoehlefnkodbefgpgknn"),
    "exfil_endpoint": re.compile(r"discord(app)?\.com/api/webhooks|pastebin\.com/raw|ngrok(-free)?\.(io|app)|transfer\.sh|webhook\.site|requestbin|pipedream\.net|interact\.sh|\boast\.(pro|live|site|online|fun|me)\b|burpcollaborator\.net", re.I),
    "env_dump": re.compile(r"JSON\.stringify\(\s*process\.env\s*\)|Object\.(entries|keys)\(\s*process\.env\s*\)"),
    "pipe_to_shell": re.compile(r"(curl|wget)[^\n|]{0,200}\|\s*(ba|z)?sh\b"),
    "powershell_dl": re.compile(r"IEX\s*\(|Invoke-Expression|DownloadString\(", re.I),
    # Python
    "py_exec_decoded": re.compile(r"exec\s*\(\s*(base64|zlib|marshal|codecs|bytes\.fromhex|__import__)"),
    "py_marshal_pickle_load": re.compile(r"\b(marshal|pickle)\.loads\s*\("),
    "py_import_os_system": re.compile(r"__import__\(\s*['\"](os|subprocess)['\"]\s*\)\.(system|popen|Popen|call)"),
}


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def leb(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7F) << s; s += 7
        if x < 0x80:
            return r, i


def wasm_imports(w):
    imps, exps, i = [], [], 8
    while i < len(w):
        sid = w[i]; i += 1
        size, i = leb(w, i); end = i + size
        if sid == 2:
            n, j = leb(w, i)
            for _ in range(n):
                l, j = leb(w, j); mod = w[j:j + l].decode(errors="replace"); j += l
                l, j = leb(w, j); name = w[j:j + l].decode(errors="replace"); j += l
                kind = w[j]; j += 1
                if kind == 0:
                    _, j = leb(w, j)
                elif kind in (1, 2):
                    if kind == 1:
                        j += 1
                    fl = w[j]; j += 1; _, j = leb(w, j)
                    if fl & 1:
                        _, j = leb(w, j)
                elif kind == 3:
                    j += 2
                imps.append(f"{mod}::{re.sub(r'_[0-9a-f]{16}$', '', name)}")
        elif sid == 7:
            n, j = leb(w, i)
            for _ in range(n):
                l, j = leb(w, j); exps.append(w[j:j + l].decode(errors="replace")); j += l
                j += 1; _, j = leb(w, j)
        i = end
    return imps, exps


res = {k: [] for k in ("unicode", "binaries", "exec_like", "stego", "svg_active", "long_lines",
                       "blobs", "wasm", "patterns", "hosts", "non_utf8")}
hosts = collections.Counter()

for f in files:
    p = os.path.join(root, f)
    try:
        data = open(p, "rb").read()
    except OSError:
        continue
    ext = os.path.splitext(f)[1].lower()
    kind = next((k for s, k in SIG if data.startswith(s)), None)
    if b"\0" in data[:8192] or (kind and kind not in ("ico",) or (kind == "ico" and b"\0" in data[:64])):
        res["binaries"].append({"f": f, "kind": kind, "size": len(data), "ent": round(entropy(data[:200000]), 2)})
        if kind in EXEC_KINDS:
            res["exec_like"].append({"f": f, "kind": kind, "size": len(data)})
        if kind == "png":
            i, odd, txt = 8, set(), 0
            while i + 8 <= len(data):
                n, = struct.unpack(">I", data[i:i + 4]); t = data[i + 4:i + 8]
                if t not in PNG_STD:
                    odd.add(t.decode("latin1"))
                if t in (b"tEXt", b"zTXt", b"iTXt"):
                    txt += n
                i += 12 + n
                if t == b"IEND":
                    break
            trailing = len(data) - i
            if trailing > 0 or odd or txt > 512:
                res["stego"].append({"f": f, "kind": "png", "trailing": trailing, "odd_chunks": sorted(odd), "text_bytes": txt})
        elif kind == "jpg":
            j = data.rfind(b"\xff\xd9")
            if j != -1 and len(data) - (j + 2) > 16:
                res["stego"].append({"f": f, "kind": "jpg", "trailing": len(data) - (j + 2)})
        elif kind == "gif" and not data.rstrip(b"\0").endswith(b";"):
            res["stego"].append({"f": f, "kind": "gif", "trailing": "no-terminator"})
        if kind in ("png", "jpg", "gif", "ico") and re.search(rb"<script|eval\(|#!/|powershell", data, re.I):
            res["stego"].append({"f": f, "kind": kind, "trailing": "script-marker-inside-image"})
        continue
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        res["non_utf8"].append({"f": f, "size": len(data), "ent": round(entropy(data), 2)})
        continue

    # unicode
    hits = collections.Counter(); first = {}
    for m in SUSP.finditer(text):
        cp = ord(m.group())
        if cp == 0xFEFF and m.start() == 0:
            continue  # leading BOM
        key = (cp_type(cp), f"U+{cp:04X}")
        hits[key] += 1
        if key not in first:
            ln = text.count("\n", 0, m.start()) + 1
            first[key] = ln
    for (t, cp), n in hits.items():
        res["unicode"].append({"f": f, "type": t, "cp": cp, "count": n, "line": first[(t, cp)]})

    if ext == ".svg":
        act = sorted(set(m.group().lower() for m in re.finditer(
            r"<script|\son[a-z]+\s*=|javascript:|<iframe|<embed|<object|xlink:href=\"https?:", text, re.I)))
        if act:
            res["svg_active"].append({"f": f, "markers": act})

    is_code = ext in CODE_EXT and not DOCISH.search(f)
    if is_code:
        for ln, line in enumerate(text.splitlines(), 1):
            if len(line) > 3000:
                res["long_lines"].append({"f": f, "line": ln, "len": len(line)})
                break
        for name, rx in PATTERNS.items():
            for m in rx.finditer(text):
                ln = text.count("\n", 0, m.start()) + 1
                res["patterns"].append({"f": f, "pattern": name, "line": ln,
                                        "test": bool(TESTISH.search(f)),
                                        "snippet": text[m.start():m.start() + 90].split("\n")[0]})
        if not TESTISH.search(f):
            for h in URLHOST.findall(text):
                parts = h.lower().split(".")
                hosts[".".join(parts[-2:])] += 1

    for m in B64.finditer(data):
        res["blobs"].append({"f": f, "off": m.start(), "len": len(m.group()), "head": m.group()[:16].decode()})
        break
    for m in HEXESC.finditer(data):
        res["blobs"].append({"f": f, "off": m.start(), "len": len(m.group()), "head": "hex-escape"})
        break
    for m in WASM_B64.finditer(data):
        try:
            w = base64.b64decode(m.group() + b"=" * (-len(m.group()) % 4))
            imps, exps = wasm_imports(w)
            strs = sorted(set(s.decode() for s in re.findall(rb"[\x20-\x7e]{6,}", w)
                              if re.search(rb"https?://|wss?://|\.(com|net|org|io|ru|cn)\b|eval|exec|child_process|require|fetch|XMLHttp|WebSocket", s, re.I)
                              and not re.search(rb"[/\\]\.cargo[/\\]registry[/\\]|[/\\]rustc[/\\][0-9a-f]{40}[/\\]|library[/\\](core|std|alloc)[/\\]src", s)))
            import hashlib
            res["wasm"].append({"f": f, "bytes": len(w), "sha256": hashlib.sha256(w).hexdigest(),
                                "imports": sorted(set(imps)), "exports": exps, "suspicious_strings": strs})
        except Exception as e:  # noqa: BLE001 — record, never crash the scan
            res["wasm"].append({"f": f, "error": str(e)})

res["hosts"] = dict(hosts)

# install-time hooks in every package.json + lockfile sources
hooks = []
for f in files:
    if f.endswith("package.json") and "node_modules" not in f:
        try:
            pj = json.load(open(os.path.join(root, f), encoding="utf-8"))
        except Exception:
            continue
        for k, v in (pj.get("scripts") or {}).items():
            if k in ("preinstall", "install", "postinstall", "prepare", "prepublish",
                     "prepublishOnly", "preuninstall", "postuninstall", "prepack", "postpack"):
                hooks.append({"f": f, "hook": k, "cmd": v})

# Other places where a repo executes code on install / open / build / commit, any ecosystem.
AUTORUN = [
    (re.compile(r"(^|/)setup\.py$"), "python setup.py runs at install"),
    (re.compile(r"(^|/)build\.rs$"), "Rust build script runs at cargo build"),
    (re.compile(r"(^|/)binding\.gyp$"), "node-gyp native build"),
    (re.compile(r"(^|/)conftest\.py$"), "pytest auto-imports conftest.py"),
    (re.compile(r"(^|/)(\.husky|\.githooks|\.git-hooks)/[^/_][^/]*$"), "git hook (runs on commit/push if installed)"),
    (re.compile(r"^\.github/workflows/"), "CI workflow (runs on GitHub, can use repo secrets)"),
    (re.compile(r"(^|/)\.devcontainer/"), "devcontainer (postCreate/postStart commands)"),
    (re.compile(r"(^|/)\.vscode/tasks\.json$"), "VS Code tasks"),
    (re.compile(r"(^|/)\.envrc$"), "direnv runs on cd"),
    (re.compile(r"(^|/)\.npmrc$|(^|/)\.yarnrc(\.yml)?$|(^|/)pip\.conf$|(^|/)\.pypirc$"), "package-manager config (registry/scripts override)"),
]
autorun = []
for f in files:
    for rx, why in AUTORUN:
        if rx.search(f):
            entry = {"f": f, "why": why, "flags": []}
            try:
                t = open(os.path.join(root, f), encoding="utf-8", errors="replace").read()
            except OSError:
                t = ""
            if f.endswith("tasks.json") and re.search(r'"runOn"\s*:\s*"folderOpen"', t):
                entry["flags"].append("AUTO-RUNS WHEN FOLDER IS OPENED")
            if ".devcontainer/" in f and re.search(r"post(Create|Start|Attach)Command|initializeCommand", t):
                entry["flags"].append("runs commands on container create/start")
            if f.startswith(".github/workflows/") and "pull_request_target" in t:
                entry["flags"].append("pull_request_target (runs untrusted PR code with secrets if checkout of head)")
            if re.search(r"(curl|wget)[^\n|]{0,200}\|\s*(ba|z)?sh\b", t):
                entry["flags"].append("download-and-execute")
            if re.search(r"^\s*registry\s*=|index-url|extra-index-url", t, re.M):
                entry["flags"].append("custom package registry")
            autorun.append(entry)
            break
for f in files:  # Dockerfiles: download-and-execute or ADD from URL
    if re.search(r"(^|/)(Dockerfile[^/]*|[^/]*\.Dockerfile|Containerfile)$", f):
        t = open(os.path.join(root, f), encoding="utf-8", errors="replace").read()
        fl = []
        if re.search(r"(curl|wget)[^\n|]{0,200}\|\s*(ba|z)?sh\b", t):
            fl.append("download-and-execute in RUN")
        if re.search(r"^\s*ADD\s+https?://", t, re.M | re.I):
            fl.append("ADD from remote URL")
        autorun.append({"f": f, "why": "Dockerfile", "flags": fl})
res["lifecycle"] = hooks + [{"f": a["f"], "hook": a["why"], "cmd": "; ".join(a["flags"])} for a in autorun]
res["autorun_flags"] = [a for a in autorun if a["flags"]]

ALLOWED_REG = tuple(os.environ.get(
    "SCAN_ALLOWED_REGISTRIES", "https://registry.npmjs.org/,https://registry.yarnpkg.com/").split(","))
lock = []
for f in files:
    if f.endswith("package-lock.json"):
        try:
            lj = json.load(open(os.path.join(root, f), encoding="utf-8"))
        except Exception:
            continue
        for name, meta in (lj.get("packages") or {}).items():
            if not name:
                continue
            r = meta.get("resolved")
            if meta.get("link"):
                continue
            if r and not r.startswith(ALLOWED_REG):
                lock.append({"f": f, "pkg": name, "resolved": r, "issue": "non-allowed-source"})
            elif r and not meta.get("integrity"):
                lock.append({"f": f, "pkg": name, "resolved": r, "issue": "missing-integrity"})
    elif re.search(r"(^|/)(yarn\.lock|pnpm-lock\.yaml|bun\.lock)$", f):
        t = open(os.path.join(root, f), encoding="utf-8", errors="replace").read()
        for u in sorted(set(re.findall(r"(?:resolved|tarball)[\"']?:?\s*[\"']?(https?://[^\"'\s#]+|git\+[^\"'\s]+|github:[^\"'\s]+)", t))):
            if not u.startswith(ALLOWED_REG):
                lock.append({"f": f, "pkg": "?", "resolved": u, "issue": "non-allowed-source"})
    elif re.search(r"(^|/)requirements[^/]*\.txt$|(^|/)Pipfile$|(^|/)pyproject\.toml$", f):
        t = open(os.path.join(root, f), encoding="utf-8", errors="replace").read()
        for u in sorted(set(re.findall(r"(?:git\+https?://\S+|https?://\S+\.(?:whl|tar\.gz|zip)\b|--(?:extra-)?index-url\s+\S+)", t))):
            lock.append({"f": f, "pkg": "?", "resolved": u, "issue": "direct-url-or-custom-index"})
res["lockfile"] = lock
res["file_count"] = len(files)
res["tracked"] = files

json.dump(res, open(out, "w", encoding="utf-8"), indent=1)
print(json.dumps({k: (len(v) if isinstance(v, (list, dict)) else v) for k, v in res.items()}))
