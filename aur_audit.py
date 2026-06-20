#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aur_audit.py — Security auditor for AUR packages (Arch / CachyOS / EndeavourOS / Manjaro)

Context: after the AUR malware campaign (Jun 2026) where nearly 2,000 packages
were compromised by abusing orphan adoptions and malicious instructions in
PKGBUILD / .install scripts, this tool automates what Arch recommends doing
by hand: reviewing the PKGBUILD, install scripts, history, maintainer and popularity.

It combines three signals:
  1. Static heuristics (regexes over PKGBUILD / .install / .SRCINFO).
  2. AUR RPC metadata (orphan status, popularity, dates, out-of-date, existence).
  3. Optional verdict from a Claude model via the Anthropic API.

No external dependencies (stdlib only). Designed not to break if the network or API is unavailable.

Usage:
  ./aur_audit.py audit                 # audit EVERYTHING installed from AUR
  ./aur_audit.py audit --ai always     # force an AI verdict on every package
  ./aur_audit.py check yay paru-bin    # audit specific packages (pre-installation)
  ./aur_audit.py audit --json out.json # export the report as JSON
  ./aur_audit.py audit --no-ai         # heuristics + metadata only (offline-friendly)

AI engines (AUR_AUDIT_ENGINE):
  api | anthropic      (default) Anthropic API — uses ANTHROPIC_API_KEY
  openai | compatible  any OpenAI-compatible endpoint (OpenAI, OpenRouter,
                       Groq, Together, Ollama, llama.cpp…) — uses AUR_AUDIT_API_KEY
                       and AUR_AUDIT_API_URL; set the model with --model / AUR_AUDIT_MODEL
  claude-code | cc     uses your local Claude Code session (claude -p), no token needed
  cli | gemini | codex any local AI CLI — set AUR_AUDIT_CLI_CMD (gemini/codex have
                       sensible defaults). Use {prompt} as placeholder, else stdin.

Environment variables:
  AUR_AUDIT_ENGINE      AI engine (see above; default: api)
  ANTHROPIC_API_KEY     Anthropic token (api engine)
  AUR_AUDIT_API_KEY     token for the openai/compatible engine
  AUR_AUDIT_API_URL     openai/compatible endpoint (default: api.openai.com)
  AUR_AUDIT_CLI_CMD     command for the cli engine, e.g. 'gemini -p {prompt}'
  AUR_AUDIT_MODEL       model (default: claude-sonnet-4-6; change it to match the engine)
  AUR_AUDIT_DENYLIST    path or URL to a list (one per line) of affected packages
"""

import argparse
import concurrent.futures
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.parse
import urllib.request

# Auto-refresh the affected list if the cache is older than this (seconds). 0 disables.
AFFECTED_TTL = int(os.environ.get("AUR_AUDIT_LIST_TTL", str(6 * 3600)))

# Provisional official list of affected packages (Jun 2026 campaign). HedgeDoc.
# The /download suffix returns the raw markdown; if it fails, the /s/ page is used.
AFFECTED_NOTE = os.environ.get("AUR_AFFECTED_URL", "https://md.archlinux.org/s/SxbqukK6IA")
CACHE_DIR = os.path.expanduser("~/.cache/aur-audit")
CACHE_AFFECTED = os.path.join(CACHE_DIR, "affected.txt")
# Valid AUR package name: starts with alphanumeric; allows . _ + - @
PKGNAME_RE = re.compile(r"^[a-z0-9][a-z0-9@._+-]{1,99}$")

AUR_RPC = "https://aur.archlinux.org/rpc/v5/info"
AUR_PLAIN = "https://aur.archlinux.org/cgit/aur.git/plain/{file}?h={base}"
DEFAULT_MODEL = os.environ.get("AUR_AUDIT_MODEL", "claude-sonnet-4-6")
ANTHROPIC_API = "https://api.anthropic.com/v1/messages"
UA = "aur-audit/1.0 (+defensive security)"

# ----------------------------------------------------------------------------
# Terminal colors
# ----------------------------------------------------------------------------
class C:
    enabled = sys.stdout.isatty()

    @classmethod
    def _w(cls, code, s):
        return f"\033[{code}m{s}\033[0m" if cls.enabled else s

    red = classmethod(lambda c, s: c._w("31;1", s))
    yel = classmethod(lambda c, s: c._w("33;1", s))
    grn = classmethod(lambda c, s: c._w("32;1", s))
    blu = classmethod(lambda c, s: c._w("34;1", s))
    dim = classmethod(lambda c, s: c._w("2", s))
    bold = classmethod(lambda c, s: c._w("1", s))


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_COLOR = {
    "info": C.dim, "low": C.grn, "medium": C.yel,
    "high": C.red, "critical": C.red,
}

# ----------------------------------------------------------------------------
# Static heuristics: (regex, severity, explanation)
# Typical abuse patterns seen in malware campaigns against PKGBUILD/.install
# ----------------------------------------------------------------------------
PATTERNS = [
    (r"curl[^\n|]*\|\s*(?:ba)?sh", "critical",
     "Remote download piped directly into the shell (curl|sh)."),
    (r"wget[^\n|]*\|\s*(?:ba)?sh", "critical",
     "Remote download piped directly into the shell (wget|sh)."),
    (r"\bbase64\b[^\n]*(?:-d|--decode)", "high",
     "base64 decoding (possible obfuscated payload)."),
    (r"\beval\b", "high",
     "Use of eval (dynamic string execution, common for obfuscation)."),
    (r"(?:\\x[0-9a-fA-F]{2}){6,}", "high",
     "Long string with hex escapes (\\xNN) — possible shellcode/obfuscation."),
    (r"https?://(?:pastebin\.com|paste\.ee|0x0\.st|transfer\.sh|ix\.io|termbin)", "high",
     "Source on an ephemeral paste/upload service (not a legitimate upstream)."),
    (r"https?://(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy)", "high",
     "Shortened URL — hides the real download destination."),
    (r"https?://\d{1,3}(?:\.\d{1,3}){3}", "high",
     "Download from a literal IP instead of a domain."),
    (r"\b(?:nc|ncat|netcat)\b\s+[^\n]*-[^\n]*e", "critical",
     "netcat with -e: classic reverse shell pattern."),
    (r"/dev/tcp/", "critical",
     "Use of /dev/tcp — raw network connection from the shell (reverse shell)."),
    (r"\bsudo\b", "medium",
     "Use of sudo inside the PKGBUILD (it should not escalate privileges while building)."),
    (r"(?:crontab|systemctl\s+enable|/etc/cron|\.config/autostart|/etc/systemd/system)", "high",
     "Attempts to establish persistence (cron / autostart / systemd unit)."),
    (r"(?:~|\$HOME)/\.(?:bashrc|zshrc|profile|bash_profile)", "high",
     "Modifies the user's shell startup files (persistence)."),
    (r"\bchattr\b", "medium",
     "chattr: sometimes used to make an implant immutable."),
    (r"(?:gpg|openssl)[^\n]*(?:dec|--decrypt|aes)", "medium",
     "Inline decryption — may hide an encrypted payload."),
    (r"\b(?:wget|curl)\b(?![^\n]*\$\{?(?:url|pkgver|_pkgname|source))", "low",
     "Download with curl/wget in the script (review the destination manually)."),
    (r"python[0-9.]*\s+-c\s+[\"']", "medium",
     "Inline Python execution (-c) — review the contents."),
    (r"\bxxd\b\s+-r", "high",
     "xxd -r: rebuilding a binary from hex (obfuscation)."),
]
COMPILED = [(re.compile(p, re.IGNORECASE), sev, desc) for p, sev, desc in PATTERNS]


def run(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return out.stdout
    except FileNotFoundError:
        return ""


def fetch_url(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def _pacman_query(flag):
    out = run(["pacman", flag])
    pkgs = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            pkgs.append((parts[0], parts[1]))
    return pkgs


def foreign_packages():
    """Installed packages that do not come from the official repos (= AUR/manual)."""
    return _pacman_query("-Qm")


def all_installed_packages():
    """Every installed package (official repos + AUR/manual)."""
    return _pacman_query("-Q")


def rpc_info(names):
    """Query the AUR RPC in batches. Returns (info, ok) where ok=False if any
    request failed at the network level (so as not to confuse 'package missing' with 'RPC down')."""
    info = {}
    ok = True
    if not names:
        return info, ok
    for i in range(0, len(names), 50):
        chunk = names[i:i + 50]
        qs = "&".join("arg[]=" + urllib.parse.quote(n) for n in chunk)
        try:
            data = json.loads(fetch_url(f"{AUR_RPC}?{qs}"))
            for r in data.get("results", []):
                info[r["Name"].lower()] = r
        except Exception as e:
            ok = False
            sys.stderr.write(C.yel(f"[rpc] warning: {e}\n"))
    return info, ok


def find_local_pkgbuild(pkgbase, pkgname):
    """Looks for the PKGBUILD actually used at build time (yay/paru cache)."""
    home = os.path.expanduser("~")
    for base in (pkgbase, pkgname):
        for cache in (f"{home}/.cache/yay/{base}", f"{home}/.cache/paru/clone/{base}"):
            path = os.path.join(cache, "PKGBUILD")
            if os.path.isfile(path):
                try:
                    with open(path, encoding="utf-8", errors="replace") as f:
                        return f.read(), cache, "local cache"
                except Exception:
                    pass
    return None, None, None


def fetch_aux(pkgbase, filename):
    try:
        return fetch_url(AUR_PLAIN.format(file=urllib.parse.quote(filename), base=urllib.parse.quote(pkgbase)))
    except Exception:
        return ""


def extract_install_files(pkgbuild_text):
    files = set()
    for m in re.finditer(r"^\s*install\s*=\s*['\"]?([^\s'\"]+)", pkgbuild_text, re.MULTILINE):
        files.add(m.group(1).replace("$pkgname", "").strip("/") or m.group(1))
    # .install names referenced in source=()
    for m in re.finditer(r"([A-Za-z0-9._-]+\.install)", pkgbuild_text):
        files.add(m.group(1))
    return [f for f in files if f]


def heuristic_scan(text, kind):
    findings = []
    if not text:
        return findings
    # Cap input size: PKGBUILD/.install are tiny; a huge file would only be an attempt
    # to slow the regex scan. 1 MiB is far beyond any legitimate packaging script.
    text = text[:1_048_576]
    for rx, sev, desc in COMPILED:
        m = rx.search(text)
        if m:
            snippet = m.group(0)[:120].replace("\n", " ")
            findings.append({"severity": sev, "source": kind,
                             "desc": desc, "match": snippet})
    return findings


def metadata_risk(name, meta, installed_version, rpc_ok=True, is_foreign=True):
    findings = []
    if meta is None:
        if rpc_ok and not is_foreign:
            # Official-repo package: not being in AUR is expected, not a finding.
            return findings
        if rpc_ok:
            findings.append({"severity": "high", "source": "aur",
                             "desc": "The package NO longer exists in AUR (removed during cleanup, renamed, or deleted?). Investigate what ran when it was installed.",
                             "match": name})
        else:
            findings.append({"severity": "low", "source": "aur",
                             "desc": "Could not be verified in AUR (RPC unreachable); not blocking on this.",
                             "match": name})
        return findings
    if not meta.get("Maintainer"):
        findings.append({"severity": "medium", "source": "aur",
                         "desc": "ORPHANED package (no maintainer). Entry vector abused in the campaign.",
                         "match": "Maintainer=null"})
    pop = float(meta.get("Popularity", 0) or 0)
    votes = int(meta.get("NumVotes", 0) or 0)
    if pop < 0.5 and votes < 5:
        findings.append({"severity": "low", "source": "aur",
                         "desc": f"Very low popularity (pop={pop:.3f}, votes={votes}). Few eyes on it.",
                         "match": "popularity"})
    if meta.get("OutOfDate"):
        findings.append({"severity": "low", "source": "aur",
                         "desc": "Marked as out-of-date.", "match": "OutOfDate"})
    fs = meta.get("FirstSubmitted", 0)
    lm = meta.get("LastModified", 0)
    if fs and lm and (lm - fs) < 7 * 86400:
        findings.append({"severity": "medium", "source": "aur",
                         "desc": "Submitted and modified within less than 7 days (recent adoption/submission, attack pattern).",
                         "match": "dates"})
    return findings


def parse_affected(text):
    """Extracts package names from a dump (HedgeDoc markdown, plain text…).
    Filters out front-matter, ``` fences, headings and any line that does not look
    like a valid AUR package name."""
    names = set()
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith(("#", "```", "meta-", "title:", "base:", "---")):
            continue
        if PKGNAME_RE.match(line):
            names.add(line)
    return names


def fetch_affected_list(url=AFFECTED_NOTE):
    """Downloads the official list. Tries the raw markdown (/download) and falls back to the page."""
    for candidate in (url.rstrip("/") + "/download", url):
        try:
            return parse_affected(fetch_url(candidate, timeout=30))
        except Exception as e:
            sys.stderr.write(C.dim(f"[list] {candidate}: {e}\n"))
    return set()


def update_affected_cache():
    names = fetch_affected_list()
    if not names:
        sys.stderr.write(C.red("[list] could not obtain any name. Network? URL?\n"))
        return 1
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(CACHE_AFFECTED, "w", encoding="utf-8") as f:
        f.write("# Provisional list of affected packages (AUR Jun 2026)\n")
        f.write(f"# Source: {AFFECTED_NOTE} — provisional, refresh it frequently\n")
        for n in sorted(names):
            f.write(n + "\n")
    print(C.grn(f"[list] {len(names)} affected packages saved to {CACHE_AFFECTED}"))
    return 0


def maybe_refresh_affected(ttl=AFFECTED_TTL):
    """Best-effort auto-update of the affected list from AFFECTED_NOTE when the cache
    is missing or older than ttl. Never fatal: keeps the old cache if the fetch fails."""
    if ttl <= 0:
        return
    try:
        fresh = os.path.isfile(CACHE_AFFECTED) and (time.time() - os.path.getmtime(CACHE_AFFECTED)) < ttl
    except OSError:
        fresh = False
    if fresh:
        return
    sys.stderr.write(C.dim("[list] refreshing the affected-packages list…\n"))
    update_affected_cache()


def load_denylist():
    """Merges: (1) AUR_AUDIT_DENYLIST if defined; (2) the local affected-packages cache."""
    maybe_refresh_affected()
    names = set()
    src = os.environ.get("AUR_AUDIT_DENYLIST")
    if src:
        try:
            text = fetch_url(src) if src.startswith("http") else open(src, encoding="utf-8").read()
            names |= parse_affected(text)
        except Exception as e:
            sys.stderr.write(C.yel(f"[denylist] could not load {src}: {e}\n"))
    if os.path.isfile(CACHE_AFFECTED):
        try:
            names |= parse_affected(open(CACHE_AFFECTED, encoding="utf-8").read())
        except Exception:
            pass
    return names


def _parse_verdict_json(text):
    text = re.sub(r"^```(?:json)?|```$", "", text.strip()).strip()
    # The model may wrap the JSON in prose or add a trailing explanation; parse just
    # the first balanced JSON object and ignore anything after it.
    start = text.find("{")
    if start != -1:
        obj, _ = json.JSONDecoder().raw_decode(text[start:])
        return obj
    return json.loads(text)


def _verdict_via_api(prompt, model, name):
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    body = json.dumps({
        "model": model, "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(ANTHROPIC_API, data=body, headers={
        "content-type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
        "User-Agent": UA,
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read().decode())
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        return _parse_verdict_json(text)
    except Exception as e:
        sys.stderr.write(C.yel(f"[ai/api] {name}: {e}\n"))
        return None


def _verdict_via_openai(prompt, model, name):
    """Generic OpenAI-compatible engine: works for OpenAI, OpenRouter, Groq,
    Together, Ollama, llama.cpp… any endpoint with the OpenAI chat API.
    Token in AUR_AUDIT_API_KEY; endpoint in AUR_AUDIT_API_URL; model in --model
    or AUR_AUDIT_MODEL."""
    key = os.environ.get("AUR_AUDIT_API_KEY")
    url = os.environ.get("AUR_AUDIT_API_URL", "https://api.openai.com/v1/chat/completions")
    if not key:
        return None
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(url, data=body, headers={
        "content-type": "application/json",
        "authorization": "Bearer " + key,
        "User-Agent": UA,
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = json.loads(r.read().decode())
        text = data["choices"][0]["message"]["content"]
        return _parse_verdict_json(text)
    except Exception as e:
        sys.stderr.write(C.yel(f"[ai/openai] {name}: {e}\n"))
        return None


def _verdict_via_claude_code(prompt, name):
    """Uses Claude Code in headless mode (claude -p). Leverages your existing
    session/subscription instead of the HTTP API. No tools: it's a pure reasoning call."""
    cli = os.environ.get("AUR_AUDIT_CLAUDE_BIN", "claude")
    cmd = [cli, "-p", prompt, "--output-format", "json", "--allowedTools", ""]
    # Use the Claude Code subscription, not a pay-as-you-go API key: if ANTHROPIC_API_KEY
    # is exported (often with no API credit), 'claude -p' would bill it and fail with
    # "Credit balance is too low". Strip it so the local session/subscription is used.
    child_env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=child_env)
        # The real reason (e.g. "Credit balance is too low") usually lives in the
        # JSON 'result' on stdout, not stderr — surface it either way.
        env = {}
        try:
            env = json.loads(out.stdout)            # Claude Code wrapper
        except Exception:
            pass
        if out.returncode != 0 or env.get("is_error"):
            reason = (env.get("result") or out.stderr or out.stdout).strip()[:200]
            sys.stderr.write(C.yel(f"[ai/claude-code] {name}: {reason or 'failed'}\n"))
            return None
        return _parse_verdict_json(env.get("result", ""))
    except FileNotFoundError:
        sys.stderr.write(C.yel("[ai/claude-code] cannot find the 'claude' binary in PATH.\n"))
        return None
    except Exception as e:
        sys.stderr.write(C.yel(f"[ai/claude-code] {name}: {e}\n"))
        return None


# Sensible default commands for known CLIs; AUR_AUDIT_CLI_CMD overrides any of them.
_CLI_DEFAULTS = {
    "gemini": "gemini -p {prompt}",
    "codex": "codex exec {prompt}",
}


def _verdict_via_cli(prompt, name, engine):
    """Generic CLI engine: shell out to ANY local AI command (gemini, codex, ollama…)
    and read the JSON verdict from its stdout. Configure with AUR_AUDIT_CLI_CMD; use
    {prompt} as the prompt placeholder, otherwise the prompt is piped via stdin.
    Examples:
        AUR_AUDIT_CLI_CMD='gemini -p {prompt}'
        AUR_AUDIT_CLI_CMD='codex exec {prompt}'
        AUR_AUDIT_CLI_CMD='ollama run llama3'        # (prompt via stdin)
    """
    template = os.environ.get("AUR_AUDIT_CLI_CMD") or _CLI_DEFAULTS.get(engine)
    if not template:
        sys.stderr.write(C.yel("[ai/cli] set AUR_AUDIT_CLI_CMD to your CLI command "
                               "(use {prompt} as placeholder, or the prompt is piped via stdin).\n"))
        return None
    try:
        argv = shlex.split(template)
    except ValueError as e:
        sys.stderr.write(C.yel(f"[ai/cli] bad AUR_AUDIT_CLI_CMD: {e}\n"))
        return None
    if "{prompt}" in template:
        argv = [a.replace("{prompt}", prompt) for a in argv]
        stdin_data = None
    else:
        stdin_data = prompt
    try:
        out = subprocess.run(argv, input=stdin_data, capture_output=True, text=True, timeout=180)
        if out.returncode != 0:
            sys.stderr.write(C.yel(f"[ai/cli] {name}: exit {out.returncode}: "
                                   f"{(out.stderr or out.stdout).strip()[:200]}\n"))
            return None
        return _parse_verdict_json(out.stdout)
    except FileNotFoundError:
        sys.stderr.write(C.yel(f"[ai/cli] command not found: {argv[0] if argv else '?'}\n"))
        return None
    except Exception as e:
        sys.stderr.write(C.yel(f"[ai/cli] {name}: {e}\n"))
        return None


def ai_verdict(name, meta, pkgbuild, aux_files, heuristics, model):
    engine = os.environ.get("AUR_AUDIT_ENGINE", "api").lower()
    meta_brief = {k: meta.get(k) for k in
                  ("Maintainer", "NumVotes", "Popularity", "OutOfDate",
                   "FirstSubmitted", "LastModified", "URL", "Depends", "MakeDepends")} if meta else {}
    aux_blob = "\n\n".join(f"### {fn}\n{txt[:4000]}" for fn, txt in aux_files.items() if txt)
    prompt = f"""You are a security auditor for AUR packages (Arch Linux). There was a recent
malware campaign that abused orphan adoptions and malicious instructions in
PKGBUILD and .install scripts. Analyze the package and respond ONLY with a JSON object
(no markdown, no extra text) with this exact shape, in English:
{{"risk":"low|medium|high|critical","confidence":0.0-1.0,"summary":"...","findings":["..."],"recommendation":"install|review|do_not_install"}}

Package: {name}
AUR metadata: {json.dumps(meta_brief, ensure_ascii=False)}
Previous heuristic findings: {json.dumps([h['desc'] for h in heuristics], ensure_ascii=False)}

--- PKGBUILD ---
{pkgbuild[:8000] if pkgbuild else '(not available)'}

--- AUXILIARY SCRIPTS ---
{aux_blob[:6000] if aux_blob else '(none)'}
"""
    if engine in ("claude-code", "cc", "claude_code"):
        return _verdict_via_claude_code(prompt, name)
    if engine in ("cli", "gemini", "codex", "custom"):
        return _verdict_via_cli(prompt, name, engine)
    if engine in ("openai", "compatible", "generic"):
        return _verdict_via_openai(prompt, model, name)
    return _verdict_via_api(prompt, model, name)  # anthropic (default)


def audit_one(name, version, meta, denylist, ai_mode, model, rpc_ok=True, is_foreign=True):
    pkgbase = (meta or {}).get("PackageBase", name)
    findings = list(metadata_risk(name, meta, version, rpc_ok, is_foreign))

    if name.lower() in denylist:
        findings.insert(0, {"severity": "high", "source": "denylist",
                            "desc": "On the official AUR affected-packages list (Jun 2026). Your copy is not necessarily compromised, but review it (PKGBUILD/.install/git history) before trusting or reinstalling.",
                            "match": name})

    pkgbuild, src_path, src_label = find_local_pkgbuild(pkgbase, name)
    if not pkgbuild and meta is not None:
        pkgbuild = fetch_aux(pkgbase, "PKGBUILD")
        src_label = "AUR (current upstream)"

    findings += heuristic_scan(pkgbuild, "PKGBUILD")

    aux_files = {}
    if pkgbuild:
        for fn in extract_install_files(pkgbuild):
            txt = ""
            if src_path and os.path.isfile(os.path.join(src_path, fn)):
                try:
                    txt = open(os.path.join(src_path, fn), encoding="utf-8", errors="replace").read()
                except Exception:
                    txt = ""
            if not txt and meta is not None:
                txt = fetch_aux(pkgbase, fn)
            if txt:
                aux_files[fn] = txt
                findings += heuristic_scan(txt, fn)

    worst = max((SEVERITY_RANK[f["severity"]] for f in findings), default=0)
    run_ai = ai_mode == "always" or (ai_mode == "suspicious" and worst >= SEVERITY_RANK["medium"])
    ai = ai_verdict(name, meta, pkgbuild, aux_files, findings, model) if run_ai else None

    return {
        "name": name, "version": version, "source": src_label or "n/a",
        "findings": findings, "worst": worst, "ai": ai,
        "popularity": (meta or {}).get("Popularity"),
        "maintainer": (meta or {}).get("Maintainer"),
    }


def verdict_label(result):
    if result["ai"] and result["ai"].get("risk"):
        return result["ai"]["risk"]
    return [k for k, v in SEVERITY_RANK.items() if v == result["worst"]][0]


def print_report(results):
    order = sorted(results, key=lambda r: (
        SEVERITY_RANK.get(r["ai"]["risk"], r["worst"]) if r["ai"] else r["worst"]
    ), reverse=True)
    crit = sum(1 for r in order if verdict_label(r) in ("high", "critical"))
    print()
    for r in order:
        lvl = verdict_label(r)
        color = SEVERITY_COLOR.get(lvl, C.dim)
        head = color(f"[{lvl.upper():8}]") + f" {C.bold(r['name'])} {C.dim(r['version'])} "
        head += C.dim(f"· {r['source']}")
        if r["maintainer"] is None and r["source"] != "n/a":
            head += C.yel(" · ORPHANED")
        print(head)
        for f in sorted(r["findings"], key=lambda x: SEVERITY_RANK[x["severity"]], reverse=True):
            fc = SEVERITY_COLOR[f["severity"]]
            print(f"    {fc('•')} {f['desc']} {C.dim('('+f['source']+': '+f['match']+')')}")
        if r["ai"]:
            ai = r["ai"]
            print(f"    {C.blu('🤖')} {ai.get('summary','')} "
                  f"{C.dim('[conf '+str(ai.get('confidence','?'))+' · '+ai.get('recommendation','?')+']')}")
            for h in ai.get("findings", [])[:5]:
                print(f"       {C.dim('-')} {h}")
        if not r["findings"] and not r["ai"]:
            print(f"    {C.grn('•')} No heuristic signals.")
        print()
    print(C.bold("Summary: ") +
          f"{len(order)} packages audited, "
          f"{C.red(str(crit)+' need attention') if crit else C.grn('0 high-risk')}.")
    print(C.dim("Reminder: being flagged does not imply compromise; manually review anything dubious."))
    return crit


def cmd_hook(pkgbase, build_dir, ai_mode, model, fail_on):
    """Mode intended for yay v13 Lua hooks (AURPreInstall / AURPostDownload).
    Audits the files yay ALREADY left in build_dir (the real PKGBUILD/.install/.SRCINFO),
    prints the findings to stderr and a final line to stdout: __AUR_AUDIT__=<worst>.
    Exit code 2 if it reaches the threshold (default high). Fails open if there is no data."""
    denylist = load_denylist()
    metas, rpc_ok = rpc_info([pkgbase])
    meta = metas.get(pkgbase.lower())
    findings = list(metadata_risk(pkgbase, meta, "", rpc_ok))

    if pkgbase.lower() in denylist:
        findings.insert(0, {"severity": "critical", "source": "denylist",
                            "desc": "Appears in the list of affected/removed packages.",
                            "match": pkgbase})

    pkgbuild = ""
    pb_path = os.path.join(build_dir, "PKGBUILD")
    if os.path.isfile(pb_path):
        try:
            pkgbuild = open(pb_path, encoding="utf-8", errors="replace").read()
        except Exception:
            pkgbuild = ""
    findings += heuristic_scan(pkgbuild, "PKGBUILD")

    aux_files = {}
    for fn in extract_install_files(pkgbuild):
        fp = os.path.join(build_dir, fn)
        if os.path.isfile(fp):
            try:
                txt = open(fp, encoding="utf-8", errors="replace").read()
            except Exception:
                txt = ""
            if txt:
                aux_files[fn] = txt
                findings += heuristic_scan(txt, fn)

    worst = max((SEVERITY_RANK[f["severity"]] for f in findings), default=0)
    run_ai = ai_mode == "always" or (ai_mode == "suspicious" and worst >= SEVERITY_RANK["medium"])
    ai = ai_verdict(pkgbase, meta, pkgbuild, aux_files, findings, model) if run_ai else None
    result = {"name": pkgbase, "version": (meta or {}).get("Version", ""),
              "source": "yay build dir", "findings": findings, "worst": worst, "ai": ai,
              "popularity": (meta or {}).get("Popularity"),
              "maintainer": (meta or {}).get("Maintainer")}

    # Human-readable report -> stderr; machine token -> stdout (read by the Lua hook).
    real_stdout = sys.stdout
    sys.stdout = sys.stderr
    try:
        print_report([result])
    finally:
        sys.stdout = real_stdout

    label = verdict_label(result)
    print(f"__AUR_AUDIT__={label}")

    if fail_on == "none":
        return 0
    return 2 if SEVERITY_RANK.get(label, worst) >= SEVERITY_RANK[fail_on] else 0


def gather(names_versions, ai_mode, model, workers=6, foreign_names=None):
    denylist = load_denylist()
    if denylist:
        sys.stderr.write(C.dim(f"[list] {len(denylist)} affected packages in the active denylist.\n"))
    else:
        sys.stderr.write(C.yel("[list] empty denylist. Run 'aur_audit.py update-list' to load it.\n"))
    metas, rpc_ok = rpc_info([n for n, _ in names_versions])

    def is_foreign(n):
        # foreign_names=None → treat all as foreign (default for 'audit'/'check').
        return foreign_names is None or n in foreign_names

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(audit_one, n, v, metas.get(n.lower()), denylist, ai_mode, model,
                          rpc_ok, is_foreign(n)): n
                for n, v in names_versions}
        for fut in concurrent.futures.as_completed(futs):
            results.append(fut.result())
    return results


def main():
    p = argparse.ArgumentParser(description="Security auditor for AUR packages.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pa = sub.add_parser("audit", help="Audit everything installed from AUR")
    pa.add_argument("--all", action="store_true",
                    help="Audit EVERY installed package (pacman -Q), not just AUR/foreign ones")
    pc = sub.add_parser("check", help="Audit specific packages (pre-installation)")
    pc.add_argument("pkgs", nargs="+")
    ph = sub.add_parser("hook", help="Mode for yay v13 Lua hooks (audits a build dir)")
    ph.add_argument("pkgbase")
    ph.add_argument("dir", help="yay build directory with the PKGBUILD already downloaded")
    sub.add_parser("update-list", help="Download the official list of affected packages")

    for sp in (pa, pc, ph):
        sp.add_argument("--ai", choices=["always", "suspicious", "never"], default="suspicious",
                        help="When to invoke the AI verdict (default: suspicious)")
        sp.add_argument("--no-ai", action="store_true", help="Shortcut for --ai never")
        sp.add_argument("--model", default=DEFAULT_MODEL)
        sp.add_argument("--json", metavar="FILE", help="Export the report to JSON")
        sp.add_argument("--fail-on", choices=["high", "critical", "none"], default="high",
                        help="Exit code !=0 if there are findings at this level (default: high)")
    for sp in (pa, pc):
        sp.add_argument("--tokens", action="store_true",
                        help="Report to stderr + a token '__AUR_AUDIT__=name=level' per package to stdout (for hooks)")
    args = p.parse_args()

    if args.cmd == "update-list":
        return update_affected_cache()

    ai_mode = "never" if getattr(args, "no_ai", False) else args.ai
    engine = os.environ.get("AUR_AUDIT_ENGINE", "api").lower()
    if ai_mode != "never":
        if engine in ("claude-code", "cc", "claude_code",
                      "cli", "gemini", "codex", "custom"):
            pass  # local CLI manages its own auth, no token needed here
        elif engine in ("openai", "compatible", "generic"):
            if not os.environ.get("AUR_AUDIT_API_KEY"):
                sys.stderr.write(C.yel("[ai] AUR_AUDIT_API_KEY not set — skipping the AI verdict. "
                                       "(Set AUR_AUDIT_API_KEY and, if needed, AUR_AUDIT_API_URL/--model.)\n"))
                ai_mode = "never"
        elif not os.environ.get("ANTHROPIC_API_KEY"):
            sys.stderr.write(C.yel("[ai] ANTHROPIC_API_KEY not set — skipping the AI verdict. "
                                   "(Alternatives: AUR_AUDIT_ENGINE=claude-code to use your session, "
                                   "or AUR_AUDIT_ENGINE=openai with AUR_AUDIT_API_KEY.)\n"))
            ai_mode = "never"

    if args.cmd == "hook":
        return cmd_hook(args.pkgbase, args.dir, ai_mode, args.model, args.fail_on)

    foreign_names = None
    if args.cmd == "audit":
        if getattr(args, "all", False):
            nv = all_installed_packages()
            foreign_names = {n for n, _ in foreign_packages()}  # rest = official repos
            scope = "installed"
        else:
            nv = foreign_packages()
            scope = "foreign"
        if not nv:
            print(C.grn("No packages to audit."))
            return 0
        print(C.dim(f"Auditing {len(nv)} {scope} packages…"))
    else:
        nv = [(pkg, "(pre-install)") for pkg in args.pkgs]

    results = gather(nv, ai_mode, args.model, foreign_names=foreign_names)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        print(C.dim(f"JSON report written to {args.json}"))

    if getattr(args, "tokens", False):
        # Human-readable report -> stderr; one token per package -> stdout (read by the Lua hook).
        real_stdout = sys.stdout
        sys.stdout = sys.stderr
        try:
            print_report(results)
        finally:
            sys.stdout = real_stdout
        for r in results:
            print(f"__AUR_AUDIT__={r['name']}={verdict_label(r)}")
    else:
        print_report(results)

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_RANK[args.fail_on]
    hit = any(SEVERITY_RANK.get(verdict_label(r), r["worst"]) >= threshold for r in results)
    return 2 if hit else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
