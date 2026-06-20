-- ~/.config/yay/init.lua
-- Safety net for yay v13 after the wave of malware in the AUR.
-- Hooks aur_audit.py into yay's NATIVE hooks (no wrapper or alias):
--   * AURPreInstall  -> audits the PKGBUILD/.install BEFORE menus, source
--                       downloads or build; aborts if the risk is high/critical.
--   * UpgradeSelect  -> on 'yay -Syu', pre-excludes AUR packages whose PKGBUILD
--                       changed very recently (extra signal, not a verdict).
--
-- Requirements: yay >= 13.0.0, python3, and aur_audit.py installed.
-- API docs: https://jguer.github.io/yay/lua.html
--
-- The environment where yay runs is inherited by the hooks, so if you export
-- AUR_AUDIT_ENGINE=claude-code or ANTHROPIC_API_KEY in your shell, the AI verdict
-- will use them automatically.

------------------------------------------------------------------ configuration
yay.log.debug("aur-audit: init.lua loaded OK")

local HOME = os.getenv("HOME")

-- Path to aur_audit.py (adjust it to wherever you installed it).
local AUDIT_BIN = HOME .. "/.local/bin/aur_audit.py"
local PY        = "python3"

-- When to request an AI verdict in the hook: "never" | "suspicious" | "always".
-- "suspicious" only invokes the AI if the heuristics/denylist already raised flags
-- (installs quickly on clean packages, digs deeper on dubious ones).
-- The AI verdict OVERRIDES the heuristics: if the AI reviews a package that the
-- heuristics flagged as high and considers it safe, installation is allowed. This
-- avoids false positives (e.g. google-chrome) without disabling the whole audit.
local AI_MODE   = "suspicious"

-- AI engine (any one with a token, a local CLI, or your Claude Code session):
--   "claude-code"      → uses your Claude Code session (no token).
--   "gemini" / "codex" → local gemini/codex CLI (AUR_AUDIT_CLI_CMD overrides default).
--   "cli"              → any local AI CLI; set AUR_AUDIT_CLI_CMD='mytool {prompt}'.
--   "openai"           → any OpenAI-compatible endpoint (OpenAI, OpenRouter, Groq,
--                        Ollama…); export AUR_AUDIT_API_KEY and, if needed,
--                        AUR_AUDIT_API_URL / AUR_AUDIT_MODEL in your shell.
--   "api"              → Anthropic API (requires ANTHROPIC_API_KEY).
--   nil                → inherits AUR_AUDIT_ENGINE from the environment.
-- The hook environment usually has no token, so "claude-code" (or a local CLI) lets
-- the AI actually run and possibly allow what the heuristics blocked. For cli/gemini/
-- codex, also export AUR_AUDIT_CLI_CMD in your shell so the hook inherits it.
local ENGINE    = "claude-code"

-- Level that BLOCKS the installation: "high" (recommended) or "critical".
local FAIL_ON   = "high"

-- STRICT=true  -> if the auditor cannot run, BLOCK (fail-closed).
-- STRICT=false -> if the auditor fails/is missing, WARN and continue (fail-open).
local STRICT    = false

-- Pre-exclude AUR packages modified in the last N days on 'yay -Syu'.
-- 0 disables this layer. It is not a verdict: it just forces you to look manually.
local RECENT_DAYS = 2

-- Trusted package bases that are NOT audited (your own, etc.).
local ALLOWLIST = {
  -- ["my-own-package"] = true,
}
------------------------------------------------------------------ utilities

local function shquote(s)
  return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

-- Environment prefix to force the AI engine in the subprocess (if ENGINE is set).
local function envprefix()
  if ENGINE then return "AUR_AUDIT_ENGINE=" .. shquote(ENGINE) .. " " end
  return ""
end

-- Runs 'aur_audit.py hook <base> <dir>' and returns the verdict read from the
-- __AUR_AUDIT__= token (the human-readable report goes to stderr, seen by the user).
local function audit(pkgbase, dir)
  -- 2>&1: yay swallows the subprocess's stderr, so we capture the report
  -- (stderr) along with the token (stdout) and re-emit it ourselves so it shows.
  local cmd = envprefix() .. table.concat({
    PY, shquote(AUDIT_BIN), "hook", shquote(pkgbase), shquote(dir),
    "--ai", AI_MODE, "--fail-on", FAIL_ON, "2>&1",
  }, " ")

  local f = io.popen(cmd, "r")
  if not f then return "error" end
  local verdict = "error"
  for line in f:lines() do
    local v = line:match("^__AUR_AUDIT__=(%S+)")
    if v then
      verdict = v
    else
      io.stderr:write(line, "\n")  -- the human-readable report, visible to the user
    end
  end
  f:close()
  return verdict
end

-- Audits several packages from the AUR upstream (in UpgradeSelect there is no
-- downloaded build dir yet). Re-emits the human-readable report and returns a
-- name->level map read from the '__AUR_AUDIT__=name=level' tokens.
local function audit_upstream(names)
  local verdicts = {}
  if #names == 0 then return verdicts end
  local parts = { PY, shquote(AUDIT_BIN), "check" }
  for _, n in ipairs(names) do parts[#parts + 1] = shquote(n) end
  parts[#parts + 1] = "--ai";      parts[#parts + 1] = AI_MODE
  parts[#parts + 1] = "--fail-on"; parts[#parts + 1] = FAIL_ON
  parts[#parts + 1] = "--tokens";  parts[#parts + 1] = "2>&1"
  local cmd = envprefix() .. table.concat(parts, " ")

  local f = io.popen(cmd, "r")
  if not f then return verdicts end
  for line in f:lines() do
    local n, v = line:match("^__AUR_AUDIT__=([^=]+)=(%S+)$")
    if n then
      verdicts[n] = v
    else
      io.stderr:write(line, "\n")  -- the human-readable report, visible to the user
    end
  end
  f:close()
  return verdicts
end

-- Should this verdict block?
local BLOCKING = { critical = true, high = (FAIL_ON == "high") }

------------------------------------------------------------------ AURPreInstall

yay.create_autocmd("AURPreInstall", {
  desc = "AUR security audit before building (aur_audit.py)",
  callback = function(event)
    local base = event.match
    if ALLOWLIST[base] then
      yay.log.debug("aur-audit: in allowlist, skipping", base)
      return
    end
    if os.getenv("AUR_AUDIT_OFF") == "1" then
      yay.log.warn("aur-audit: disabled by AUR_AUDIT_OFF=1 ->", base)
      return
    end

    yay.log.info("aur-audit: reviewing " .. base .. "…")
    local verdict = audit(base, event.data.dir)

    if verdict == "error" then
      if STRICT then
        yay.abort("aur-audit: could not audit " .. base .. " (strict mode).")
      else
        yay.log.warn("aur-audit: could not audit " .. base .. "; continuing (fail-open).")
      end
      return
    end

    if BLOCKING[verdict] then
      -- yay.abort stops this installation gracefully, without a traceback.
      yay.abort(string.format(
        "aur-audit: BLOCKED %s (risk=%s). Check the report above. " ..
        "To force it: AUR_AUDIT_OFF=1 yay -S %s", base, verdict, base))
    else
      yay.log.info(string.format("aur-audit: %s ok (risk=%s)", base, verdict))
    end
  end,
})

------------------------------------------------------------------ UpgradeSelect

yay.create_autocmd("UpgradeSelect", {
  desc = "Audit AUR upgrades: exclude the risky ones, continue with the rest",
  callback = function(event)
    if os.getenv("AUR_AUDIT_OFF") == "1" then
      yay.log.warn("aur-audit: disabled by AUR_AUDIT_OFF=1; not auditing the upgrade.")
      return { exclude = {}, skip_menu = false }
    end

    local excluded = {}   -- name -> reason (to avoid duplicates and build the report)
    local cutoff = (RECENT_DAYS and RECENT_DAYS > 0)
                   and (os.time() - RECENT_DAYS * 24 * 60 * 60) or nil

    -- Layer 1: pre-exclude anything modified very recently (signal, not verdict).
    local to_audit = {}
    for _, pkg in ipairs(event.data.upgrades) do
      if pkg.repository == "aur" and not ALLOWLIST[pkg.name] then
        if cutoff and pkg.last_modified and pkg.last_modified >= cutoff then
          excluded[pkg.name] = string.format("modified <%dd ago", RECENT_DAYS)
        else
          table.insert(to_audit, pkg.name)
        end
      end
    end

    -- Layer 2: audit the rest and exclude whatever blocks (the AI may absolve).
    local verdicts = audit_upstream(to_audit)
    for _, name in ipairs(to_audit) do
      local v = verdicts[name]
      if v and BLOCKING[v] then
        excluded[name] = "risk=" .. v
      elseif v == nil then
        yay.log.warn("aur-audit: could not audit " .. name .. "; continuing (fail-open).")
      end
    end

    -- Final report: everything that is NOT installed, with its reason and how to force it.
    local exclude, any = {}, false
    for name, reason in pairs(excluded) do
      if not any then
        yay.log.warn("==== aur-audit: packages EXCLUDED from the upgrade ====")
        any = true
      end
      table.insert(exclude, name)
      yay.log.warn(string.format(
        "  - %s (%s). To install it anyway: AUR_AUDIT_OFF=1 yay -S %s",
        name, reason, name))
    end
    if not any then
      yay.log.info("aur-audit: no AUR package in the upgrade requires exclusion.")
    end

    -- skip_menu=false: yay still shows its exclusion menu after this.
    return { exclude = exclude, skip_menu = false }
  end,
})
