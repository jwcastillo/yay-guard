# yay-guard

Security audit **before** installing packages from the AUR. Born after the AUR malware
campaign (June 2026), in which ~2,000 packages were abused through orphan adoption and
malicious instructions in `PKGBUILD` and `.install` scripts.

It automates what Arch recommends doing by hand: reviewing the PKGBUILD, install
scripts, history, maintainer, and popularity — and, optionally, asking an AI for a
verdict.

## What it decides

It produces a single verdict — `info`/`low`/`medium`/`high`/`critical` — used to decide
**whether a package should be installed**. Each finding carries a severity; the package's
verdict is the **worst** finding. The `--fail-on` threshold (default `high`) turns that
verdict into an action:

- **yay v13 hook** — on `yay -S`, a blocking verdict aborts the build (with `AUR_AUDIT_OFF=1`
  to force); on `yay -Syu`, blocking packages are **excluded** and the upgrade continues.
- **`yay-guard` wrapper** — a blocking verdict requires typing an explicit confirmation
  before it hands off to `yay`.
- **exit code** — `2` when any package meets the threshold, so it composes in scripts.

So the answer to "install or not" is: install if the verdict is below `--fail-on`;
otherwise stop and review (or explicitly override).

## What it's based on (beyond the AI)

The AI verdict is **optional**. The core decision works with no token and no network,
on two deterministic signals:

**1. Static heuristics** — regex over the real `PKGBUILD` / `.install` / `.SRCINFO`
(the locally built copy in `~/.cache/yay|paru` is preferred over upstream, since that's
what actually ran). It flags, with a severity each:

- `curl|sh` / `wget|sh`, raw `curl`/`wget` downloads, downloads from a literal **IP**,
  **URL shorteners**, or **ephemeral paste** services (not a real upstream)
- `base64 -d`, `eval`, long `\xNN` **hex blobs**, `xxd -r`, inline `gpg`/`openssl`
  decryption, inline `python -c` — obfuscation / hidden payloads
- `nc -e`, `/dev/tcp/` — reverse shells
- `cron` / `systemctl enable` / `autostart` / systemd units, edits to
  `~/.bashrc`/`.zshrc`/`.profile`, `chattr` — **persistence**
- `sudo` inside the PKGBUILD (build steps shouldn't escalate)

**2. AUR RPC metadata** — orphan (no maintainer), very low popularity/votes,
out-of-date, **submitted and modified within 7 days** (the adoption pattern of the
campaign), or the package **no longer existing** in AUR.

**3. Affected-packages denylist** — auto-refreshed from the official Arch note
(`https://md.archlinux.org/s/SxbqukK6IA`, cache TTL `AUR_AUDIT_LIST_TTL`). Being on it
means *review with attention* (severity `high`), **not** that your copy is compromised.

**4. AI verdict (optional)** — a model reviews the package and **overrides the
heuristics**: it can clear a false positive (e.g. `google-chrome`, whose legitimate
`curl` + `cron`-removal lines trip the regexes) without disabling the audit. It never
makes a clean package look worse than the deterministic signals already flagged.

For the deepest check, `aur-deep-audit` runs Claude Code as a **read-only agent** that
walks the package's `git log`/`git diff` to find the exact malicious adoption commit.

## Components

| File | What it is | When |
|---|---|---|
| `aur_audit.py` | The audit engine (heuristics + metadata + AI). | Always. |
| `yay-guard` | Wrapper/alias for `yay`; requires written confirmation on high/critical risk. | Any yay version. |
| `init.lua` | **Native** yay v13 hooks (`AURPreInstall`, `UpgradeSelect`). | yay ≥ 13 (recommended). |
| `aur-deep-audit` | Clones the package repo and runs **Claude Code as a read-only agent** to walk the `git log`/`git diff` for the malicious adoption commit. | Deep investigation of one package. |

With the yay v13 hook:
- `yay -S google-chrome` → audits before building; if the AI clears it, it installs.
- `yay -Syu` → **excludes** risky AUR packages, **continues** with the rest, and prints
  a final report of the excluded ones with the reason and how to force them.

## Installation

### From the AUR

```bash
yay -S yay-guard          # or: paru -S yay-guard
```

Then follow the post-install hint (enable the hook or the wrapper alias).

### Manual / from source

```bash
./install.sh              # binaries to ~/.local/bin + yay v13 hook
./install.sh --no-hook    # binaries only (if you use the wrapper/alias)
BIN=/usr/local/bin sudo ./install.sh   # system-wide
```

### Enable an integration

```bash
# Native yay v13 hook (recommended):
mkdir -p ~/.config/yay && cp /usr/share/yay-guard/init.lua ~/.config/yay/init.lua

# Or wrapper alias (any yay):
alias yay='yay-guard'
```

Then load the affected list once (it auto-refreshes afterwards):

```bash
aur_audit.py update-list
```

## AI engines

Configured with `AUR_AUDIT_ENGINE`:

```bash
# Your local Claude Code session (no token):
export AUR_AUDIT_ENGINE=claude-code

# Any OpenAI-compatible endpoint (OpenAI, OpenRouter, Groq, Ollama, llama.cpp…):
export AUR_AUDIT_ENGINE=openai
export AUR_AUDIT_API_KEY=...                 # token
export AUR_AUDIT_API_URL=https://...         # optional; default api.openai.com
export AUR_AUDIT_MODEL=gpt-4o-mini           # match the model to the provider

# Anthropic API (default engine):
export ANTHROPIC_API_KEY=sk-ant-...
```

> Note: when using `claude-code`, an exported `ANTHROPIC_API_KEY` is stripped from the
> child process so it uses your subscription instead of a (possibly empty) API balance.

Without a token and without Claude Code, the audit still works using heuristics +
metadata only.

## Using the auditor directly

```bash
aur_audit.py audit                 # audits everything installed from the AUR (pacman -Qm)
aur_audit.py audit --all           # audits EVERY installed package (pacman -Q)
aur_audit.py audit --ai always     # forces an AI verdict on all of them
aur_audit.py check yay paru-bin    # audits specific packages (pre-install)
aur_audit.py audit --json out.json # exports the report as JSON
aur_audit.py audit --no-ai         # heuristics + metadata only (no network/AI)
aur_audit.py update-list           # refreshes the denylist of affected packages

aur-deep-audit slack               # deep git-history audit of one package
```

Flags: `--ai always|suspicious|never` · `--no-ai` · `--model` · `--json` ·
`--fail-on high|critical|none` · `--tokens` (report to stderr, token per package to stdout).

Relevant environment variables: `AUR_AUDIT_ENGINE`, `ANTHROPIC_API_KEY`,
`AUR_AUDIT_API_KEY`, `AUR_AUDIT_API_URL`, `AUR_AUDIT_MODEL`, `AUR_AUDIT_DENYLIST`,
`AUR_AUDIT_LIST_TTL`, `AUR_AUDIT_CLAUDE_BIN`.

## One-off bypass

```bash
YAY_GUARD_OFF=1 yay -S package     # skips the wrapper
AUR_AUDIT_OFF=1  yay -S package    # skips the yay hook
```

## Requirements

`python3` (stdlib only), `pacman`/`yay`. For `aur-deep-audit`: `claude` (Claude Code),
`git`, and, optionally, `jq`. The native hook requires `yay >= 13`.

## Packaging (AUR)

This repo ships a `PKGBUILD`, `.SRCINFO`, and `yay-guard.install`. To publish:

1. Set `# Maintainer`, `url`, and push a `v<pkgver>` tag to your repo.
2. `updpkgsums` to fill `sha256sums`, then `makepkg --printsrcinfo > .SRCINFO`.
3. `makepkg -si` to test locally; push `PKGBUILD` + `.SRCINFO` to the AUR.

## License

MIT. See [LICENSE](LICENSE).

> Being flagged does **not** imply compromise. Always review anything dubious manually;
> the AUR cleanup may still be in progress.
