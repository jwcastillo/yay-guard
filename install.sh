#!/usr/bin/env bash
# install.sh — installs yay-guard and the AUR auditor.
#
# Copies the 3 binaries to ~/.local/bin and, optionally, hooks into yay v13's
# native hook (init.lua). No sudo needed if you use the default prefix (~/.local/bin).
#
# Usage:
#   ./install.sh                 # installs binaries + asks about the yay hook
#   BIN=/usr/local/bin sudo ./install.sh   # system-wide installation
#   ./install.sh --no-hook       # binaries only, without touching ~/.config/yay/init.lua

set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${BIN:-$HOME/.local/bin}"
YAY_CFG="${YAY_CFG:-$HOME/.config/yay}"
WANT_HOOK=1
[[ "${1:-}" == "--no-hook" ]] && WANT_HOOK=0

say() { printf '\033[1m[install]\033[0m %s\n' "$*"; }

# 1) Binaries.
install -Dm755 "$SRC/aur_audit.py"    "$BIN/aur_audit.py"
install -Dm755 "$SRC/yay-guard"       "$BIN/yay-guard"
install -Dm755 "$SRC/aur-deep-audit"  "$BIN/aur-deep-audit"
say "installed aur_audit.py, yay-guard and aur-deep-audit in $BIN"

# 2) yay v13 native hook (init.lua). It is not overwritten without permission.
if [[ $WANT_HOOK -eq 1 ]]; then
    dst="$YAY_CFG/init.lua"
    if [[ -e "$dst" ]]; then
        read -rp "[install] $dst already exists. Overwrite? [y/N]: " ans
        [[ "$ans" == [yY] ]] || { say "keeping the existing init.lua."; WANT_HOOK=0; }
    fi
    if [[ $WANT_HOOK -eq 1 ]]; then
        install -Dm644 "$SRC/init.lua" "$dst"
        say "yay hook installed in $dst (requires yay >= 13)"
    fi
fi

# 3) Final notices.
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) say "NOTE: $BIN is not in your PATH. Add it to your ~/.bashrc / ~/.zshrc:"
       printf '         export PATH="%s:$PATH"\n' "$BIN" ;;
esac

cat <<EOF

Done. Next steps:
  • Load the denylist of affected packages:   aur_audit.py update-list
  • Choose the AI engine (one):
      export AUR_AUDIT_ENGINE=claude-code        # use your Claude Code session (no token)
      export AUR_AUDIT_ENGINE=openai  AUR_AUDIT_API_KEY=...   # any OpenAI-compatible endpoint
      export ANTHROPIC_API_KEY=sk-ant-...        # default 'api' engine (Anthropic)
  • If you do NOT use the yay hook, alias the wrapper:  alias yay='yay-guard'

One-off bypass:  YAY_GUARD_OFF=1 yay -S package   (wrapper)
                 AUR_AUDIT_OFF=1 yay -S package   (hook)
EOF
