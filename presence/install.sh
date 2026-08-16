#!/usr/bin/env bash
# install.sh — put the presence registry and the peer-note inbox on PATH, and show the hook
# wiring you still have to paste in by hand.
#
# Idempotent. Installs two names for one implementation (dispatch is by invocation name, so a
# wrapper cannot drift from the script it wraps):
#   agent-presence   who else is live, where they are writing, what is undelivered
#   agent-send       leave a note for a peer session
#
# This installer NEVER writes ~/.claude/settings.json. It reads it, and if the wiring is not
# there it prints what to paste — your settings file is yours, and a tool that rewrites it can
# only ever guess at what else you have in there.
#
# The suite runs as a gate. The suite does not invoke this installer, so there is no
# installer-runs-suite-runs-installer cycle here.
#
#   AGENT_PRESENCE_BIN    where to link the two commands   (default ~/bin)
#   AGENT_PRESENCE_DIR    where the registry lives         (default ~/.local/state/claude-sessions)
set -uo pipefail
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
BIN="${AGENT_PRESENCE_BIN:-$HOME/bin}"
STATE="${AGENT_PRESENCE_DIR:-$HOME/.local/state/claude-sessions}"
SETTINGS="$HOME/.claude/settings.json"

echo "installing agent-presence from $HERE"

# 1. gate on the suite -------------------------------------------------------------------------
# Its own sink, in its own temp file: a fixed name in /tmp is a file two concurrent runs share.
out=$(mktemp) || exit 1
trap 'rm -f "$out"' EXIT
if ! python3 "$HERE/tests/test-session-presence.py" >"$out" 2>&1; then
  echo "  ERROR: suite failed — refusing to install. Output:" >&2
  tail -30 "$out" >&2
  exit 1
fi
echo "  suite    $(awk '/^Ran /{print $2}' "$out") tests pass"

# 2. binaries ----------------------------------------------------------------------------------
mkdir -p "$BIN"
for name in agent-presence agent-send; do
  dst="$BIN/$name"
  if [ -e "$dst" ] && [ ! -L "$dst" ]; then
    echo "  REFUSED  $dst exists and is not a symlink — inspect it by hand" >&2
    exit 1
  fi
  ln -sf "$HERE/session-presence" "$dst"
  echo "  bin      $dst -> $HERE/session-presence"
done
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "  NOTE     $BIN is not on your PATH — add it, or set AGENT_PRESENCE_BIN to a dir that is" ;;
esac

# 3. state root --------------------------------------------------------------------------------
# Only the root. The subdirectories are created on first use by ensure_dirs() in the script
# itself, which is the one place that knows what they are — a second list here would drift.
mkdir -p "$STATE"
echo "  state    $STATE"

# 4. hook wiring: report it, never perform it --------------------------------------------------
# Note the command is the SCRIPT's own path, not `agent-presence`: dispatch is by invocation
# name, so the hook entry points answer only to the name `session-presence`.
if [ -r "$SETTINGS" ] && grep -q 'session-presence' "$SETTINGS"; then
  echo "  hooks    $SETTINGS already mentions session-presence"
  exit 0
fi
if [ -r "$SETTINGS" ]; then
  echo "  hooks    NOT WIRED — presence is on PATH but no session will register itself."
else
  echo "  hooks    no readable $SETTINGS — nothing to check."
fi
cat <<SNIPPET

  Merge these into the "hooks" object of $SETTINGS by hand. Each is fail-open: a hook that
  breaks a tool call is worse than no hook, hence the "2>/dev/null || true" on every one.
  New hook blocks take effect on the next turn — no restart.

  "SessionStart": [
    { "hooks": [ { "type": "command",
      "command": "$HERE/session-presence register 2>/dev/null || true" } ] }
  ],
  "PreToolUse": [
    { "hooks": [ { "type": "command",
      "command": "$HERE/session-presence pretool 2>/dev/null || true" } ] }
  ],
  "SessionEnd": [
    { "hooks": [ { "type": "command",
      "command": "$HERE/session-presence end 2>/dev/null || true" } ] }
  ]

  PreToolUse has an empty matcher on purpose: presence is refreshed on EVERY tool call, which
  is what makes a peer note arrive within seconds of being sent. If you already have a
  PreToolUse block, add this hook to it rather than replacing it.
SNIPPET
exit 0
