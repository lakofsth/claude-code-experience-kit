#!/usr/bin/env bash
# PreToolUse(Bash) guard — block pattern-based process kills that can match the CALLING shell.
#
# `pkill -f <pat>` and `for p in $(pgrep -f <pat>); do kill "$p"; done` kill the very shell
# running them, because the pattern is present in that shell's own cmdline. Agents are told
# this, remember it, and do it anyway — repeatedly, including with the "safe" bracket trick
# (`foo[-]bar`), which fails whenever the plain string also appears elsewhere in the same
# command. A structural guard, not a reminder.
#
# Blocks: pkill -f · killall · (pgrep -f … + kill) in one command.
# Allows: kill by PID · pkill -x (exact process NAME) · pgrep without a kill.
#
# Only real SHELL CODE is inspected: quoted strings and heredocs are stripped first, so a commit
# message or a docstring that merely MENTIONS these commands is not blocked. (Learned
# immediately: v1 blocked its own commit message.)
set -uo pipefail

payload=$(cat)

# NB: the payload goes in via the ENVIRONMENT, not stdin -- `python3 - <<'PY'` makes the heredoc
# python's stdin, which silently discards a piped payload and makes this guard fail OPEN.
# (v2 did exactly that and blocked nothing at all.)
verdict=$(HOOK_PAYLOAD="$payload" python3 - <<'PY'
import json, os, re, sys

try:
    cmd = json.loads(os.environ.get("HOOK_PAYLOAD", "{}")).get("tool_input", {}).get("command", "")
except Exception:
    sys.exit(0)
if not cmd:
    sys.exit(0)

# If you have a kill helper that filters out $$, $PPID and every ancestor PID, allow it
# through wholesale by name here, e.g.:
# if "my_safe_kill" in cmd: sys.exit(0)

# --- strip everything that is DATA rather than shell code -------------------------------
s = cmd
s = re.sub(r"<<'?(\w+)'?.*?^\1", " ", s, flags=re.DOTALL | re.MULTILINE)  # heredocs
s = re.sub(r"'[^']*'", " ", s)                                            # single-quoted
s = re.sub(r'"[^"]*"', " ", s)                                            # double-quoted

reason = None
if re.search(r"(^|[;&|(\s])pkill\s+(-\w+\s+)*-\w*f", s):
    reason = "pkill -f"
elif re.search(r"(^|[;&|(\s])killall(\s|$)", s):
    reason = "killall"
elif re.search(r"pgrep\s+(-\w+\s+)*-\w*f", s) and re.search(r"(^|[;&|`(\s])kill(\s|$)", s):
    reason = "pgrep -f + kill (resolves PIDs by cmdline pattern — matches this shell)"

if reason:
    print(reason)
PY
) || exit 0

[ -n "$verdict" ] || exit 0

cat >&2 <<EOF
BLOCKED: '$verdict' can match the calling shell's own cmdline and kill this session.
The bracket trick ('foo[-]bar') does NOT save you when the plain string appears elsewhere
in the same command.

Use instead, in order of preference:
  1. by PID:            SRV=\$!   ...   kill "\$SRV"
  2. by exact name:     pkill -x processname
  3. a safe helper that resolves pgrep -f matches and then filters out \$\$, \$PPID,
     every ancestor PID, and any harness wrapper shells before killing.
EOF
exit 2
