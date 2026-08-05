#!/usr/bin/env bash
# PreToolUse(Bash) — catch backticks in a DURABLE-PROSE write before the shell eats them.
#
# Writing prose through a double-quoted shell string is routine — a commit message, a PR body,
# a note-store entry. Backticks are equally routine INSIDE that prose (quoting command names in
# markdown). The shell then executes them: the span vanishes, or worse, the command's OUTPUT is
# spliced into the record. Observed three times in one session; the third spliced a directory
# listing into a handoff document, where it would have been read as content.
#
# It is pure oversight, not judgment — which is why a notice at the moment of the call is the
# right instrument: seeing "the shell will execute these" fixes it instantly, whereas no amount
# of resolving-to-be-careful survives a long session.
#
# PRECISION IS THE WHOLE DESIGN. A hook that fires on the CORRECT form teaches you to ignore it,
# so it stays silent when:
#   - a quoted heredoc is in use (<<'EOF' / <<"EOF") — the body is literal, the safe form;
#   - the backticks sit inside single quotes — also literal;
#   - the command is not writing durable prose (ordinary substitution is not this hook's concern).
# WARN, never block, fail-open: any error, unparseable payload, or non-match -> exit 0 silently.
set -uo pipefail

payload=$(cat 2>/dev/null) || exit 0

HOOK_PAYLOAD="$payload" python3 - <<'PY' || exit 0
import json, os, re, sys

try:
    payload = json.loads(os.environ.get("HOOK_PAYLOAD", "{}"))
    if payload.get("tool_name", "") != "Bash":
        sys.exit(0)
    cmd = (payload.get("tool_input", {}) or {}).get("command", "") or ""
    if "`" not in cmd:
        sys.exit(0)

    # The safe form already in use -> say nothing. A quoted heredoc delimiter makes the whole
    # body literal, which is exactly what this hook would otherwise be recommending.
    if re.search(r"<<-?\s*(['\"])", cmd):
        sys.exit(0)

    # Single-quoted spans are literal too; drop them before looking for live backticks.
    stripped = re.sub(r"'[^']*'", "", cmd)
    if "`" not in stripped:
        sys.exit(0)

    # Only durable-prose writers. Anything else with a backtick is ordinary shell.
    # Add your own note-store / wiki CLI's write verbs to this list.
    writers = [
        (r"\bgit\s+commit\b[^|]*\s-m\b",               "a commit message"),
        (r"\bgit\s+tag\b[^|]*\s-m\b",                  "a tag message"),
        (r"\bgh\s+(pr|issue|release)\s+\w+[^|]*(-b|--body|--notes)\b", "a GitHub body"),
    ]
    where = next((w for pat, w in writers if re.search(pat, stripped)), None)
    if not where:
        sys.exit(0)

    msg = ("Backtick notice: this command writes %s through an interpolating string, and it "
           "contains backticks the shell will EXECUTE before the text is ever written — the span "
           "disappears, or the command's output is spliced into the record. Re-issue it with a "
           "single-quoted heredoc so the body stays literal, e.g. for git:  git commit -F - "
           "<<'MSG' ... MSG. If the backticks are deliberate command substitution, prefer $(...) "
           "and ignore this." % where)
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "additionalContext": msg}}))
except Exception:
    sys.exit(0)
PY
exit 0
