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
#   - the prose goes through a QUOTED heredoc (<<'EOF' / <<"EOF") — the body is literal, and
#     that is the very form this hook recommends;
#   - a quoted heredoc body is literal DATA handed to some program — it is blanked before
#     anything is matched, so a sample command quoted inside it is not read as a real one;
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

    # A QUOTED heredoc body is literal DATA handed to some program, not shell performing a
    # durable write — so blank those bodies out before matching anything. Earned immediately:
    # the very command that tested this fix was `python3 - <<'PY'` whose body contained a sample
    # `git commit -F - <<MSG` with backticks as FIXTURE text, and the hook warned about a commit
    # that was never going to happen. Scanning literal data is how a precise hook becomes noise,
    # and noise is what this file's header says must never happen.
    def _blank_quoted_heredocs(text):
        out, i = [], 0
        for m in re.finditer(r"<<-?\s*(['\"])([A-Za-z_]\w*)\1", text):
            end = m.end()
            close = re.search(r"^\s*" + re.escape(m.group(2)) + r"\s*$", text[end:], re.M)
            stop = end + (close.end() if close else len(text) - end)
            out.append(text[i:end]); i = stop
        out.append(text[i:])
        return "".join(out)

    cmd = _blank_quoted_heredocs(cmd)
    if "`" not in cmd:
        sys.exit(0)

    # TWO SHAPES, and the second was missing until 2026-08-09.
    #
    # Shape A: prose inline in an interpolating string  ->  git commit -m "... `x` ..."
    # Shape B: prose in an UNQUOTED heredoc fed to the writer  ->  git commit -F - <<MSG ... MSG
    #
    # Shape B is the one that bit: this hook's own advice recommends `git commit -F - <<'MSG'`,
    # and the flag-based patterns below only ever matched `-m`, so the UNQUOTED variant of the
    # very form the hook tells you to use was invisible to it. Two commit messages were silently
    # eaten before anyone noticed — a countermeasure whose advice covers a case its detector
    # does not.
    #
    # Shape B is matched with the heredoc TIED to the writer on the same command segment
    # ([^|;&\n]*), not merely present somewhere in the command. Otherwise the common and correct
    # `git commit -F - <<'MSG' ... MSG` sitting beside an unrelated `cat > f <<X` would warn, and
    # a hook that fires on the correct form teaches you to ignore it — which this file's own
    # header calls the whole design.
    #
    # Both lists below are the same enumeration of durable-prose writers, matched two ways. Add
    # your own note-store / wiki CLI's write verbs to BOTH — a verb added to only one of them is
    # exactly the blind axis that made shape B necessary in the first place.
    SEG = r"[^|;&\n]*"
    HD  = r"<<-?\s*[A-Za-z_]\w*"          # an UNQUOTED delimiter; <<'X' and <<"X" are the safe form
    heredoc_writers = [
        (r"\bgit\s+commit\b" + SEG + HD,                "a commit message"),
        (r"\bgit\s+tag\b" + SEG + HD,                   "a tag message"),
        (r"\bgh\s+(pr|issue|release)\s+\w+" + SEG + HD, "a GitHub body"),
    ]
    where = None
    for pat, w in heredoc_writers:
        m = re.search(pat, cmd)
        # the backtick must be in the BODY, i.e. after the delimiter — a backtick elsewhere in
        # the line is ordinary shell and not this hook's business.
        if m and "`" in cmd[m.end():]:
            where = w
            break

    if where is None:
        # Shape A. The safe form already in use -> say nothing. A quoted heredoc delimiter makes
        # the whole body literal, which is exactly what this hook would otherwise be recommending.
        if re.search(r"<<-?\s*(['\"])", cmd):
            sys.exit(0)

        # Single-quoted spans are literal too; drop them before looking for live backticks.
        stripped = re.sub(r"'[^']*'", "", cmd)
        if "`" not in stripped:
            sys.exit(0)

        # Only durable-prose writers. Anything else with a backtick is ordinary shell.
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
