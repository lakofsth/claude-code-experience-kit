#!/usr/bin/env bash
# PreToolUse(Bash) guard — block a process kill or a wait gate that is keyed on a process
# PATTERN or a process NAME, either of which can reach a process that is not yours.
#
# `pkill -f <pat>` and `for p in $(pgrep -f <pat>); do kill "$p"; done` kill the very shell
# running them, because the pattern is present in that shell's own cmdline. Agents are told
# this, remember it, and do it anyway — repeatedly, including with the "safe" bracket trick
# (`foo[-]bar`), which fails whenever the plain string also appears elsewhere in the same
# command. A structural guard, not a reminder.
#
# Blocks: pkill -f · killall · (pgrep -f … + kill) in one command ·
#         a wait gate (until/while) on ANY pgrep · a kill by exact NAME that would reach more
#         than one process on this host.
# Allows: kill by PID · a safe helper you name below (one that filters out its own ancestry) ·
#         pgrep on its own · a kill by exact NAME that resolves to at most one process.
#
# Only real SHELL CODE is inspected: quoted strings and heredocs are stripped first, so a commit
# message or a docstring that merely MENTIONS these commands is not blocked. (Learned
# immediately: v1 blocked its own commit message.)
#
# WIDENED 2026-09-10 (ledger D740): the strip is the SHARED bash-aware, length-preserving quote
# mask (hooks/quote_mask.py), not two regexes. The naive pair treated the apostrophe inside
# "it's fine" as an opening quote and ate everything up to the next literal quote — including
# pkill -f's own argument — so `echo "it's fine" ; pkill -f 'llama-server'` exited 0, SILENT:
# the danger was stripped from the text the guard tests, the fail-open direction. Pinned by the
# one fixture matrix over all four mask call sites, hooks/tests/test-quote-mask-matrix.py.
#
# WIDENED 2026-09-17: THE GUARD'S OWN ADVICE WAS THE DANGEROUS HALF. Until today this file
# offered, in as many words, "2. by exact name: pkill -x llama-server". On the host this was
# measured on that command stops FOUR processes and three of them belong to other services.
# `-x` is exact in the NAME, not in the OWNER: it is safe only where the name is unique on the
# host, and llama-server was the worst possible example to print there. Three changes:
#   (a) the advice now names killing by the PID you captured, and a safe helper, as the right
#       constructs, and states the uniqueness precondition `-x` actually carries;
#   (b) the until/while arm covers `pgrep -x` and bare `pgrep`, not only `pgrep -f`. A wait gate
#       on a process NAME hangs two ways and neither is visible from the command: the pattern
#       can match the caller (the 2026-08-31 case), or an unrelated long-lived service can hold
#       the name for ever (this one). A queued job was written as
#       `until ! pgrep -x llama-server; do sleep 10; done` and would never have run; it was
#       caught by eye, which is the state this file exists to end;
#   (c) `pkill -x <name>` (and `pgrep -x <name>` paired with a kill) is no longer allowed
#       unconditionally. It is COUNTED at hook time — `pgrep -x <name>`, the same matcher pkill
#       itself uses, so the count is exactly what the command would stop — and denied only when
#       it would reach more than one process, naming each pid and its cmdline. That keeps the
#       legitimate single-owner use silent, which is the whole reason `-x` was on the allow list.
#
# STATED LIMITS, rather than discovered later:
#   - a name held in a shell variable (`pkill -x "$NAME"`) is unresolvable here and passes;
#   - a count of exactly one is allowed, and this guard cannot tell whether that one is yours;
#   - the count is read at hook time, so a process that starts between the check and the kill is
#     not seen. The guard catches the standing shared-name case, which is what was measured.
set -uo pipefail

payload=$(cat)

# NB: the payload goes in via the ENVIRONMENT, not stdin -- `python3 - <<'PY'` makes the heredoc
# python's stdin, which silently discards a piped payload and makes this guard fail OPEN.
# (v2 did exactly that and blocked nothing at all.)
#
# The MESSAGE is built in python, inside a QUOTED heredoc, not in a bash heredoc downstream: an
# unquoted bash heredoc expands `$!`, `$$` and backticks in the advice itself, so the guidance
# renders as empty strings or as command output. That has happened to this file before.
verdict=$(HOOK_PAYLOAD="$payload" HOOK_SELF="${BASH_SOURCE[0]}" python3 - <<'PY'
import json, os, re, shlex, subprocess, sys
sys.path.insert(1, os.path.dirname(os.path.realpath(os.environ.get("HOOK_SELF", ""))))
from quote_mask import mask_quoted

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
# A command substitution — `...` or $(...) — is CODE wherever bash runs it: in plain text,
# inside "...", and inside the body of an UNQUOTED heredoc. Only single quotes and a QUOTED
# heredoc (<<'X', <<"X", <<\X) make it data. Until 2026-09-27 this file stripped every heredoc
# and every "..." wholesale, so `python3 - <<EOF` carrying a note with a backticked
# `pkill -f "tests/run.sh --fast"` passed and ran as the operator (session 0fd30f6c).
# So: blank the heredoc bodies, but first carry every LIVE substitution out of them and out
# of "..." spans, and test those as shell code alongside the masked text.
HEREDOC = re.compile(r"<<(-?)[ \t]*(?:'(\w+)'|\"(\w+)\"|\\(\w+)|(\w+))[^\n]*\n(.*?)^[ \t]*(?:\2|\3|\4|\5)[ \t]*$",
                     re.DOTALL | re.MULTILINE)


def substitutions(t, heredoc_body=False):
    """Contents of every `...` and $(...) that bash would EXECUTE in t. In a heredoc body the
    quote characters are literal, so every substitution there is live; elsewhere, only those
    outside single quotes are."""
    out, i, n, q = [], 0, len(t), None
    while i < n:
        c = t[i]
        if not heredoc_body and q is None and c in "'\"":
            q = c; i += 1; continue
        if not heredoc_body and q is not None and c == q:
            q = None; i += 1; continue
        if q == "'":
            i += 1; continue
        if c == "\\" and i + 1 < n:
            i += 2; continue
        if c == "`":
            j = t.find("`", i + 1)
            j = n if j < 0 else j
            out.append(t[i + 1:j]); i = j + 1; continue
        if c == "$" and t[i + 1:i + 2] == "(" and t[i + 2:i + 3] != "(":
            depth, j = 1, i + 2
            while j < n and depth:
                depth += {"(": 1, ")": -1}.get(t[j], 0); j += 1
            out.append(t[i + 2:j - 1]); i = j; continue
        i += 1
    return out


live = []
def _heredoc(m):
    if m.group(5):                       # unquoted delimiter: the body's substitutions run
        live.extend(substitutions(m.group(6), heredoc_body=True))
    return " "
s = HEREDOC.sub(_heredoc, cmd)
live.extend(substitutions(s))            # substitutions inside "..." (plain ones are kept anyway)
s = mask_quoted(s)   # bash's quoting rules, length-preserving — see hooks/quote_mask.py
for sub in live:                          # each live substitution is shell code in its own right
    s += "\n" + mask_quoted(HEREDOC.sub(" ", sub))

WAIT_ADVICE = """
If you are WAITING on something, gate on the RESOURCE, not on a process:
  nvidia-smi --query-gpu=memory.used ... -lt 1000   # the card is free
  [ -f "$done_marker" ]                             # the job said so
  wait "$PID"                                       # you started it, wait for it
  curl -sf localhost:8080/health                    # it is up and answering
A gate on a process NAME or PATTERN hangs two ways, and neither is visible from the command:
your own gate can match the calling shell, and an unrelated long-lived service can hold that
name for as long as the host is up. On one host four processes were called llama-server and
three of them belonged to other services, so `until ! pgrep -x llama-server` never exited at all.
"""

KILL_ADVICE = """
If you are KILLING, in order of preference:
  1. by PID:          SRV=$!   ...   kill "$SRV"
  2. a safe helper: one that resolves pgrep -f matches and then filters out $$, $PPID,
     every ancestor, and harness wrapper shells before killing — it solves the SELF-match;
     choosing a pattern narrow enough to reach only your own is still yours
`pkill -x <name>` is exact in the NAME, not in the OWNER: it stops EVERY process with that
name, whoever started it. It is safe only where the name is unique on this host, so count
before you trust it —
      pgrep -x <name> | wc -l
and it is not unique for llama-server, python3, node, bash or sleep.
"""


def counted_name(verb):
    """The literal argument of `<verb> -x NAME`, or None if there isn't one we can resolve.

    Matched on the MASK so a mention inside quotes is not shell code, but read out of the RAW
    command, because the mask blanks a quoted argument to spaces. The mask is length-preserving,
    so an index into it is an index into the raw text — that is what it is for. The flag is
    matched with a lookahead so the following whitespace is not consumed: a masked quoted name
    IS whitespace in the mask, and a greedy \\s+ would swallow the whole argument.
    """
    m = re.search(r"(?:^|[;&|(!\s])" + verb + r"\s+(?:-\w+\s+)*(?:-\w*x\w*|--exact)(?=\s)", s)
    if not m:
        return None
    lex = shlex.shlex(cmd[m.end():], posix=True)
    lex.whitespace_split = True
    try:
        tok = lex.get_token()
    except ValueError:
        return None
    if not tok:
        return None
    # shlex splits on whitespace only, so `$(pgrep -x foo); do` hands back `foo);` — a shell
    # metacharacter ends the word even with no space before it. Cut there.
    tok = re.split(r"[)(;&|<>`\n]", tok)[0]
    if not tok or tok.startswith("-"):
        return None
    if "$" in tok or "`" in tok or "*" in tok:   # unresolved at hook time; say so, do not guess
        return None
    return tok


def shared_name(name):
    """The processes `pkill -x name` would stop, when that is more than one. pgrep -x is the
    same matcher pkill -x uses, so this count is the command's own blast radius."""
    try:
        r = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True, timeout=5)
    except Exception:
        return None
    pids = [p for p in r.stdout.split() if p.isdigit()]
    if len(pids) < 2:
        return None
    rows = []
    for p in pids[:8]:
        try:
            with open("/proc/%s/cmdline" % p, "rb") as fh:
                line = fh.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except Exception:
            line = "(gone)"
        rows.append("  pid %-8s %s" % (p, line[:110]))
    if len(pids) > 8:
        rows.append("  ... and %d more" % (len(pids) - 8))
    return len(pids), "\n".join(rows)


reason = advice = detail = None

if re.search(r"(^|[;&|(\s])pkill\s+(-\w+\s+)*-\w*f", s):
    reason, advice = "pkill -f", KILL_ADVICE
elif re.search(r"(^|[;&|(\s])killall(\s|$)", s):
    reason, advice = "killall", KILL_ADVICE
elif re.search(r"pgrep\s+(-\w+\s+)*-\w*f", s) and re.search(r"(^|[;&|`(\s])kill(\s|$)", s):
    reason, advice = ("pgrep -f + kill (resolves PIDs by cmdline pattern — matches this shell)",
                      KILL_ADVICE)
elif re.search(r"(^|[;&|(\s])(until|while)\b[^\n]{0,200}?pgrep\s+(-\w+\s+)*-\w*f", s):
    # 2026-08-31: the NON-destructive half of the same bug. `until ... pgrep -f <pat>` never
    # exits when <pat> appears in the caller's own cmdline — the loop waits on itself. Cost a
    # 38-minute stall in tier1.sh, whose own path contained the pattern it was grepping for.
    reason, advice = ("pgrep -f inside an until/while gate (the pattern matches THIS shell, "
                      "so the wait never exits)", WAIT_ADVICE)
elif re.search(r"(^|[;&|(\s])(until|while)\b[^\n;]{0,200}?(^|[;&|(!\s])pgrep\b", s):
    # 2026-09-17: the same gate keyed on a NAME rather than a pattern. It does not match the
    # caller, so the 2026-08-31 arm never saw it; it hangs anyway, because the name is shared.
    # `[^\n;]` rather than the arm above's `[^\n]`: a gate command sits between the keyword and
    # the first `;`, so refusing to cross one keeps `while read l; do …; done; pgrep -x foo` —
    # a loop that merely shares a line with a pgrep — out of this arm. The arm above is left
    # exactly as it was; its behaviour is pinned by the 2026-08-31 case.
    reason, advice = ("a pgrep wait gate keyed on a process NAME (a name this host shares "
                      "between services makes the gate true for ever)", WAIT_ADVICE)
else:
    for verb, needs_kill in (("pkill", False), ("pgrep", True)):
        if needs_kill and not re.search(r"(^|[;&|`(\s])kill(\s|$)", s):
            continue
        name = counted_name(verb)
        if not name:
            continue
        hit = shared_name(name)
        if hit:
            n, rows = hit
            reason = ("%s -x %s reaches %d processes on this host, not one — `-x` is exact in "
                      "the NAME, not in the OWNER" % (verb, name, n))
            detail = "The processes it would stop right now:\n" + rows
            advice = KILL_ADVICE
            break

if reason:
    print("BLOCKED: " + reason + ".")
    if detail:
        print("")
        print(detail)
    print(advice.rstrip())
PY
) || exit 0

[ -n "$verdict" ] || exit 0

printf '%s\n' "$verdict" >&2
exit 2
