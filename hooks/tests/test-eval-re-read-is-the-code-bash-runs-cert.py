#!/usr/bin/env python3
"""The code handed on for an `eval`, and the eval's re-read, are the string bash's eval runs.

hooks/tests/INVARIANTS.md `mh-an-eval-is-read-as-the-code-bash-runs`. Written from the hooks/tests/INVARIANTS.md clause alone, with bash as the oracle throughout:

  A. hooks/bash_parse.py parse(): the code an `eval` command hands on is the string bash's eval
     runs -- its argument words' values joined by single spaces, after a leading `--`, with no
     redirection or redirection target among them. Bash's string is taken from bash itself: the
     line is run with `eval` replaced by a function that drops a leading `--` as eval does and
     writes "$*" to a file (bash has already removed the redirections from its words). Rows that
     leave stderr alone are cross-checked against real eval under `set -v`, which echoes the
     string eval parses.
  B. hooks/block-unsafe-kill.sh, where it re-reads the call with the eval spelled as what it
     runs: that code ends where bash's string ends, so a `#` comment or an open quote in it (or
     in a redirection target the string must not hold) does not reach the commands written
     after the eval. Each must-refuse row is first run by bash with pgrep printing a marker pid
     and kill a shim recording its operands: the marker reaches the kill. Its twin with `echo`
     for the kill must stay silent.
"""
import json, os, subprocess, sys, tempfile
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "hooks"))
import bash_parse  # noqa: E402

ENV = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8")
CWD = tempfile.mkdtemp()
red, total = [], 0


def bash(script):
    p = bash_oracle.run(["bash", "--norc", "--noprofile", "-c", script],
                        capture_output=True, cwd=CWD, env=ENV, timeout=20)
    return p.stdout.decode("utf-8", "surrogateescape"), p.stderr.decode("utf-8", "surrogateescape")


def check(name, ok, detail):
    global total
    total += 1
    if not ok:
        red.append(name)
        print("  RED  %s\n       %s" % (name, detail))


# --- A: the code parse() hands on for an eval -------------------------------------------------
OUT = os.path.join(CWD, "eval-string")
E = 'E(){ [ "${1-}" = -- ] && shift; printf %%s "$*" > %s; }; ' % OUT


def bash_eval_string(line):
    """The string bash's eval runs for line (which starts `eval `)."""
    if os.path.exists(OUT):
        os.unlink(OUT)
    bash(E + "E " + line[len("eval "):])
    with open(OUT, encoding="utf-8", errors="surrogateescape") as f:
        return f.read()


def verbose_string(line):
    """Real eval under `set -v`: the first line it writes (stderr, sent to stdout) is the string
    it parses, echoed before any of it runs."""
    out, _ = bash("exec 2>&1; set -v; " + line + "\n")
    return out.split("\n")[0]


A_ROWS = [  # (line, whether stderr is left alone so `set -v` can witness it)
    ('eval "a  b"   c "" d', True),
    ("eval x\\ y $'p\\tq' \"c'd\"", True),
    ("eval -- 'echo one'", True),
    ("eval -- -- echo two", True),
    ("eval -- \"P=\\$(pgrep -f X)\"", True),
    ("eval 'P=$(pgrep -f X)' >/dev/null", True),
    ("eval >/dev/null 'echo  three'", True),
    ("eval echo > out four", True),
    ("eval echo >>out five six", True),
    ("eval echo </dev/null seven", True),
    ("eval echo <<< 'here string' eight", True),
    ("eval echo 3<>rw nine", True),
    ("eval echo >|clob ten", True),
    ("eval echo 1>&2 eleven", True),
    ("eval >/dev/null -- echo twelve", True),
    ("eval 'P=$(pgrep -f X)' 2>/dev/null", False),
    ("eval echo 2>&1 thirteen", False),
    ("eval echo &>/dev/null fourteen", False),
    ("eval 2>/dev/null -- 'echo fifteen'", False),
    ("eval echo 2>'#x' sixteen", False),
    ("eval echo >\"'\" seventeen", False),
    ("eval 'P=$(pgrep -f X) #' 2>err", False),
]

for line, witness in A_ROWS:
    want = bash_eval_string(line)
    if witness:
        seen = verbose_string(line)
        if seen != want:
            print("  ORACLE DISAGREES on %r: E model %r, set -v %r" % (line, want, seen))
            red.append("oracle " + line)
    cmds = [c for c in bash_parse.parse(line) if c.kw is None and c.name == "eval"]
    got = cmds[0].codes if cmds else None
    check("A %s" % line, got == [want], "bash's eval runs %r; bash_parse hands on %r" % (want, got))


# --- B: the hook's re-read of the call ends where bash's string ends --------------------------
SHIM = "pgrep(){ echo 4242; }; kill(){ printf 'KILL<%s>' \"$*\"; }; "


def kill_reached(line):
    out, _ = bash(SHIM + line + "\n")
    return "KILL<4242>" in out


def hook_exit(line):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": line}})
    return subprocess.run(["bash", os.path.join(ROOT, "hooks", "block-unsafe-kill.sh")],
                          input=payload, capture_output=True, text=True, timeout=60,
                          cwd=CWD).returncode


B_ROWS = [
    # a `#` comment at the end of the string
    "eval 'P=$(pgrep -f X) #'; kill $P",
    "eval \"P=\\$(pgrep -f X) #\"; kill \"$P\"",
    "eval 'P=$(pgrep -f X)  # a note'; kill $P",
    "eval 'P=$(pgrep -f X)' '#'; kill $P",
    "eval 'P=$(pgrep -f X)' '#c'; kill $P",
    "eval -- 'P=$(pgrep -f X) #'; kill $P",
    "eval 'P=$(pgrep -f X); Q=$P #'; kill $Q",
    "eval 'P=$(pgrep -f X) #' && kill $P",
    "eval 'P=$(pgrep -f X) #'\nkill $P",
    # a quote the string leaves open (bash runs the first line, then fails on the second)
    "eval $'P=$(pgrep -f X)\\n\\''; kill $P",
    "eval $'P=$(pgrep -f X)\\n\"'; kill $P",
    # a redirection target that is not part of the string, and would comment or quote it
    "eval 'P=$(pgrep -f X)' 2>'#x'; kill $P",
    "eval 2>'#x' 'P=$(pgrep -f X); Q=$P'; kill $Q",
    "eval 'P=$(pgrep -f X)' >\"'\"; kill $P",
    "eval 'P=$(pgrep -f X); Q=$P' 2>'\"'; kill $Q",
]

for line in B_ROWS:
    if not kill_reached(line):
        print("  FIXTURE  bash does not carry the marker to the kill in %r" % line)
        red.append("fixture " + line)
        continue
    rc = hook_exit(line)
    check("B refuse %r" % line, rc == 2, "bash kills what pgrep printed; hook exit %d (want 2)" % rc)
    twin = line.replace("kill ", "echo ")
    rc = hook_exit(twin)
    check("B silent %r" % twin, rc == 0, "no kill in the line; hook exit %d (want 0)" % rc)

print("%d of %d rows red" % (len(red), total))
sys.exit(1 if red else 0)
