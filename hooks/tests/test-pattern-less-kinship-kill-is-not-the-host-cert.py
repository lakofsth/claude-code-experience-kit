"""A pattern-less kill whose only uncountable filters are kinship filters with runtime values is not
counted and not refused; every other pattern-less selection still is (hooks/tests/INVARIANTS.md,
mh-a-pattern-less-kinship-kill-is-not-the-host). Written from the hooks/tests/INVARIANTS.md clause alone.

NO PROCESS IS SIGNALLED AND THE PROCESS TABLE IS NOT READ. Every row runs the hook on the command
TEXT with a stub `pgrep` first on PATH that prints 3 pids (this test's own, repeated) and logs its
argv, so "not counted" is observable as "the stub was never asked", and a counted selection always
reaches more than one process.

DIRECTIONS (the ways the sentence can be false)
  S  silent: pattern-less, not inverted, the only filters kinship ones (-P/--parent, -s/--session,
     -g/--pgroup) whose values are known only when the shell runs ($$, $PPID, $BASHPID, "$var",
     ${var}, $(...), `...`), in every spelling (separate, glued, `=`, comma lists, two kinship
     filters together, a signal option beside them) and every route into a kill (pkill, kill
     $(pgrep …), kill `pgrep …`, pgrep | xargs kill, pgrep | while read). Must exit 0 AND the
     matcher must never be asked.
  C  still counted (the "every other" clause, so a fix that silences too much is red here):
     C1 inverted (-v) beside a runtime kinship filter; C2 a kinship filter with a LITERAL value
     (known before the shell runs); C3 a non-kinship filter with a runtime value, alone or beside a
     runtime kinship filter (something other than kinship is left out of the count); C4 a pattern
     present beside a runtime kinship filter (not pattern-less: the name-kill rule). Each must be
     refused (exit 2) and the stub asked.
  Not pinned (ambiguous as written): a runtime kinship filter beside a RESOLVABLE non-kinship
  filter (`pkill -P $$ -u "$USER"`) — it "leaves out of its count only kinship filters", yet its
  selection is not kinship alone; neither verdict is asserted.
"""
import json, os, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.environ.get("HOOK", os.path.join(HERE, "..", "block-unsafe-kill.sh"))

STUB = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\n")
print("\n".join([os.environ["STUB_PID"]] * 3))
"""

SILENT = [
    "pkill -P $$",
    "pkill -P $PPID",
    "pkill -P $BASHPID",
    'pkill -P "$pid"',
    "pkill -P ${pid}",
    "pkill -P$$",
    "pkill --parent $$",
    "pkill --parent=$$",
    "pkill -P $(cat /tmp/kin.pid)",
    "pkill -P `cat /tmp/kin.pid`",
    "pkill -P $$,$PPID",
    "pkill -s $$",
    "pkill -s$$",
    "pkill --session $$",
    "pkill --session=$(ps -o sid= $$)",
    "pkill -g $$",
    "pkill -g$BASHPID",
    "pkill --pgroup $$",
    'pkill --pgroup="$pgid"',
    "pkill -P $$ -s $$",
    "pkill -g $$ --parent $PPID",
    "pkill -9 -P $$",
    "pkill -TERM -P $$",
    "pkill --signal KILL -P $$",
    "pkill -e -P $$",
    "kill $(pgrep -P $$)",
    "kill -9 $(pgrep -P $$)",
    "kill `pgrep -s $$`",
    'kill $(pgrep --parent "$pid")',
    "pgrep -P $$ | xargs kill",
    "pgrep -g $$ | xargs -r kill -TERM",
    "pgrep -P $$ | while read p; do kill $p; done",
    "sleep 1 & pkill -P $$",
]

COUNTED = [
    ("C1", "pkill -v -P $$"),
    ("C1", "pkill -v -s $$"),
    ("C1", "pkill -v --pgroup $$"),
    ("C1", "kill $(pgrep -v -P $$)"),
    ("C2", "pkill -P 1"),
    ("C2", "pkill --parent=1"),
    ("C2", "pkill -s 1"),
    ("C2", "pkill -g 4242"),
    ("C2", "kill $(pgrep -P 1)"),
    ("C2", "pgrep -s 1 | xargs kill"),
    ("C3", "pkill -t $TTY"),
    ("C3", 'pkill -u "$SOMEONE"'),
    ("C3", "pkill -P $$ -t $TTY"),
    ("C3", 'pkill -s $$ -u "$SOMEONE"'),
    ("C3", "kill $(pgrep -P $$ -t $TTY)"),
    ("C4", "pkill -P $$ python3"),
    ("C4", "pkill -s $$ worker"),
    ("C4", "kill $(pgrep -P $$ node)"),
]


def run(d, cmd):
    log = os.path.join(d, "log")
    open(log, "w").close()
    env = dict(os.environ, PATH=os.path.join(d, "bin") + os.pathsep + os.environ["PATH"],
               STUB_LOG=log, STUB_PID=str(os.getpid()), pid="4242", pgid="4242")
    r = subprocess.run(["bash", HOOK], input=json.dumps({"tool_input": {"command": cmd}}),
                       capture_output=True, text=True, env=env, timeout=60)
    calls = [json.loads(l) for l in open(log) if l.strip()]
    return r.returncode, r.stderr, calls


def main():
    d = tempfile.mkdtemp(prefix="kinship-cert-")
    os.mkdir(os.path.join(d, "bin"))
    p = os.path.join(d, "bin", "pgrep")
    with open(p, "w") as fh:
        fh.write(STUB)
    os.chmod(p, 0o755)
    bad, total = [], 0
    for cmd in SILENT:
        total += 1
        rc, err, calls = run(d, cmd)
        if rc != 0 or calls:
            bad.append("S  %-45s rc %d, matcher asked %r: %s"
                       % (cmd, rc, calls, err.strip().splitlines()[0][:140] if err.strip() else ""))
    for tag, cmd in COUNTED:
        total += 1
        rc, err, calls = run(d, cmd)
        if rc != 2 or not calls:
            bad.append("%s %-45s rc %d, matcher asked %r (wanted refused at a count)"
                       % (tag, cmd, rc, calls))
    for b in bad:
        print("  FAIL " + b)
    print("%d of %d rows red" % (len(bad), total))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
