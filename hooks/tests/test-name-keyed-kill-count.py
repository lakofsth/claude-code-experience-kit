"""Check: every kill keyed on a process NAME is counted, and refused when the count is over one.

The sentence (hooks/tests/INVARIANTS.md, mh-every-name-keyed-kill-is-counted):

    hooks/block-unsafe-kill.sh counts every kill keyed on a process name (pkill without -f in
    any spelling of its options, and pgrep without -f or pidof whose pids reach a kill) with the
    command's own matcher and selection options, and refuses it when that count is more than one.

Written from the hooks/tests/INVARIANTS.md clause alone. Its directions:

  1. SPELLING  — pkill with no -f is name-keyed however its options are written: bare, with a
                 signal in any of its forms (-9, -KILL, -SIGTERM, --signal X, --signal=X), with
                 -x before or after another option, with `--`. Each is counted and, when it would
                 reach two processes, refused.
  2. MATCHER   — the count uses the command's own matcher. pkill without -x is a REGEX on the
                 name, so `pkill <prefix>` reaches every process whose name holds the prefix;
                 -i makes it case-blind. Counting with an exact match instead under-counts.
  3. PIPE      — pgrep without -f, and pidof, are name-keyed too when their pids reach a kill
                 ($(...), backticks, `| xargs kill`, a for loop).
  4. SELECTION — selection options narrow what the command reaches, and the count honours them:
                 -n / -o / pidof -s select one, -u / -P select by owner or parent. A selection
                 that still reaches two is refused; one that reaches at most one is not.

Fixture: two copies of a uniquely named program of this test's own, stopped by PID afterwards,
plus one solo copy under a second name. Nothing here runs a kill; the hook only reads.
"""
import json, os, shutil, signal, subprocess, sys, tempfile, time
from _proc_names import proc_name, sleeper  # noqa: E402  (per-run comm names: host-wide pgrep must see only this run)

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

# comm is truncated to 15 characters; keep both names short and distinct from the sibling test's.
SHARED = proc_name("mhcnt")
SOLO = proc_name("mhsol")
UID = str(os.getuid())


def verdict(cmd):
    """(fired, stderr) — fired is True iff the hook exited non-zero."""
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


def count(name):
    r = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True)
    return len([x for x in r.stdout.split() if x.isdigit()])


def start(d, name, n):
    exe = os.path.join(d, name)
    shutil.copy2("/bin/sleep", exe)
    procs = [sleeper(exe) for _ in range(n)]
    for _ in range(50):
        if count(name) >= n:
            break
        time.sleep(0.05)
    return procs


S = SHARED

MUST_BLOCK = [
    # 1. SPELLING: pkill without -f, in any spelling of its options
    ("pkill, no options (regex on the name)",     "pkill " + S),
    ("pkill -9",                                  "pkill -9 " + S),
    ("pkill -KILL",                               "pkill -KILL " + S),
    ("pkill -SIGTERM",                            "pkill -SIGTERM " + S),
    ("pkill --signal KILL",                       "pkill --signal KILL " + S),
    ("pkill --signal=KILL -x",                    "pkill --signal=KILL -x " + S),
    ("pkill -x then a signal",                    "pkill -x -9 " + S),
    ("pkill -e -x",                               "pkill -e -x " + S),
    ("pkill -ex, clustered",                      "pkill -ex " + S),
    ("pkill -- name",                             "pkill -- " + S),
    ("pkill, quoted name",                        "pkill '" + S + "'"),
    ("pkill after another command",               "sleep 0; pkill " + S),
    # 2. MATCHER: the command's own matcher, not an exact match standing in for it
    ("pkill regex prefix reaches both",           "pkill " + S[:7]),
    ("pkill anchored regex",                      "pkill '^" + S[:9] + "'"),
    ("pkill -i, case-blind",                      "pkill -i " + S.upper()),
    # 3. PIPE: pgrep without -f, and pidof, whose pids reach a kill
    ("pgrep (regex) into kill $()",               "kill $(pgrep " + S + ")"),
    ("pgrep prefix | xargs kill",                 "pgrep " + S[:7] + " | xargs kill"),
    ("pgrep -i in a for loop into kill",          "for p in $(pgrep -i " + S.upper() + "); do kill \"$p\"; done"),
    ("pgrep -x -u <me> into kill -9",             "kill -9 $(pgrep -x -u " + UID + " " + S + ")"),
    ("pidof into kill $()",                       "kill $(pidof " + S + ")"),
    ("pidof into kill, backticks",                "kill `pidof " + S + "`"),
    ("pidof | xargs kill",                        "pidof " + S + " | xargs kill"),
    ("pidof in a for loop into kill -9",          "for p in $(pidof " + S + "); do kill -9 \"$p\"; done"),
    # 4. SELECTION that still reaches two
    ("pkill -u <me>, both are mine",              "pkill -u " + UID + " " + S),
    ("pkill -u <me> -x",                          "pkill -u " + UID + " -x " + S),
]

MUST_BE_SILENT = [
    # 4. SELECTION that narrows to at most one: counted with the option, so not refused
    ("pkill -n selects the newest only",          "pkill -n " + S),
    ("pkill -o -x selects the oldest only",       "pkill -o -x " + S),
    ("pkill -u root reaches none of these",       "pkill -u root -x " + S),
    ("pkill -P 1 reaches none of these",          "pkill -P 1 -x " + S),
    ("pgrep -n into kill selects one",            "kill $(pgrep -n " + S + ")"),
    ("pidof -s into kill selects one",            "kill $(pidof -s " + S + ")"),
    # 2. MATCHER: exact means exact — a prefix under -x reaches nothing
    ("pkill -x on a prefix reaches nothing",      "pkill -x " + S[:7]),
    # a name that is genuinely unique stays allowed, in every form
    ("pkill on a name one process holds",         "pkill " + SOLO),
    ("pidof a unique name into kill",             "kill $(pidof " + SOLO + ")"),
    ("pgrep a unique name into kill",             "kill $(pgrep -x " + SOLO + ")"),
    # 3. PIPE: no kill, no refusal
    ("pidof with no kill anywhere",               "pidof " + S),
    ("pgrep with no kill anywhere",               "pgrep " + S),
]


def main():
    d = tempfile.mkdtemp(prefix="mh-name-count-")
    procs = start(d, SHARED, 2) + start(d, SOLO, 1)
    failures = []
    try:
        if count(SHARED) != 2 or count(SOLO) != 1:
            print("SETUP FAILED: want 2 x %s and 1 x %s, have %d and %d"
                  % (SHARED, SOLO, count(SHARED), count(SOLO)))
            return 2
        for label, cmd in MUST_BLOCK:
            fired, err = verdict(cmd)
            if not fired:
                failures.append("NOT REFUSED [%s]: %s" % (label, cmd))
            elif "BLOCKED:" not in err:
                failures.append("REFUSED but said nothing useful [%s]: %r" % (label, err[:200]))
        for label, cmd in MUST_BE_SILENT:
            fired, err = verdict(cmd)
            if fired:
                failures.append("FALSE REFUSAL [%s]: %s\n    said: %s"
                                % (label, cmd, err.splitlines()[0] if err else ""))
    finally:
        for p in procs:             # by PID
            try:
                p.send_signal(signal.SIGTERM)
                p.wait(timeout=5)
            except Exception:
                pass
        shutil.rmtree(d, ignore_errors=True)

    total = len(MUST_BLOCK) + len(MUST_BE_SILENT)
    if failures:
        print("FAIL (%d of %d cases)" % (len(failures), total))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d refused + %d silent name-keyed kill cases" % (len(MUST_BLOCK), len(MUST_BE_SILENT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
