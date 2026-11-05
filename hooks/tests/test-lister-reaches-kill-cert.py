"""Check: a pgrep or pidof counts only when its pids reach a kill.

The sentence (hooks/tests/INVARIANTS.md, mh-a-lister-counts-only-when-its-pids-reach-a-kill):

    hooks/block-unsafe-kill.sh treats a pgrep or pidof as choosing what a kill stops only when
    that lister's output reaches the kill -- in the kill's pipeline, in a substitution the kill
    expands, or through a variable, for loop or read the kill expands -- and a lister whose
    output reaches no kill in the command neither causes a refusal nor is named in one.

Written from the hooks/tests/INVARIANTS.md clause alone. Its directions:

  1. REACH      -- each of the five routes the sentence names carries a lister's pids into a
                   kill, for pgrep -f (a pattern), pgrep -x (a shared name) and pidof (a shared
                   name): the kill's pipeline, a substitution the kill expands, a variable the
                   kill expands, a for loop whose variable the kill expands, and a read whose
                   variable the kill expands. Each must still be refused.
  2. NO REACH   -- a lister in the same command as a kill whose output goes somewhere else
                   (stdout, wc, a test, a variable the kill does not expand, a loop or read whose
                   variable the kill does not expand) must not cause a refusal.
  3. NOT NAMED  -- where the command IS refused because one lister reaches its kill, the refusal
                   must name that lister and not another lister in the command that reaches no
                   kill.

Fixture: two copies each of two uniquely named programs of this test's own, stopped by PID
afterwards. Nothing here runs a kill; the hook only reads.
"""
import json, os, shutil, signal, subprocess, sys, tempfile, time
from _proc_names import proc_name, sleeper  # noqa: E402  (per-run comm names: host-wide pgrep must see only this run)

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

# comm is truncated to 15 characters; distinct from the sibling tests' names.
A = proc_name("mhrea")
B = proc_name("mreb")
PAT = "mhreach-no-such-pattern"


def verdict(cmd):
    """(fired, stderr) -- fired is True iff the hook exited non-zero."""
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


MUST_REFUSE = [
    # 1. REACH -- the kill's pipeline
    ("pipe: pgrep -f | xargs kill",              "pgrep -f %s | xargs kill" % PAT),
    ("pipe: pidof | xargs kill -9",              "pidof %s | xargs kill -9" % A),
    ("pipe: pgrep -x | xargs -r kill",           "pgrep -x %s | xargs -r kill" % A),
    ("pipe: pgrep -x | head | xargs kill",       "pgrep -x %s | head -n 5 | xargs kill" % A),
    # 1. REACH -- a substitution the kill expands
    ("subst: kill $(pgrep -f)",                  "kill $(pgrep -f %s)" % PAT),
    ("subst: kill -TERM `pidof`",                "kill -TERM `pidof %s`" % A),
    ("subst: kill \"$(pgrep -x)\"",              "kill \"$(pgrep -x %s)\"" % A),
    ("subst: between other commands",            "echo start; kill $(pidof %s); echo done" % A),
    # 1. REACH -- a variable the kill expands
    ("var: P=$(pgrep -f); kill $P",              "P=$(pgrep -f %s); kill $P" % PAT),
    ("var: P=$(pidof) && kill \"$P\"",           "PIDS=$(pidof %s) && kill \"$PIDS\"" % A),
    ("var: backticks, echoed, kill ${P}",        "P=`pgrep -x %s`; echo \"$P\"; kill -9 ${P}" % A),
    ("var: on separate lines",                   "P=$(pidof %s)\nsleep 1\nkill \"$P\"" % A),
    # 1. REACH -- a for loop the kill expands
    ("for: pgrep -f into kill",                  "for p in $(pgrep -f %s); do kill \"$p\"; done" % PAT),
    ("for: pidof, echo then kill -9",            "for p in $(pidof %s); do echo $p; kill -9 $p; done" % A),
    ("for: backticked pgrep -x",                 "for p in `pgrep -x %s`; do kill $p; done" % A),
    # 1. REACH -- a read the kill expands
    ("read: pgrep -f | while read; kill",        "pgrep -f %s | while read p; do kill \"$p\"; done" % PAT),
    ("read: pidof | tr | while read -r; kill",   "pidof %s | tr ' ' '\\n' | while read -r p; do kill $p; done" % A),
    ("read: done < <(pgrep -x)",                 "while read p; do kill $p; done < <(pgrep -x %s)" % A),
    ("read: read < <(pidof); kill",              "read p < <(pidof %s); kill \"$p\"" % A),
    ("read: pgrep -x | { read; kill; }",         "pgrep -x %s | { read p; kill $p; }" % A),
]

MUST_BE_SILENT = [
    # 2. NO REACH -- a lister beside a kill of a pid captured elsewhere
    ("pgrep -f; kill $SRV",                      "pgrep -f %s; kill \"$SRV\"" % PAT),
    ("pgrep -f >/dev/null && kill",              "pgrep -f %s >/dev/null && kill $SRV" % PAT),
    ("if pgrep -x; then kill $SRV",              "if pgrep -x %s >/dev/null; then kill \"$SRV\"; fi" % A),
    ("pidof | wc -w; kill <pid>",                "pidof %s | wc -w; kill 12345" % A),
    ("kill a pidfile, then pidof",               "kill $(cat \"$TMPDIR/x.pid\"); pidof %s" % A),
    ("kill $!, then pidof",                      "sleep 5 & kill $!; pidof %s" % A),
    ("kill, sleep, pgrep -x || echo",            "kill -TERM \"$SRV\"; sleep 1; pgrep -x %s || echo gone" % A),
    ("pgrep -f | xargs echo; kill",              "pgrep -f %s | xargs echo; kill $SRV" % PAT),
    # 2. NO REACH -- a variable the kill does not expand
    ("var P echoed, kill $SRV",                  "P=$(pgrep -x %s); echo \"$P\"; kill \"$SRV\"" % A),
    ("var N=count, kill $SRV",                   "N=$(pidof %s | wc -w); kill $SRV" % A),
    ("var P, kill $Q",                           "P=$(pidof %s); Q=$SRV; kill \"$Q\"" % A),
    ("var P=$(pgrep -f), kill $SRV",             "P=$(pgrep -f %s); echo $P; kill $SRV" % PAT),
    # 2. NO REACH -- a for loop / read whose variable the kill does not expand
    ("for over pgrep -f echoes; kill after",     "for p in $(pgrep -f %s); do echo \"$p\"; done; kill \"$SRV\"" % PAT),
    ("for over pidof echoes; kill $SRV inside",  "for p in $(pidof %s); do echo $p; done; kill $SRV" % A),
    ("pidof | while read echoes; kill after",    "pidof %s | while read p; do echo \"$p\"; done; kill $SRV" % A),
    ("read < <(pidof) echoed; kill $SRV",        "read p < <(pidof %s); echo $p; kill $SRV" % A),
]

# 3. NOT NAMED -- (label, cmd, a lister that must be named, a lister that must not be)
NAMED = [
    ("pidof A; kill $(pidof B)",                 "pidof %s; kill $(pidof %s)" % (A, B), B, A),
    ("kill $(pidof B); pidof A",                 "kill $(pidof %s); pidof %s" % (B, A), B, A),
    ("pgrep -x A; kill $(pgrep -x B)",           "pgrep -x %s >/dev/null; kill $(pgrep -x %s)" % (A, B), B, A),
    ("pgrep -f; kill $(pidof B)",                "pgrep -f %s >/dev/null; kill $(pidof %s)" % (PAT, B), B, "pgrep -f"),
    ("P=$(pidof A); Q=$(pidof B); kill $Q",      "P=$(pidof %s); Q=$(pidof %s); kill $Q" % (A, B), B, A),
    ("for over A echoes; kill $(pidof B)",       "for p in $(pidof %s); do echo $p; done; kill $(pidof %s)" % (A, B), B, A),
]


def main():
    d = tempfile.mkdtemp(prefix="mh-lister-reach-")
    procs = start(d, A, 2) + start(d, B, 2)
    failures = []
    try:
        if count(A) != 2 or count(B) != 2:
            print("SETUP FAILED: want 2 x %s and 2 x %s, have %d and %d"
                  % (A, B, count(A), count(B)))
            return 2
        for label, cmd in MUST_REFUSE:
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
        for label, cmd, want, unwanted in NAMED:
            fired, err = verdict(cmd)
            first = err.splitlines()[0] if err else ""
            if not fired:
                failures.append("NOT REFUSED [%s]: %s" % (label, cmd))
            elif want not in err or unwanted in err:
                failures.append("NAMED THE WRONG LISTER [%s]: %s\n    want %r, not %r; said: %s"
                                % (label, cmd, want, unwanted, first))
    finally:
        for p in procs:             # by PID
            try:
                p.send_signal(signal.SIGTERM)
                p.wait(timeout=5)
            except Exception:
                pass
        shutil.rmtree(d, ignore_errors=True)

    total = len(MUST_REFUSE) + len(MUST_BE_SILENT) + len(NAMED)
    if failures:
        print("FAIL (%d of %d cases)" % (len(failures), total))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d refused + %d silent + %d named-the-right-lister cases"
          % (len(MUST_REFUSE), len(MUST_BE_SILENT), len(NAMED)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
