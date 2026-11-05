#!/usr/bin/env python3
"""Check of `claude-launch-waits-out-a-missing-binary` (presence/tests/INVARIANTS.md).

claude-launch, finding no claude on PATH but itself, re-scans PATH for up to CLAUDE_LAUNCH_WAIT
seconds and execs the binary that appears; only when none appears does it exit 127.

Why: during npm's reinstall of Claude Code the package directory, and with it the binary, is
briefly absent, and a launch then would print "no claude binary on PATH other than this
launcher" and exit 127.

Rows (each uses a PATH of temp dirs only, with the launcher itself first, and `-p` so no name is
minted):
  1. the binary appears 1.5 s after launch: the launcher execs it (exit 0, its marker printed);
  2. no binary ever: exit 127 after about CLAUDE_LAUNCH_WAIT (2 s), not at once and not much later;
  3. a binary present from the start: exec'd at once, nothing said about waiting (control).
"""
import os, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
LAUNCH = os.path.join(os.path.dirname(HERE), "claude-launch")
FAILS = []


def check(ok, what):
    print("  %s %s" % ("ok  " if ok else "FAIL", what))
    if not ok:
        FAILS.append(what)


def fake(path):
    with open(path + ".tmp", "w") as f:
        f.write("#!/bin/sh\necho REAL-RAN \"$@\"\n")
    os.chmod(path + ".tmp", 0o755)
    os.replace(path + ".tmp", path)


def run(appear_after=None, present=False, wait="2"):
    with tempfile.TemporaryDirectory() as t:
        a, b = os.path.join(t, "a"), os.path.join(t, "b")
        os.mkdir(a); os.mkdir(b)
        os.symlink(LAUNCH, os.path.join(a, "claude"))
        if present:
            fake(os.path.join(b, "claude"))
        timer = None
        if appear_after is not None:
            timer = threading.Timer(appear_after, fake, [os.path.join(b, "claude")])
            timer.start()
        env = {"PATH": "%s:%s:/usr/bin:/bin" % (a, b), "HOME": t, "CLAUDE_LAUNCH_WAIT": wait}
        t0 = time.monotonic()
        try:
            p = subprocess.run([os.path.join(a, "claude"), "-p", "hi"], env=env, capture_output=True,
                               text=True, timeout=30)
        finally:
            if timer:
                timer.cancel(); timer.join()
        return p, time.monotonic() - t0


if not os.path.exists("/usr/bin/claude") and not os.path.exists("/bin/claude"):
    p, dt = run(appear_after=1.5, wait="10")
    check(p.returncode == 0 and "REAL-RAN -p hi" in p.stdout and "waiting" in p.stderr,
          "row 1: a binary that appears 1.5 s in is exec'd (exit %d, %.1fs, out %r, err %r)"
          % (p.returncode, dt, p.stdout[-80:], p.stderr[-160:]))
    p, dt = run(wait="2")
    check(p.returncode == 127 and 1.5 <= dt <= 5,
          "row 2: no binary: exit 127 after about the 2 s wait (exit %d, %.1fs)" % (p.returncode, dt))
    p, dt = run(present=True)
    check(p.returncode == 0 and "REAL-RAN" in p.stdout and "waiting" not in p.stderr and dt < 1.5,
          "row 3: a present binary is exec'd at once (exit %d, %.1fs, err %r)" % (p.returncode, dt, p.stderr[-120:]))
else:
    check(False, "a claude in /usr/bin or /bin would be found by every row; the rows cannot isolate")

if FAILS:
    print("FAIL: %d row(s)" % len(FAILS)); sys.exit(1)
print("PASS")
