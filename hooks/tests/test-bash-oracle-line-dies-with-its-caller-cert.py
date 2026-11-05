"""Check of mh-a-hooks-tests-oracle-line-dies-with-its-caller (hooks/tests/INVARIANTS.md).

The sentence: every process `bash_oracle` starts for a hooks test (unshare, the namespace's INIT
and the line) dies when the process that called `bash_oracle.argv(...)` or `bash_oracle.run(...)`
dies, whatever ended it, including a SIGTERM to the caller's process group that the line's own
session does not receive.

Written from the hooks/tests/INVARIANTS.md clause alone.

HOW. Every row starts a sacrificial CALLER: a python in a session and process group of its own
(start_new_session), standing in for a hooks test. The caller hands bash_oracle one line that runs
a SENTINEL (a copy of /bin/sleep under a unique name) for two minutes, by one of the two sanctioned
routes: `bash_oracle.run(...)`, or `subprocess.Popen(bash_oracle.argv(...))` run by the caller
itself. Seen from the host, this test then finds the caller's descendants by their ppid chain:
unshare (the caller's child), INIT (unshare's child), the line's shell (INIT's child) and the
sentinel (the shell's child), each recorded with its start time so a recycled pid is never
mistaken for a survivor. Then the caller is ended, and every recorded process must be gone (absent,
a zombie, or a different process under the same pid) within DEADLINE seconds. Whatever survives is
SIGKILLed by this test afterwards, by recorded pid and start time, so a red run leaves nothing.

DIRECTIONS (each a way the sentence can be false), each by both routes:
  1. the caller is SIGKILLed alone (nothing else is signalled; it cannot clean up);
  2. the caller's PROCESS GROUP is sent SIGTERM -- the sentence's own named case: unshare is in that
     group and receives it, the line's session does not;
  3. the caller's process group is sent SIGHUP (a terminal hang-up reaches the group the same way);
  4. the caller alone is sent SIGTERM (it dies by the default action; unshare is not signalled);
  5. the caller ends by a plain exit (os._exit(0)) while the line still runs -- "whatever ended it"
     includes no signal at all.
Positive controls: before the caller is ended, all four roles are found and alive, so a
green row measured a live tree and not an empty one; and the sentinel is found by its unique name.
"""
import os, random, shutil, signal, subprocess, sys, tempfile, time
from _proc_names import tied  # noqa: E402  (a child in a session of its own dies with this test)

HERE = os.path.dirname(os.path.abspath(__file__))
FAILS = []
DEADLINE = 5.0   # seconds a process may take to die after its caller has; INIT's GRACE is 2 s

CALLER = r"""
import os, subprocess, sys, threading, time
here, exe, route, ending = sys.argv[1:5]
sys.path.insert(0, here)
import bash_oracle
line = "%s 120; true" % exe
if ending == "exit":
    threading.Thread(target=lambda: (time.sleep(float(sys.argv[5])), os._exit(0)), daemon=True).start()
if route == "run":
    bash_oracle.run(["bash", "-c", line], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)
else:
    p = subprocess.Popen(bash_oracle.argv(["bash", "-c", line]), stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p.wait()
"""


def check(ok, what):
    print("  %s %s" % ("ok  " if ok else "FAIL", what))
    if not ok:
        FAILS.append(what)


def stat(pid):
    """(state, ppid, starttime, comm) of a host pid, or None when it does not exist."""
    try:
        with open("/proc/%d/stat" % pid) as f:
            s = f.read()
    except OSError:
        return None
    comm = s[s.index("(") + 1:s.rindex(")")]
    rest = s[s.rindex(")") + 2:].split()
    return rest[0], int(rest[1]), rest[19], comm


def children(ppid):
    out = []
    for d in os.listdir("/proc"):
        if d.isdigit():
            st = stat(int(d))
            if st and st[1] == ppid and st[0] != "Z":
                out.append(int(d))
    return out


def tree_of(caller, tag, timeout=30.0):
    """{role: (pid, starttime, comm)} for unshare, INIT, the line's shell and the sentinel."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        found, cur = {}, caller
        for role in ("unshare", "init", "shell", "sentinel"):
            kids = children(cur)
            if role == "sentinel":
                kids = [k for k in kids if (stat(k) or ("", 0, "", ""))[3] == tag[:15]]
            if len(kids) != 1:
                break
            st = stat(kids[0])
            if not st:
                break
            found[role] = (kids[0], st[2], st[3])
            cur = kids[0]
        if len(found) == 4:
            return found
        time.sleep(0.05)
    return found


def alive(rec):
    pid, start, _ = rec
    st = stat(pid)
    return st is not None and st[2] == start and st[0] != "Z"


def row(exe, tag, route, ending):
    label = "%s, caller ended by %s" % (route, ending)
    argv = [sys.executable, "-I", "-c", CALLER, HERE, exe, route, "exit" if ending == "plain exit" else "signal"]
    if ending == "plain exit":
        argv.append("3")
    caller = tied(argv, start_new_session=True, stdin=subprocess.DEVNULL)
    found = {}
    try:
        found = tree_of(caller.pid, tag)
        if len(found) != 4 or not all(alive(r) for r in found.values()):
            check(False, "%s: control -- the caller's tree (unshare, INIT, shell, sentinel) is found alive "
                  "before it is ended (found %s)" % (label, found))
            return
        if ending == "SIGKILL to the caller":
            os.kill(caller.pid, signal.SIGKILL)
        elif ending == "SIGTERM to the caller":
            os.kill(caller.pid, signal.SIGTERM)
        elif ending == "SIGTERM to the caller's process group":
            os.killpg(caller.pid, signal.SIGTERM)
        elif ending == "SIGHUP to the caller's process group":
            os.killpg(caller.pid, signal.SIGHUP)
        # plain exit: the caller's own thread calls os._exit(0) three seconds in
        try:
            rc = caller.wait(timeout=30)
        except subprocess.TimeoutExpired:
            check(False, "%s: the caller itself did not end" % label)
            return
        end = time.monotonic() + DEADLINE
        while time.monotonic() < end and any(alive(r) for r in found.values()):
            time.sleep(0.05)
        left = sorted("%s pid %d" % (role, r[0]) for role, r in found.items() if alive(r))
        check(not left, "%s (caller rc %s): every process bash_oracle started is gone within %.0f s%s"
              % (label, rc, DEADLINE, "" if not left else " -- still alive: " + ", ".join(left)))
    finally:
        if caller.poll() is None:
            try:
                os.killpg(caller.pid, signal.SIGKILL)
            except OSError:
                pass
            caller.wait()
        for role in ("unshare", "init", "shell", "sentinel"):   # leave nothing behind a red row
            if role in found and alive(found[role]):
                try:
                    os.kill(found[role][0], signal.SIGKILL)
                except OSError:
                    pass


def main():
    T = tempfile.mkdtemp(prefix="bo-dies-")
    try:
        endings = ["SIGKILL to the caller", "SIGTERM to the caller's process group",
                   "SIGHUP to the caller's process group", "SIGTERM to the caller", "plain exit"]
        n = 0
        for route in ("run", "argv"):
            for ending in endings:
                n += 1
                tag = "bodie%d%03d%d" % (os.getpid() % 10000, random.randrange(1000), n)
                exe = os.path.join(T, tag)
                shutil.copy2("/bin/sleep", exe)
                row(exe, tag, route, ending)
    finally:
        shutil.rmtree(T, ignore_errors=True)
    print("%d failure(s)" % len(FAILS))
    return 1 if FAILS else 0


sys.exit(main())
