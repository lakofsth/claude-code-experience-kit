"""Check of mh-a-hooks-tests-shell-runs-where-no-host-process-can-be-signalled, its
process-group clause (hooks/tests/INVARIANTS.md).

The clause: a line handed to `bash_oracle.argv(...)` / `bash_oracle.run(...)` runs in a session and
process group of its own, so no host process can be signalled by a signal to the line's own
process group either -- not only not by its pid.

WHY A PID NAMESPACE ALONE DOES NOT SAY IT. kill(0, sig) (and killpg(0), and kill(-pgid)) reaches
every member of the caller's process group, and the kernel walks that group by its struct pid,
which knows nothing of namespaces: a line whose process group was inherited from the host test
reaches the test itself, its runner, and every sibling in that group, from inside any pid namespace.

HOW, WITHOUT HURTING THE HOST WHEN IT IS RED. Every row runs in a sacrificial CALLER: a python
started in a session and process group of its own (start_new_session), which plays the hooks test.
It records every catchable signal it receives, starts a SENTINEL (a copy of /bin/sleep under a
unique name) in its own process group, hands one line to bash_oracle, and reports whether it was
signalled and whether the sentinel is alive and not stopped. When the clause does not hold the
damage stops at that caller's group, which this test then kills; this test's own group is never
the line's.

DIRECTIONS (each a way the clause can be false):
  1. the line signals its own process group, by every spelling of "my group": kill 0, builtin /
     command / env / /bin/kill 0, the eval'd form, kill -- -<my pgid as I read it>, python's
     os.kill(0) and os.killpg(0) and os.killpg(os.getpgrp()), SIGHUP and SIGSTOP as well as SIGTERM;
  2. by both sanctioned routes: bash_oracle.run(...) and a caller that runs bash_oracle.argv(...)
     itself;
  3. a straggler the line leaves running (re-parented to the namespace's pid 1) that signals the
     group after the shell has exited;
  4. structurally, seen from the host: the line's process group and session are not the caller's.
Positive control: a host python child of the caller doing os.kill(0, SIGTERM) does reach the
caller and the sentinel, so a green row is a measurement and not blindness.
"""
import json, os, random, shutil, signal, subprocess, sys, tempfile, time
from _proc_names import tied  # noqa: E402  (a child in a session of its own dies with this test)

HERE = os.path.dirname(os.path.abspath(__file__))
FAILS = []


def check(ok, what):
    print("  %s %s" % ("ok  " if ok else "FAIL", what))
    if not ok:
        FAILS.append(what)


CALLER = r"""
import ctypes, json, os, signal, subprocess, sys, time
here, exe, route, line, line_timeout = sys.argv[1:6]
line_timeout = float(line_timeout)
sys.path.insert(0, here)
got = []
for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT, signal.SIGUSR1, signal.SIGQUIT):
    signal.signal(s, lambda n, f: got.append(signal.Signals(n).name))
def tie():
    ctypes.CDLL(None).prctl(1, 9)
sentinel = subprocess.Popen([exe, "infinity"], preexec_fn=tie, stdin=subprocess.DEVNULL)
time.sleep(0.1)
me = {"pgid": os.getpgrp(), "sid": os.getsid(0)}
seen = None
err = ""
try:
    if route == "control":
        subprocess.run([sys.executable, "-c", "import os, signal; os.kill(0, signal.SIGTERM)"])
    elif route == "run":
        import bash_oracle
        bash_oracle.run(["bash", "-c", line], stdin=subprocess.DEVNULL, timeout=line_timeout,
                        capture_output=True)
    elif route == "argv":
        import bash_oracle
        p = subprocess.Popen(bash_oracle.argv(["bash", "-c", line]), stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            p.wait(timeout=line_timeout)
        except subprocess.TimeoutExpired:
            p.kill(); p.wait()
            raise
    elif route == "observe":
        import bash_oracle
        tag = sys.argv[6]
        p = subprocess.Popen(bash_oracle.argv(["bash", "-c", line]), stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(200):
            r = subprocess.run(["pgrep", "-f", "^" + tag], capture_output=True, text=True)
            pids = [int(x) for x in r.stdout.split()]
            if pids:
                stat = open("/proc/%d/stat" % pids[0]).read()
                f = stat[stat.rindex(")") + 2:].split()
                seen = {"pid": pids[0], "pgid": int(f[2]), "sid": int(f[3])}
                break
            time.sleep(0.02)
        p.wait(timeout=30)
except subprocess.TimeoutExpired as e:
    err = "line-timeout: " + repr(e)[:200]
except Exception as e:
    err = repr(e)[:300]
time.sleep(0.4)
try:
    state = [l for l in open("/proc/%d/status" % sentinel.pid) if l.startswith("State:")][0].split()[1]
except (OSError, IndexError):
    state = "gone"
sentinel.kill(); sentinel.wait()
print(json.dumps({"signals": got, "sentinel": state, "me": me, "seen": seen, "err": err}))
"""


def ask(exe, route, line, extra=(), line_timeout=30):
    """Run one caller in a session of its own; its report, or what became of it."""
    p = tied([sys.executable, "-c", CALLER, HERE, exe, route, line, str(line_timeout)]
             + list(extra),
             start_new_session=True, stdin=subprocess.DEVNULL,
             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, errs = p.communicate(timeout=40)
    except subprocess.TimeoutExpired:
        for s in (signal.SIGCONT, signal.SIGKILL):
            try:
                os.killpg(p.pid, s)
            except OSError:
                pass
        p.communicate()
        return {"fate": "the caller never returned (stopped or hung) -- killed after 40 s"}
    try:
        os.killpg(p.pid, signal.SIGKILL)   # whatever the row left in that group
    except OSError:
        pass
    try:
        rep = json.loads(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"fate": "the caller died, exit %s, stderr %r" % (p.returncode, errs[-300:])}
    rep["fate"] = "returned"
    return rep


def unharmed(rep, self_stops=False):
    """No host process was reached: the caller returned (so it was not stopped), caught no signal,
    and its sentinel is alive and not stopped. A SIGSTOP row's line stops ITSELF where the clause
    holds (it is in its own group, inside the namespace), so the caller's wait on it times out and
    the namespace is torn down; that is the line's own fate, not a host process's, and is allowed
    on those rows alone. Every other row must also return without error, so a line that never got
    as far as its kill cannot read as a pass."""
    err_ok = (not rep.get("err")) or (self_stops and rep["err"].startswith("line-timeout:"))
    return (rep.get("fate") == "returned" and rep["signals"] == [] and rep["sentinel"] in ("S", "R", "D")
            and err_ok)


def main():
    T = tempfile.mkdtemp(prefix="bo-pgrp-")
    try:
        tag = "bopg%d%04d" % (os.getpid() % 100000, random.randrange(10 ** 4))
        exe = os.path.join(T, tag)
        shutil.copy2("/bin/sleep", exe)

        print("control: a host child signalling its group reaches the caller and the sentinel")
        rep = ask(exe, "control", "")
        check(rep.get("fate") == "returned" and "SIGTERM" in rep.get("signals", [])
              and rep.get("sentinel") in ("Z", "gone"),
              "control: os.kill(0, SIGTERM) on the host is seen (%s)" % rep)

        rows = [
            ("kill -TERM 0", "run", "kill -TERM 0; sleep 0.2"),
            ("builtin kill -TERM 0", "run", "builtin kill -TERM 0; sleep 0.2"),
            ("command kill -TERM 0", "run", "command kill -TERM 0; sleep 0.2"),
            ("/bin/kill -TERM 0", "run", "/bin/kill -TERM 0; sleep 0.2"),
            ("env kill -TERM 0", "run", "env kill -TERM 0; sleep 0.2"),
            ("eval'd kill 0", "run", "eval kill\\ -TERM\\ 0; sleep 0.2"),
            ("kill -- -<own pgid as read>", "run",
             "g=$(ps -o pgid= -p $$ | tr -d ' '); kill -TERM -- -\"$g\"; sleep 0.2"),
            ("kill -HUP 0", "run", "kill -HUP 0; sleep 0.2"),
            ("kill -USR1 0", "run", "kill -USR1 0; sleep 0.2"),
            ("kill -STOP 0", "run", "kill -STOP 0; sleep 0.2"),
            ("python os.kill(0)", "run", "python3 -c 'import os; os.kill(0, 15)'; sleep 0.2"),
            ("python os.killpg(0)", "run", "python3 -c 'import os; os.killpg(0, 15)'; sleep 0.2"),
            ("python os.killpg(getpgrp())", "run",
             "python3 -c 'import os; os.killpg(os.getpgrp(), 15)'; sleep 0.2"),
            ("kill -TERM 0 via bash_oracle.argv", "argv", "kill -TERM 0; sleep 0.2"),
            ("kill -STOP 0 via bash_oracle.argv", "argv", "kill -STOP 0; sleep 0.2"),
            ("a straggler signals the group after the shell exits", "run",
             "(sleep 0.3; kill -TERM 0) & exit 0"),
        ]
        print("1. a line that signals its own process group reaches no host process")
        for label, route, line in rows:
            stops = "-STOP" in line
            rep = ask(exe, route, line, line_timeout=8 if stops else 30)
            check(unharmed(rep, self_stops=stops), "%s: the caller is not signalled and the sentinel lives (%s)"
                  % (label, {k: rep.get(k) for k in ("fate", "signals", "sentinel", "err")}))

        print("2. seen from the host, the line's process group and session are not the caller's")
        otag = tag + "ob"
        rep = ask(exe, "observe", "(exec -a %s sleep 3) & sleep 1" % otag, [otag])
        seen, me = rep.get("seen"), rep.get("me")
        check(rep.get("fate") == "returned" and seen is not None,
              "the line's process is found on the host (%s)" % rep)
        if seen and me:
            check(seen["pgid"] != me["pgid"],
                  "its process group (%d) is not the caller's (%d)" % (seen["pgid"], me["pgid"]))
            check(seen["sid"] != me["sid"],
                  "its session (%d) is not the caller's (%d)" % (seen["sid"], me["sid"]))
    finally:
        shutil.rmtree(T, ignore_errors=True)
    print("%d failure(s)" % len(FAILS))
    return 1 if FAILS else 0


sys.exit(main())
