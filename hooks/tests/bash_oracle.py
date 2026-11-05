"""The one way a hooks test hands code to a real shell: in a namespace where no host process exists.

Sentence `mh-a-hooks-tests-shell-runs-where-no-host-process-can-be-signalled` (hooks/tests/INVARIANTS.md).

WHY. A hooks test asks bash itself how it reads a line (bash is the oracle), and the lines are the
guard's own fixtures: `kill $(pgrep -f X)`, `pkill -f srv`, `eval kill\\ ...`. Run on the host they
are real: run as `bash -c 'pkill(){ echo RAN; }; ' + line` with only pkill shadowed, the line
`eval kill\\ \\$(pgrep\\ -f\\ X)` runs the real pgrep and kill, and X can match an unrelated
process of the same uid. A list of shadowed names misses
whatever it does not name (command kill, /bin/kill, builtin kill, env kill, timeout -s, killall5),
so the fix is where the line runs, not what it may call.

HOW. Every argv goes through `setpriv --pdeathsig KILL unshare --user --map-current-user --pid --fork --mount-proc
--kill-child`: a new pid namespace whose only processes are the ones the line starts, with a /proc
that shows only those. A pid of the host is not addressable from inside (kill(2) answers ESRCH),
pgrep/pidof/killall read the namespace's /proc, `kill -1` reaches only the namespace, and when
unshare dies (a timeout's SIGKILL included) --kill-child takes the namespace's pid 1, and with it
every process inside. The uid and gid read as the caller's (--map-current-user, so `sg` and
`newgrp` to the caller's own group still run their string); the filesystem, cwd, env and stdio
are the caller's, but for HOME (below).

A HOME OF ITS OWN. An interactive shell saves its history to $HOME on exit (bash -i, and a shell
reading its code from stdin, append every fixture line to the history file) and reads its rc
files from there, so with the caller's HOME the fixture lines (`echo RAN >m`, `echo hi`, `echo
STDIN-RAN`) would land in the caller's shell history. INIT makes a
fresh directory and sets HOME to it whenever HOME is unset or is the caller's real home (its
passwd entry), and points HISTFILE and the XDG_*_HOME variables into that HOME when they name a
path under the real home; a caller that sets HOME to a directory of its own keeps it. INIT
removes the directory when it exits; one SIGKILLed first leaves it in $TMPDIR.
Sentence `mh-a-hooks-tests-shell-writes-nothing-under-the-callers-home`.

A PROCESS GROUP OF ITS OWN. A pid namespace does not move its processes out of the caller's host
process group, so `kill 0`, `kill -s KILL 0`, `os.killpg(0, ...)` or `kill -- -PGID` from inside
would signal every host process in that group, and under a suite runner that group is the
runner's. INIT calls
setsid() before it forks the line, so the namespace's processes are in a session and process group
whose leader is INIT (pgid 1, sid 1 as the namespace sees them), and the line has no controlling
terminal. unshare itself stays in the caller's group; it is outside the namespace, so no pid the
line can name reaches it.

IT DIES WITH ITS CALLER. Out of the caller's group, the line no longer gets the signal a runner
sends that group: a suite runner's `timeout -k 10 T` SIGTERMs the section's group, and unshare
blocks SIGTERM while it waits, so only the test would die, timeout would exit 124 without its -k
SIGKILL, and unshare, INIT and the line would run on, holding the runner's `$(...)` open. So PREFIX
starts `setpriv --pdeathsig
KILL`: the kernel SIGKILLs unshare when its parent dies, and --kill-child then takes INIT and the
line. The parent-death signal follows the calling THREAD, not the process: a caller that runs
argv() or run() from a thread that exits before the line ends has the line killed then. And a
caller that dies between its fork and setpriv's prctl leaves an untied unshare (a window of a few
microseconds, not closed here).

PID 1 IS A SMALL REAPER (INIT below), not the line's shell, because a namespace ends when its pid 1
does: a `>(reader)` or a backgrounded stage that on the host outlives the shell by a few ms would
be killed mid-write. INIT runs the argv, keeps its exit status, then waits up to GRACE seconds for
whatever the line left running (orphans are re-parented to pid 1) and exits; anything still alive
then dies with the namespace. One difference from the host stays: a shell killed by signal N reads
as exit 128+N, not -N, because a namespace's init cannot be killed by its own signal.

FAIL-CLOSED. The first call proves the namespace is real (a shell inside is INIT's child, pid 2,
and cannot see the caller's pid in /proc), and that its process group is its own: the shell's
pgid and sid are 1, and its `kill -s WINCH 0` (ignored by default, so benign wherever it lands)
is not pending in the caller, which blocks it for the probe. If it is not, every call raises RuntimeError: the test goes red, and the
line is never run on the host.

    import bash_oracle                      # hooks/tests is on sys.path for a test run from it
    p = bash_oracle.run(["bash", "-c", line], capture_output=True, text=True)
    argv = bash_oracle.argv(["bash", "-c", line])    # for a caller that runs argv itself

`argv()` and `run()` are the only sanctioned homes of a shell-with-code argv in hooks/tests:
hooks/tests/test-bash-oracle-sees-no-host-process.py fails any other.
"""
import os
import shutil
import signal
import subprocess

UNSHARE = shutil.which("unshare") or "/usr/bin/unshare"
GRACE = 2.0
INIT = r"""
import os, pwd, sys, time
# a HOME of its own: an interactive shell (bash -i, a shell reading code from stdin) saves its
# history under $HOME on exit, and reads its rc files from there; the caller's real home is never it
real = os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
scratch = os.path.join(os.environ.get("TMPDIR") or "/tmp", "bash-oracle-home-%d-%s" % (os.getpid(), os.urandom(6).hex()))
os.mkdir(scratch, 0o700)   # os only: tempfile and shutil are slow imports under -I, paid on every call
def under_real(v):
    v = os.path.realpath(v)
    return v == real or v.startswith(real.rstrip("/") + "/")
if not os.environ.get("HOME") or os.path.realpath(os.environ["HOME"]) == real:
    os.environ["HOME"] = scratch
for k, d in (("HISTFILE", ".bash_history"), ("XDG_DATA_HOME", ".local/share"),
             ("XDG_CONFIG_HOME", ".config"), ("XDG_STATE_HOME", ".local/state"),
             ("XDG_CACHE_HOME", ".cache")):
    if os.environ.get(k) and under_real(os.environ[k]):
        os.environ[k] = os.path.join(os.environ["HOME"], d)
os.setsid()   # a session and process group of the namespace's own: `kill 0` reaches no host process
child = os.fork()
if child == 0:
    try:
        os.execvp(sys.argv[1], sys.argv[1:])
    except OSError as e:
        sys.stderr.write("bash_oracle: " + sys.argv[1] + ": " + e.strerror + "\n")
        os._exit(127)
rc, deadline = 1, None
while True:
    try:
        pid, st = os.waitpid(-1, 0 if deadline is None else os.WNOHANG)
    except ChildProcessError:
        break
    if pid == child:
        code = os.waitstatus_to_exitcode(st)
        rc, deadline = (code if code >= 0 else 128 - code), time.monotonic() + GRACE_S
    elif pid == 0:
        if time.monotonic() > deadline:
            break
        time.sleep(0.005)
def rm(d):
    try:
        for e in os.scandir(d):
            if e.is_dir(follow_symlinks=False):
                rm(e.path)
            else:
                os.unlink(e.path)
        os.rmdir(d)
    except OSError:
        pass
rm(scratch)
sys.exit(rc)
""".replace("GRACE_S", repr(GRACE))
SETPRIV = shutil.which("setpriv") or "/usr/bin/setpriv"
PREFIX = (SETPRIV, "--pdeathsig", "KILL", UNSHARE, "--user", "--map-current-user", "--pid", "--fork", "--mount-proc", "--kill-child",
          "--", shutil.which("python3") or "/usr/bin/python3", "-I", "-c", INIT)

_proved = None   # None: not asked yet; "" : proved; otherwise the reason it is not


def _prove():
    global _proved
    if _proved is None:
        # the shell is INIT's first child, pid 2, and the caller's pid is not in its /proc; its
        # process group and session are INIT's (1, 1); and a signal it sends to its own process
        # group does not reach the caller. SIGWINCH is ignored by default, so where the group is
        # the host's it lands harmlessly; the caller blocks it so that it stays pending to be seen.
        probe = ('test "$$" = 2 && ! test -e /proc/%d && set -- $(sed "s/.*) //" /proc/$$/stat) '
                 '&& test "$3 $4" = "1 1" && kill -s WINCH 0 && echo isolated' % os.getpid())
        mine = signal.SIGWINCH not in signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGWINCH})
        try:
            p = subprocess.run(list(PREFIX) + ["/bin/sh", "-c", probe], capture_output=True,
                               text=True, timeout=30, stdin=subprocess.DEVNULL)
            leaked = mine and signal.SIGWINCH in signal.sigpending()
            ok = p.returncode == 0 and p.stdout.strip() == "isolated" and not leaked
            _proved = "" if ok else "exit %d, stdout %r, stderr %r%s" % (
                p.returncode, p.stdout[-200:], p.stderr[-400:],
                ", its process-group signal reached the caller" if leaked else "")
        except (OSError, subprocess.TimeoutExpired) as e:
            _proved = repr(e)
        finally:
            if mine:
                if signal.SIGWINCH in signal.sigpending():
                    signal.sigtimedwait({signal.SIGWINCH}, 0)
                signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGWINCH})
    if _proved:
        raise RuntimeError("bash_oracle: no pid namespace of its own process group here (%s) -- refusing to run a test's "
                           "shell line on the host, where its kill and pgrep are real" % _proved)


def argv(cmd):
    """`cmd` (a full argv: ["bash", "-c", line, ...]) as an argv that runs it in the namespace."""
    _prove()
    return list(PREFIX) + list(cmd)


def run(cmd, **kw):
    """subprocess.run(cmd, **kw), with cmd run in the namespace. The CompletedProcess's .args is
    the prefixed argv; cmd itself is `p.args[len(bash_oracle.PREFIX):]`."""
    return subprocess.run(argv(cmd), **kw)
