"""Check: a name-keyed kill whose selection option takes a value the shell only knows when
it runs is still counted (sentence mh-a-name-kill-filter-held-in-an-expansion-is-counted).

The sentence: where a name-keyed kill that hooks/block-unsafe-kill.sh
counts gives a selection option a value the shell only knows when it runs (`pkill -u $(id -u)
NAME`, `kill $(pgrep -P $X NAME)`, `kill $(pidof -o $$ NAME)`), the hook still counts it: an owner
value that spells the session's own user in the call's own shell is counted as that user, and any
other such value is counted with its option left out, so the count is never smaller than what the
kill can reach.

Written from the hooks/tests/INVARIANTS.md clause alone, not from the implementation. Its directions:

  A. OWNER, OWN USER. An owner option (-u/-U/--euid/--uid, pkill and pgrep) whose value is an
     expansion naming the session's own user ($(id -u), `id -u`, $UID, $EUID, ${UID}, $USER,
     $(whoami), $(id -un), quoted or attached) is counted as that user. Every process of the
     fixture is this test's own, so with two or more live the kill is refused, and its sibling
     reaching one process stays silent (counted as the user: one).
  B. ANY OTHER EXPANDED VALUE is counted with its option left out: -P/--parent, -s, -g, -t, -O,
     -G, an owner value that is not (or not knowably) the session's user, and pidof -o. The
     fixture makes the option-left-out count larger than the runtime reach on purpose: `-P` of a
     parent holding one SHARED child, `-u` of root (which holds none) -- the sentence asks for the
     option-left-out count, so these are refused while the name is held by two or more; their
     one-process siblings stay silent.
  C. THE FEEDERS. The same values inside pgrep / pidof whose pids reach a kill by $( ), backticks
     or a pipe into xargs.

No value is assigned in the command itself (an assignment the hook could read is not a value
"the shell only knows when it runs"); every variable reaches the call from its environment or
from a command substitution.

Fixture, this test's own children only, named per run, stopped by PID: two copies of SHARED under
this process and one more under a python parent of its own (so `-P <that parent>` reaches one),
and one SOLO. THIS CHECK READS THE PROCESS TABLE, SO IT RUNS SERIALLY.
"""
import json, os, pwd, shutil, signal, subprocess, sys, tempfile, time
from _proc_names import TIE_SRC, sleeper, tied

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))
TAG = "%06d" % (os.getpid() % 1000000)
SHARED = "mhxe" + TAG
SOLO = "mhxes" + TAG
USER = pwd.getpwuid(os.getuid()).pw_name


def rows():
    """(label, command template with {N} for the name, direction)."""
    A = [
        ("-u $(id -u)",            "pkill -u $(id -u) {N}"),
        ("-u \"$(id -u)\"",        "pkill -u \"$(id -u)\" {N}"),
        ("-u `id -u`",             "pkill -u `id -u` {N}"),
        ("-u $UID",                "pkill -u $UID {N}"),
        ("-u ${UID}",              "pkill -u ${UID} {N}"),
        ("-u $EUID",               "pkill -u $EUID {N}"),
        ("-u $USER",               "pkill -u $USER {N}"),
        ("-u $(whoami)",           "pkill -u $(whoami) {N}"),
        ("-u $(id -un)",           "pkill -u $(id -un) {N}"),
        ("-U $(id -u)",            "pkill -U $(id -u) {N}"),
        ("--euid=$(id -u)",        "pkill --euid=$(id -u) {N}"),
        ("--uid $UID",             "pkill --uid $UID {N}"),
        ("-u$UID attached",        "pkill -u$UID {N}"),
        ("-x -u $(id -u)",         "pkill -x -u $(id -u) {N}"),
        ("-9 -u $(id -u) -x",      "pkill -9 -u $(id -u) -x {N}"),
        ("pgrep -u $(id -u)->kill", "kill $(pgrep -u $(id -u) {N})"),
        ("pgrep -U $UID | xargs",  "pgrep -U $UID -x {N} | xargs kill"),
    ]
    B = [
        ("-P $MHXE_PARENT",        "pkill -P $MHXE_PARENT {N}"),
        ("-P \"$MHXE_PARENT\"",    "pkill -P \"$MHXE_PARENT\" {N}"),
        ("-P$(cat pf) attached",   "pkill -P$(cat pf) {N}"),
        ("--parent=$(cat pf)",     "pkill --parent=$(cat pf) {N}"),
        ("-P $PPID",               "pkill -P $PPID {N}"),
        ("-P $$",                  "pkill -P $$ {N}"),
        ("-s $MHXE_SID",           "pkill -s $MHXE_SID {N}"),
        ("-g $MHXE_PGID",          "pkill -g $MHXE_PGID {N}"),
        ("-G $(id -g)",            "pkill -G $(id -g) {N}"),
        ("-O $MHXE_AGE",           "pkill -O $MHXE_AGE {N}"),
        ("-t $MHXE_TTY",           "pkill -t $MHXE_TTY {N}"),
        ("-u $MHXE_OTHER (root)",  "pkill -u $MHXE_OTHER {N}"),
        ("-u $(id -u root)",       "pkill -u $(id -u root) {N}"),
        ("-x -P $MHXE_PARENT",     "pkill -x -P $MHXE_PARENT {N}"),
    ]
    C = [
        ("kill $(pgrep -P $X)",    "kill $(pgrep -P $MHXE_PARENT {N})"),
        ("kill `pgrep -P $X`",     "kill `pgrep -P $MHXE_PARENT {N}`"),
        ("pgrep -P $X | xargs",    "pgrep -P $MHXE_PARENT -x {N} | xargs kill"),
        ("kill $(pgrep -s $S -x)", "kill $(pgrep -s $MHXE_SID -x {N})"),
        ("kill $(pidof -o $$)",    "kill $(pidof -o $$ {N})"),
        ("kill $(pidof -o $PPID)", "kill $(pidof -o $PPID {N})"),
        ("kill -9 $(pidof -o $X)", "kill -9 $(pidof -o $MHXE_PARENT {N})"),
        ("pidof -o $$ | xargs",    "pidof -o $$ {N} | xargs kill"),
    ]
    return [(l, t, "A") for l, t in A] + [(l, t, "B") for l, t in B] + [(l, t, "C") for l, t in C]


# Controls: the same options with LITERAL values, which the hook already counted before any fix
# (they show a red row here is red for the expansion, not for the option or the fixture).
def controls(parent):
    return [
        ("literal -u USER",        "pkill -u %s {N}" % USER),
        ("literal pgrep -P",       "kill $(pgrep -P %d {N})" % os.getpid()),
    ]


def verdict(cmd, cwd, env):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       cwd=cwd, env=env, capture_output=True, text=True)
    return p.returncode == 2 and "BLOCKED:" in p.stderr, p.returncode


def count(name):
    r = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True)
    return len([x for x in r.stdout.split() if x.isdigit()])


def main():
    d = tempfile.mkdtemp(prefix="mh-xexp-")
    shared, solo = os.path.join(d, SHARED), os.path.join(d, SOLO)
    shutil.copy2("/bin/sleep", shared); shutil.copy2("/bin/sleep", solo)
    procs = [sleeper(shared) for _ in range(2)]
    procs.append(tied([sys.executable, "-c", TIE_SRC + "import subprocess, sys; "
                       "subprocess.run([sys.argv[1], 'infinity'], preexec_fn=tie)", shared],
                      stderr=subprocess.DEVNULL))
    procs.append(sleeper(solo))
    parent = procs[2].pid
    with open(os.path.join(d, "pf"), "w") as fh:
        fh.write("%d\n" % parent)
    for _ in range(60):
        if count(SHARED) >= 3 and count(SOLO) >= 1:
            break
        time.sleep(0.05)
    env = dict(os.environ, USER=USER, MHXE_PARENT=str(parent), MHXE_SID=str(os.getsid(0)),
               MHXE_PGID=str(os.getpgid(0)), MHXE_AGE="0", MHXE_TTY="pts/0", MHXE_OTHER="root")
    failures, n = [], 0
    try:
        if (count(SHARED), count(SOLO)) != (3, 1):
            print("SETUP FAILED: want 3 x %s, 1 x %s; have %d, %d"
                  % (SHARED, SOLO, count(SHARED), count(SOLO)))
            return 2
        cases = [(l, t, "control") for l, t in controls(parent)] + rows()
        for label, tmpl, direction in cases:
            for name, refuse in ((SHARED, True), (SOLO, False)):
                n += 1
                cmd = tmpl.replace("{N}", name)
                blocked, rc = verdict(cmd, d, env)
                alive = all(p.poll() is None for p in procs)
                if not alive:
                    print("SETUP FAILED: a fixture child died at [%s]" % label)
                    return 2
                mark = "ok" if blocked == refuse else "WRONG"
                print("  %-5s %-7s want=%-6s got=%-6s %-26s %s"
                      % (mark, direction, "refuse" if refuse else "silent",
                         "refuse" if blocked else ("silent" if rc == 0 else "rc%d" % rc),
                         label + ("" if refuse else ", one"), cmd))
                if blocked != refuse:
                    failures.append("%s [%s %s]: %s"
                                    % ("NOT COUNTED (silent with 3 live)" if refuse
                                       else "FALSE REFUSAL (1 live)", direction, label, cmd))
    finally:
        try:
            with open("/proc/%d/task/%d/children" % (parent, parent)) as fh:
                grand = [int(x) for x in fh.read().split()]
        except Exception:
            grand = []
        for pid in grand:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
        for p in procs:
            try:
                p.send_signal(signal.SIGKILL); p.wait(timeout=5)
            except Exception:
                pass
        shutil.rmtree(d, ignore_errors=True)
    if failures:
        print("FAIL (%d of %d rows)" % (len(failures), n))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d rows -- a selection option holding a runtime value never shrinks the count" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
