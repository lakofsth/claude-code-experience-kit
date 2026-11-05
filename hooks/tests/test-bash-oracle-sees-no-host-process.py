"""Check of mh-a-hooks-tests-shell-runs-where-no-host-process-can-be-signalled (hooks/tests/INVARIANTS.md).

The sentence: every hooks test that hands code to a real shell on its argv (a `-c` string, or
`shell=True`, `os.system`, `os.popen`, `subprocess.getoutput`) runs it through
hooks/tests/bash_oracle.py, where no host process can be listed or signalled.

TWO HALVES.
  1. THE HELPER. A sentinel (a copy of /bin/sleep under a unique name) is started on the host, and
     each row hands bash_oracle one line that lists or signals it by every route a per-file list
     of shadowed commands misses (kill, command kill, builtin kill, /bin/kill, env kill,
     pkill, killall, a pgrep fed to kill, `eval kill\\ \\$(pgrep\\ -f\\ X)` with pkill
     shadowed, python's os.kill, systemctl --user stop of a unit). Each row has a fresh sentinel,
     which must be alive and not stopped afterwards, and a `pgrep -f` inside must print nothing,
     beside a positive control: the same pgrep on the host finds it. And a line still running
     when its caller's timeout fires leaves no process behind. And a line that signals its own
     process group (`kill -9 0`, `kill -0 -s KILL 0`, `os.killpg(0, 9)`, `kill -- -PGID`) reaches
     no host process: run from a child of this test in a session of its own, the child and a
     sentinel in its group survive.
  2. THE GUARD. Every hooks/tests/*.py but the helper is parsed and walked (ast), and every argv
     display that gives a shell code on its argv must sit inside the first argument of
     `bash_oracle.argv(...)` or `bash_oracle.run(...)`. Shell names are /etc/shells' basenames and
     bash_parse.SHELLS. An argv display is flagged when it holds a shell name followed by a short
     option cluster holding `c`; or when its first element is not a string constant (and is not
     `sys.executable`) and it holds such a cluster; or when it starts with one (a tail spliced
     onto a shell argv). `shell=` other than False, os.system, os.popen, subprocess.getoutput and
     getstatusoutput are flagged wherever they stand, and so are os.exec*/os.spawn* calls whose
     positional arguments read as such an argv. One fixture per flagged form, each beside its
     routed twin, and the non-shell forms the corpus uses (`[sys.executable, "-c", ...]`,
     `["pgrep", "-c", ...]`, `["bash", HOOK]`) as controls that must pass.

ONE-SIDED. The guard promises refusal on that lexical class and nothing more: an argv whose `-c`
arrives in a variable, a shell given its code on stdin or in a script file, is not read. In the
corpus every `bash <file>` runs a hook under test or a fixed `sleep`.

Why: a fixture line run on the host with only pkill shadowed, such as `eval kill\\ \\$(pgrep\\
-f\\ X)`, runs the real pgrep and kill, and X can match an unrelated process of the same uid.
"""
import ast, glob, os, random, re, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
from _proc_names import sleeper, tied  # noqa: E402  (a sentinel lives as long as this test)
import bash_oracle  # noqa: E402
from bash_parse import SHELLS as PARSE_SHELLS  # noqa: E402

FAILS = []


def check(ok, what):
    print("  %s %s" % ("ok  " if ok else "FAIL", what))
    if not ok:
        FAILS.append(what)


# ---------------------------------------------------------------- 1. the helper

def alive(pid):
    try:
        with open("/proc/%d/status" % pid) as fh:
            state = [l for l in fh if l.startswith("State:")][0]
    except (OSError, IndexError):
        return False
    return state.split()[1] not in ("Z", "T", "t", "X")


def host_pgrep(pattern):
    r = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True)
    return [int(x) for x in r.stdout.split() if x.isdigit()]


def helper_half(T):
    tag = "bo-sentinel-%d-%06d" % (os.getpid(), random.randrange(10 ** 6))
    exe = os.path.join(T, tag)
    shutil.copy2("/bin/sleep", exe)

    def sentinel():
        p = sleeper(exe, start_new_session=True, stdin=subprocess.DEVNULL)
        for _ in range(100):
            if p.pid in host_pgrep(tag):
                return p
            time.sleep(0.02)
        return p

    rows = [
        ("pgrep -f lists nothing", "pgrep -f {R}; echo rc=$?", "rc=1"),
        ("pidof lists nothing", "pidof {T}; echo rc=$?", "rc=1"),
        ("kill PID", "kill -9 {P}", None),
        ("command kill PID", "command kill -9 {P}", None),
        ("builtin kill PID", "builtin kill -9 {P}", None),
        ("/bin/kill PID", "/bin/kill -9 {P}", None),
        ("env kill PID", "env kill -9 {P}", None),
        ("kill -STOP PID", "kill -STOP {P}", None),
        ("kill $(pgrep -f NAME)", "kill -9 $(pgrep -f {R})", None),
        ("pkill -f NAME", "pkill -9 -f {R}", None),
        ("killall NAME", "killall -9 {T}", None),
        ("eval kill of a pgrep, pkill shadowed",
         "pkill(){ echo RAN; }; eval kill\\ -9\\ \\$\\(pgrep\\ -f\\ {R}\\)", None),
        ("python os.kill", "python3 -c 'import os; os.kill({P}, 9)'", None),
    ]  # no `kill -1` row: under a mutant that drops the namespace it would signal the whole uid
    found = host_pgrep(tag)
    check(found == [], "no sentinel is live before the rows (%s)" % found)
    for label, line, want in rows:
        s = sentinel()
        check(s.pid in host_pgrep(tag), "control: the host's pgrep -f finds the sentinel [%s]" % label)
        # {R}: the tag as a pattern its own text does not match, so the bash -c carrying it is not found
        code = line.replace("{T}", tag).replace("{R}", "[%s]%s" % (tag[0], tag[1:])).replace("{P}", str(s.pid))
        try:
            r = bash_oracle.run(["bash", "-c", code], capture_output=True, text=True, timeout=30)
            out = r.stdout.strip()
        except RuntimeError as e:
            out = "REFUSED: %s" % e
        time.sleep(0.15)
        ok = alive(s.pid) and (want is None or out == want)
        check(ok, "%s: the sentinel survives%s (out %r)"
              % (label, "" if want is None else " and it reads %r" % want, out[-160:]))
        s.kill(); s.wait()

    pgrp_rows(tag, exe)

    # systemctl --user stop of a unit: asked where a user manager answers, said so where none does
    env = dict(os.environ)
    rt = "/run/user/%d" % os.getuid()
    if os.path.isdir(rt):
        env.setdefault("XDG_RUNTIME_DIR", rt)
    unit = tag + "-unit"
    r = subprocess.run(["systemd-run", "--user", "--unit=" + unit, exe, "600"], env=env,
                       capture_output=True, text=True)
    if r.returncode != 0:
        print("  not asked: systemctl --user stop (no user manager answers: %s)" % r.stderr.strip()[-120:])
    else:
        try:
            bash_oracle.run(["bash", "-c", "systemctl --user stop %s" % unit], env=env,
                            capture_output=True, text=True, timeout=30)
        except RuntimeError as e:
            print("  " + str(e))
        a = subprocess.run(["systemctl", "--user", "is-active", unit], env=env,
                           capture_output=True, text=True).stdout.strip()
        check(a == "active", "systemctl --user stop of a host unit: it stays active (%s)" % a)
        subprocess.run(["systemctl", "--user", "stop", unit], env=env, capture_output=True)

    # what the line leaves running briefly still finishes, as it would on the host: the namespace
    # ends with its pid 1, so pid 1 is INIT, which waits GRACE seconds for the line's stragglers
    late = os.path.join(T, "late")
    bash_oracle.run(["bash", "-c", "echo x > >(sleep 0.3; cat > %s)" % late], stdin=subprocess.DEVNULL)
    check(os.path.exists(late) and open(late).read() == "x\n",
          "a >( ) reader that outlives the shell by 0.3 s still writes (%s)"
          % (open(late).read() if os.path.exists(late) else "nothing written"))

    # a line still running when the caller's timeout fires leaves nothing behind
    orphan = tag + "-orphan"
    try:
        bash_oracle.run(["bash", "-c", "(exec -a %s sleep 300) & (exec -a %s sleep 300)" % (orphan, orphan)],
                        timeout=1, stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        pass
    except RuntimeError as e:
        print("  " + str(e))
    left = []
    for _ in range(50):
        left = host_pgrep(orphan)
        if not left:
            break
        time.sleep(0.05)
    check(left == [], "a line cut by its caller's timeout leaves no process behind (%s)" % left)
    for pid in left:
        try:
            os.kill(pid, 9)
        except OSError:
            pass

    outer_sigterm_row(tag, T)
    prefix_rows()


def outer_sigterm_row(tag, T):
    """A suite runner (the original's tests/run.sh, not shipped) runs a section as
    `out=$(timeout -k 10 T python3 section.py 2>&1)`. When T
    fires, timeout SIGTERMs the section's process group, and the line is not in it (INIT's
    setsid()). The line must still die with its caller, and the `$(...)` must return near T: a
    line that inherits stdout and outlives its caller holds the pipe open, and the per-check
    timeout no longer bounds the suite."""
    hang = tag + "-hang"
    # a suite runner's own shape, as a script file run on the host (it is the runner, not an oracle line),
    # in a session of its own so that timeout's SIGTERM to its group reaches nothing else
    runner = os.path.join(T, "runner.sh")
    with open(runner, "w") as fh:
        fh.write('out=$(timeout -k 10 2 "$1" "$2" --hang-row "$3" 2>&1); echo "rc=$?"\n')
    t0 = time.monotonic()
    c = tied(["timeout", "60", "bash", runner, sys.executable, os.path.abspath(__file__), hang],
             start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
             stdin=subprocess.DEVNULL)
    out, _ = c.communicate()
    r = subprocess.CompletedProcess(c.args, c.returncode, out, "")
    took = time.monotonic() - t0
    time.sleep(0.3)
    left = host_pgrep(hang)
    check(r.stdout.strip() == "rc=124" and took < 8 and left == [],
          "timeout's SIGTERM to the caller's group: the line dies with its caller and the "
          "$(...) returns in %.1f s, want < 8 (%s; left %s)" % (took, r.stdout.strip(), left))
    for pid in left:
        try:
            os.kill(pid, 9)
        except OSError:
            pass


def hang_child(name):
    """--hang-row: a hooks test whose oracle line inherits its stdout and runs 15 s."""
    bash_oracle.run(["bash", "-c", "exec -a %s sleep 15" % name], stdin=subprocess.DEVNULL)
    return 0


def prefix_rows():
    """Every process bash_oracle starts is built from PREFIX (an AST walk of the helper: each
    subprocess call's argv is argv(...) or starts list(PREFIX)), and PREFIX starts by tying
    unshare to its caller: `setpriv --pdeathsig KILL`."""
    src = open(os.path.join(HERE, "bash_oracle.py"), encoding="utf-8").read()
    calls = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call)
             and re.match(r"^(subprocess|os)\.(run|Popen|call|check_call|check_output|exec|spawn|posix_spawn)",
                          ast.unparse(n.func))]
    check(len(calls) >= 2, "the helper's spawning calls are found (%d)" % len(calls))
    for n in calls:
        a = ast.unparse(n.args[0]) if n.args else ""
        check(a.startswith("argv(") or a.startswith("list(PREFIX)"),
              "bash_oracle.py:%d spawns from PREFIX (%s)" % (n.lineno, a[:60]))
    head = tuple(bash_oracle.PREFIX[1:3])
    check(os.path.basename(bash_oracle.PREFIX[0]) == "setpriv" and head == ("--pdeathsig", "KILL"),
          "PREFIX ties unshare to its caller: %s" % " ".join(bash_oracle.PREFIX[:4]))


PGRP_ROWS = [
    ("kill -9 0", "kill -9 0"),
    ("kill -s KILL 0", "kill -s KILL 0"),
    ("kill -0 -s KILL 0, a group-kill line", "kill -0 -s KILL 0"),
    ("/bin/kill -9 0", "/bin/kill -9 0"),
    ("kill -9 -- -PGID, the pgid read in the line", "kill -9 -- -$(ps -o pgid= -p $$ | tr -d ' ')"),
    ("a background stage's kill -9 0", "(sleep 0.1; kill -9 0) & wait"),
    ("python os.killpg(0)", "python3 -c 'import os; os.killpg(0, 9)'"),
]


def pgrp_child(code, exe):
    """--pgrp-row: run in a session of this test's own making (the parent starts it with
    start_new_session), so a signal to the caller's process group reaches this child, its
    sentinel and nothing else on the host. The sentinel shares this child's process group."""
    s = sleeper(exe, stdin=subprocess.DEVNULL)
    if code == "--host-control":
        # positive control: the same signal sent by a host process of this group; this child must die
        subprocess.run([sys.executable, "-c", "import os; os.kill(0, 9)"])
    else:
        bash_oracle.run(["bash", "-c", code], capture_output=True, text=True, timeout=30,
                        stdin=subprocess.DEVNULL)
    time.sleep(0.15)
    print("sentinel=%s" % ("alive" if alive(s.pid) else "gone"))
    s.kill(); s.wait()
    return 0


def pgrp_rows(tag, exe):
    """A line that signals its own process group (kill 0, killpg(0), kill -- -PGID) must reach no
    host process: the caller (here a child in a session of its own, standing in for the test
    runner's group) and a sentinel in that group both survive."""
    def child(code):
        # tied: in a session of its own it gets no signal sent to this test's group, so it dies
        # with this test instead (a test killed by its timeout leaves no row running)
        c = tied([sys.executable, os.path.abspath(__file__), "--pgrp-row", code, exe],
                 start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                 text=True, stdin=subprocess.DEVNULL)
        try:
            out, err = c.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            c.kill()
            out, err = c.communicate()
        r = subprocess.CompletedProcess(c.args, c.returncode, out, err)
        for pid in host_pgrep(tag):   # a sentinel a killed child left behind
            try:
                os.kill(pid, 9)
            except OSError:
                pass
        return r
    r = child("--host-control")
    check(r.returncode == -9, "control: kill(0, 9) from a host process of the child's group kills "
          "the child (rc %s)" % r.returncode)
    for label, line in PGRP_ROWS:
        r = child(line)
        ok = r.returncode == 0 and r.stdout.strip() == "sentinel=alive"
        check(ok, "%s: the caller and a sentinel in its process group survive (rc %s, out %r, err %r)"
              % (label, r.returncode, r.stdout.strip()[-80:], r.stderr.strip()[-200:]))


# ---------------------------------------------------------------- 2. the guard

def shell_names():
    names = set(PARSE_SHELLS)
    with open("/etc/shells") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("/"):
                names.add(os.path.basename(line))
    return names


SH = shell_names()
CODE_OPT = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")
ROUTED = {"bash_oracle.argv", "bash_oracle.run"}
SHELL_CALLS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput"}


def _consts(elts):
    return [e.value if isinstance(e, ast.Constant) and isinstance(e.value, str) else None for e in elts]


def code_argv(elts):
    """True when this sequence of argv elements gives a shell code on its argv."""
    if not elts:
        return False
    c = _consts(elts)
    for i, x in enumerate(c):
        if x is not None and os.path.basename(x) in SH and any(
                y is not None and CODE_OPT.match(y) for y in c[i + 1:]):
            return True
    has_opt = any(y is not None and CODE_OPT.match(y) for y in c)
    if c[0] is not None and CODE_OPT.match(c[0]):
        return True
    if c[0] is None and has_opt and ast.unparse(elts[0]) != "sys.executable":
        return True
    return False


def violations(src):
    """(lineno, text) of every shell-code site in src that is not inside a routed call's argv."""
    tree = ast.parse(src)
    allowed = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and ast.unparse(n.func) in ROUTED and n.args:
            allowed |= {id(m) for m in ast.walk(n.args[0])}
    out = []
    for n in ast.walk(tree):
        if id(n) in allowed:
            continue
        if isinstance(n, (ast.List, ast.Tuple)) and code_argv(n.elts):
            out.append((n.lineno, ast.unparse(n)[:100]))
        elif isinstance(n, ast.Call):
            fn = ast.unparse(n.func)
            if fn in SHELL_CALLS:
                out.append((n.lineno, fn))
            elif re.match(r"^os\.(exec|spawn|posix_spawn)", fn) and code_argv(n.args):
                out.append((n.lineno, fn))
            for k in n.keywords:
                if k.arg == "shell" and not (isinstance(k.value, ast.Constant) and k.value.value is False):
                    out.append((n.lineno, "shell=%s" % ast.unparse(k.value)))
    return sorted(out)


def routed_count(src):
    return sum(1 for n in ast.walk(ast.parse(src))
               if isinstance(n, ast.Call) and ast.unparse(n.func) in ROUTED)


FLAGGED = [  # (form, the call as a test writes it, its routed twin or None where none is sanctioned)
    ("bash -c", 'subprocess.run(["bash", "-c", x])', 'bash_oracle.run(["bash", "-c", x])'),
    ("bash --norc --noprofile -c", 'subprocess.run(["bash", "--norc", "--noprofile", "-c", x])',
     'bash_oracle.run(["bash", "--norc", "--noprofile", "-c", x])'),
    ("bash -n -c", 'subprocess.run(["bash", "-n", "-c", x])', 'bash_oracle.run(["bash", "-n", "-c", x])'),
    ("/bin/sh -c", 'subprocess.Popen(["/bin/sh", "-c", x])', 'bash_oracle.run(["/bin/sh", "-c", x])'),
    ("sh -lc cluster", 'subprocess.run(["sh", "-lc", x])', 'bash_oracle.run(["sh", "-lc", x])'),
    ("dash -c", 'subprocess.run(("dash", "-c", x))', 'bash_oracle.run(("dash", "-c", x))'),
    ("a runner then sh -c", 'subprocess.run(["setsid", "-c", "/bin/sh", "-c", x])',
     'bash_oracle.run(["setsid", "-c", "/bin/sh", "-c", x])'),
    ("a shell in a variable", 'probe([sh, "-c", x])', 'probe(bash_oracle.argv([sh, "-c", x]))'),
    ("a spliced -c tail", 'argv = [sh] + opts + ["-c", code]\nsubprocess.run(argv)',
     'bash_oracle.run([sh] + opts + ["-c", code])'),
    ("shell=True", 'subprocess.run(x, shell=True)', None),
    ("shell=flag", 'subprocess.run(x, shell=flag)', None),
    ("os.system", 'os.system(x)', None),
    ("os.popen", 'os.popen(x)', None),
    ("subprocess.getoutput", 'subprocess.getoutput(x)', None),
    ("os.execl a shell", 'os.execl("/bin/sh", "sh", "-c", x)', None),
]
PASSING = [
    ("python -c", 'subprocess.run([sys.executable, "-c", x])'),
    ("pgrep -c", 'subprocess.run(["pgrep", "-c", x])'),
    ("pkill --signal 0 -c", 'subprocess.run(["pkill", "--signal", "0", "-c"] + rest)'),
    ("a hook under test", 'subprocess.run(["bash", HOOK], input=payload)'),
    ("a script file", 'subprocess.Popen(["bash", run_sh])'),
    ("shell=False", 'subprocess.run(["ls"], shell=False)'),
]


def guard_half():
    for form, bad, twin in FLAGGED:
        check(len(violations(bad)) >= 1, "guard flags: %s -- %s" % (form, bad.replace("\n", "; ")))
        if twin:
            check(violations(twin) == [], "guard passes its routed twin: %s" % twin)
    for form, good in PASSING:
        check(violations(good) == [], "guard passes a non-shell form: %s -- %s" % (form, good))

    files = sorted(f for f in glob.glob(os.path.join(HERE, "*.py"))
                   if os.path.basename(f) != "bash_oracle.py")
    print("enumeration: %s/*.py but bash_oracle.py -- %d file(s); shell names: %d"
          % (HERE, len(files), len(SH)))
    check(len(files) > 1, "the enumeration is not empty")
    total_routed = 0
    for f in files:
        src = open(f, encoding="utf-8").read()
        v = violations(src)
        r = routed_count(src)
        total_routed += r
        # metamorphic: the same program, re-printed by ast, holds the same sites
        same = len(violations(ast.unparse(ast.parse(src)))) == len(v)
        if v or r or not same:
            print("  %-62s routed=%d unrouted=%d" % (os.path.basename(f), r, len(v)))
        for ln, text in v:
            check(False, "%s:%d hands code to a shell outside bash_oracle: %s"
                  % (os.path.relpath(f, os.path.dirname(os.path.dirname(HERE))), ln, text))
        if not same:
            check(False, "%s: the site count moved when the file was re-printed" % os.path.basename(f))
    print("routed calls across the enumeration: %d" % total_routed)
    check(total_routed > 0, "the guard saw at least one routed call (it is not reading nothing)")


def main():
    T = tempfile.mkdtemp(prefix="bash-oracle-")
    try:
        print("1. the helper (%s, then INIT)" % " ".join(bash_oracle.PREFIX[:11]))
        helper_half(T)
        print("2. the guard")
        guard_half()
    finally:
        shutil.rmtree(T, ignore_errors=True)
    print("%d failure(s)" % len(FAILS))
    return 1 if FAILS else 0


if len(sys.argv) == 3 and sys.argv[1] == "--hang-row":
    sys.exit(hang_child(sys.argv[2]))
if len(sys.argv) == 4 and sys.argv[1] == "--pgrp-row":
    sys.exit(pgrp_child(sys.argv[2], sys.argv[3]))
sys.exit(main())
