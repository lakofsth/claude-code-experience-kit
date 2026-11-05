"""A name kill filtered by -U (real uid), -G (gid) or any other value-taking option is counted
with the name the tool itself matches (hooks/tests/INVARIANTS.md, mh-every-name-keyed-kill-is-counted).

Ledger D1243: a signal-word test that reads any `-` plus a capital as a signal drops -U/-G/-P/-F,
and their ARGUMENT is counted as the name, so `pkill -U USER NAME`, `pkill -G GID NAME`, `pkill -U
USER -x NAME` and `pkill -x -U USER NAME` would pass with two processes of NAME live while `pkill
-u USER NAME` is refused.

THE ORACLE IS THE TOOL. Before the hook is asked about a row, the row's own options are put to
the tool with nothing signalled: pkill as `pkill --signal 0 -c ...` (signal 0 signals nothing;
pkill's own count of what it matched -- the grammar of its signal word was measured the same way),
pgrep as `pgrep -c ...`, killall as `killall -s 0 ...`. A row whose oracle disagrees with the
fixture it was written for is a SETUP failure, not a verdict. Then: a row whose tool reaches two
or more processes is refused; its control sibling -- the same spelling reaching one process (a name
one process holds, or a filter that narrows to one: -P of a parent with one child) -- keeps the
silent verdict. killall is refused whatever it reaches (block-unsafe-kill.sh's structural arm),
so its rows have no silent sibling; they pin that its -u/-o/-y arguments cannot hide it.

Fixture, this test's own children only, named uniquely per run and stopped by PID: two copies of
SHARED under this process, one more under a /bin/sh of its own (so `-P <that sh>` narrows to one),
and one SOLO. THIS CHECK READS THE PROCESS TABLE, SO IT RUNS SERIALLY: run it alone, never beside
another check that starts processes of a name it counts (a suite runner runs checks one at a time).
"""
import json, os, pty, pwd, grp, shlex, shutil, signal, subprocess, sys, tempfile, time
from _proc_names import TIE_SRC, sleeper, tied  # every sleeper lives as long as this test

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))
TAG = "%06d" % (os.getpid() % 1000000)
SHARED = "mhug" + TAG            # 10 chars: under the 15 of comm, and no substring of SOLO
SOLO = "mhugs" + TAG
ME = str(os.getpid())
UID, GID = str(os.getuid()), str(os.getgid())
USER = pwd.getpwuid(os.getuid()).pw_name
GROUP = grp.getgrgid(os.getgid()).gr_name
SID, PGID = str(os.getsid(0)), str(os.getpgid(0))
TTYTWO = "mhut" + TAG          # two of these, and one TTYONE, under a controlling tty of their own
TTYONE = "mhuto" + TAG


def rows(sh_pid, tty):
    S, O, SH = SHARED, SOLO, str(sh_pid)
    TS, TO = TTYTWO, TTYONE
    pk = lambda *a: ("pkill",) + a
    pg = lambda *a: ("pgrep",) + a
    ka = lambda *a: ("killall",) + a
    # (label, tool argv, how the command is written around it, refused?)
    return [
        # the -U and -G spellings, and their one-process siblings
        ("uid -U USER",            pk("-U", USER, S),            None, True),
        ("uid -U USER, one",       pk("-U", USER, O),            None, False),
        ("gid -G GID",             pk("-G", GID, S),             None, True),
        ("gid -G GID, one",        pk("-G", GID, O),             None, False),
        ("U4 -U USER -x",         pk("-U", USER, "-x", S),      None, True),
        ("U4 -U USER -x, one",    pk("-U", USER, "-x", O),      None, False),
        ("U5 -x -U USER",         pk("-x", "-U", USER, S),      None, True),
        ("U5 -x -U USER, one",    pk("-x", "-U", USER, O),      None, False),
        # every other value-taking option of pkill (pkill(1) OPTIONS on procps-ng)
        ("-U UID",                pk("-U", UID, S),             None, True),
        ("-UUSER attached",       pk("-U" + USER, S),           None, True),
        ("-xU USER clustered",    pk("-xU", USER, S),           None, True),
        ("--uid=USER",            pk("--uid=" + USER, S),       None, True),
        ("-G GROUP",              pk("-G", GROUP, S),           None, True),
        ("--group GID",           pk("--group", GID, S),        None, True),
        ("-G 0 reaches none",     pk("-G", "0", "-x", S),       None, False),
        ("-U root reaches none",  pk("-U", "root", "-x", S),    None, False),
        ("-P ME (two children)",  pk("-P", ME, S),              None, True),
        ("-P SH (one child)",     pk("-P", SH, S),              None, False),
        ("--parent ME",           pk("--parent", ME, S),        None, True),
        ("--parent SH",           pk("--parent", SH, S),        None, False),
        ("-s SID",                pk("-s", SID, S),             None, True),
        ("-s SID, one",           pk("-s", SID, O),             None, False),
        ("-g PGID",               pk("-g", PGID, S),            None, True),
        ("-g PGID, one",          pk("-g", PGID, O),            None, False),
        ("-O 0",                  pk("-O", "0", S),             None, True),
        ("-O 0, one",             pk("-O", "0", O),             None, False),
        ("-O 99999 reaches none", pk("-O", "99999", S),         None, False),
        ("-r S",                  pk("-r", "S", S),             None, True),
        ("-r S, one",             pk("-r", "S", O),             None, False),
        ("-u USER",               pk("-u", USER, S),            None, True),
        ("--euid UID",            pk("--euid", UID, S),         None, True),
        # -t TTY: two TS and one TO run under one controlling tty of their own; TTY is "pts/N"
        ("-t TTY (two)",          pk("-t", tty, TS),            None, True),
        ("-t TTY, one",           pk("-t", tty, TO),            None, False),
        ("-tTTY attached",        pk("-t" + tty, TS),           None, True),
        ("-xt TTY clustered",     pk("-xt", tty, TS),           None, True),
        ("--terminal TTY",        pk("--terminal", tty, TS),    None, True),
        ("--terminal=TTY",        pk("--terminal=" + tty, TS),  None, True),
        ("--terminal TTY, one",   pk("--terminal", tty, TO),    None, False),
        ("-t no such tty",        pk("-t", "pts/99999", TS),    None, False),
        ("-t TTY, a name it lacks", pk("-t", tty, S),           None, False),
        ("-term -t TTY",          pk("-term", "-t", tty, TS),   None, True),
        ("pgrep -t into kill",    pg("-t", tty, TS),  "kill $(%s)", True),
        ("pgrep -t, one",         pg("-t", tty, TO),  "kill $(%s)", False),
        # -F PIDFILE: pkill/pgrep read ONE pid from it, so no -F row reaches two processes and none
        # is refused; the rows pin that the file is not the NAME. The files are in the cwd, and
        # `SHARED` is a pidfile named like the processes it must not be counted as.
        ("-F file named NAME, one", pk("-F", S, O),             None, False),
        ("--pidfile file named NAME", pk("--pidfile", S, O),    None, False),
        ("--pidfile=file named NAME", pk("--pidfile=" + S, O),  None, False),
        ("-F attached, named NAME", pk("-F" + S, O),            None, False),
        ("-xF file named NAME",   pk("-xF", S, O),              None, False),
        ("-F pid of one SHARED",  pk("-F", "pf_shared", S),     None, False),
        ("pgrep -F named NAME",   pg("-F", S, O),     "kill $(%s)", False),
        # a signal word, in the spellings pkill reads as one, beside a filter
        ("-term -U USER",         pk("-term", "-U", USER, S),   None, True),
        ("-term -U USER, one",    pk("-term", "-U", USER, O),   None, False),
        ("-9 -G GID",             pk("-9", "-G", GID, S),       None, True),
        ("-hup",                  pk("-hup", S),                None, True),
        ("-usr1",                 pk("-usr1", S),               None, True),
        ("-SIGsegv -x",           pk("-SIGsegv", "-x", S),      None, True),
        ("-usr1, one",            pk("-usr1", O),               None, False),
        # pgrep whose pids reach a kill, with the same filters
        ("pgrep -U into kill",    pg("-U", USER, S),  "kill $(%s)", True),
        ("pgrep -U, one",         pg("-U", USER, O),  "kill $(%s)", False),
        ("pgrep -G -x | xargs",   pg("-G", GID, "-x", S), "%s | xargs kill", True),
        ("pgrep -P SH, one",      pg("-P", SH, S),    "kill $(%s)", False),
        # the all-processes-by-name tool: refused whatever its -u/-o/-y/-g say
        ("killall -u USER",       ka("-u", USER, S),            None, True),
        ("killall -o 0s",         ka("-o", "0s", S),            None, True),
        ("killall -y 1h",         ka("-y", "1h", S),            None, True),
        ("killall -g -u USER",    ka("-g", "-u", USER, S),      None, True),
    ]


def oracle(argv, cwd):
    """How many processes the tool, given these options, would signal -- asked with nothing sent."""
    if argv[0] == "pkill":
        cmd = ["pkill", "--signal", "0", "-c"] + list(argv[1:])
    elif argv[0] == "pgrep":
        cmd = ["pgrep", "-c"] + list(argv[1:])
    else:
        r = subprocess.run(["killall", "-s", "0"] + list(argv[1:]), cwd=cwd, capture_output=True, text=True)
        return 1 if r.returncode == 0 else 0          # killall: matched something, or not
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    out = r.stdout.strip()
    return int(out) if out.isdigit() else -1


def verdict(cmd, cwd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       cwd=cwd, capture_output=True, text=True)
    return p.returncode == 2 and "BLOCKED:" in p.stderr, p.returncode


def count(name):
    r = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True)
    return len([x for x in r.stdout.split() if x.isdigit()])


def main():
    d = tempfile.mkdtemp(prefix="mh-uidgid-")
    shared, solo = os.path.join(d, SHARED), os.path.join(d, SOLO)
    shutil.copy2("/bin/sleep", shared); shutil.copy2("/bin/sleep", solo)
    procs = [sleeper(shared) for _ in range(2)]
    # a parent that is not SHARED, with one SHARED child (no shell: the line is ours, not a fixture)
    procs.append(tied([sys.executable, "-c", TIE_SRC + "import subprocess, sys; "
                       "subprocess.run([sys.argv[1], 'infinity'], preexec_fn=tie)", shared],
                      stderr=subprocess.DEVNULL))
    procs.append(sleeper(solo))
    tshared, tsolo = os.path.join(d, TTYTWO), os.path.join(d, TTYONE)
    shutil.copy2("/bin/sleep", tshared); shutil.copy2("/bin/sleep", tsolo)
    master, slave = pty.openpty()
    tty = os.ttyname(slave)[len("/dev/"):]
    procs.append(tied(                                # one session, one controlling tty: setsid -c
        ["setsid", "-c", sys.executable, "-c", TIE_SRC + "import subprocess, sys; "
         "[p.wait() for p in [subprocess.Popen([a, 'infinity'], preexec_fn=tie) "
         "for a in sys.argv[1:]]]",
         tshared, tshared, tsolo],
        stdin=slave, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    pfdir = os.path.join(d, "pf"); os.mkdir(pfdir)
    for fname, pid in ((SHARED, procs[3].pid), ("pf_shared", procs[0].pid)):
        with open(os.path.join(pfdir, fname), "w") as fh:
            fh.write("%d\n" % pid)
    for _ in range(60):
        if count(SHARED) >= 3 and count(SOLO) >= 1 \
                and count(TTYTWO) >= 2 and count(TTYONE) >= 1:
            break
        time.sleep(0.05)
    setup, failures, n = [], [], 0
    try:
        if (count(SHARED), count(SOLO), count(TTYTWO), count(TTYONE)) != (3, 1, 2, 1):
            print("SETUP FAILED: want 3 x %s, 1 x %s, 2 x %s, 1 x %s; have %d, %d, %d, %d"
                  % (SHARED, SOLO, TTYTWO, TTYONE, count(SHARED), count(SOLO), count(TTYTWO),
                     count(TTYONE)))
            return 2
        for label, argv, shape, refuse in rows(procs[2].pid, tty):
            n += 1
            reach = oracle(argv, pfdir)
            alive = all(p.poll() is None for p in procs)
            want_reach = (reach >= 2) if argv[0] != "killall" else (reach == 1)
            if not alive or want_reach != refuse and argv[0] != "killall" or reach < 0:
                setup.append("ORACLE [%s]: the tool reaches %d, row says %s%s"
                             % (label, reach, "refuse" if refuse else "silent",
                                "" if alive else " (a child died)"))
                continue
            cmd = shlex.join(argv)
            cmd = shape % cmd if shape else cmd
            blocked, rc = verdict(cmd, pfdir)
            mark = "ok" if blocked == refuse else "WRONG"
            print("  %-5s reach=%-2d want=%-6s got=%-6s %-24s %s"
                  % (mark, reach, "refuse" if refuse else "silent",
                     "refuse" if blocked else ("silent" if rc == 0 else "rc%d" % rc), label, cmd))
            if blocked != refuse:
                failures.append("%s [%s]: %s" % ("NOT REFUSED" if refuse else "FALSE REFUSAL",
                                                 label, cmd))
    finally:
        try:                         # the sh's own child, by the pid the kernel lists under it
            with open("/proc/%d/task/%d/children" % (procs[2].pid, procs[2].pid)) as fh:
                grand = [int(x) for x in fh.read().split()]
        except Exception:
            grand = []
        for name in (TTYTWO, TTYONE):     # the tty session's children, by unique name
            r = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True)
            grand += [int(x) for x in r.stdout.split() if x.isdigit()]
        for pid in grand:
            try:
                os.kill(pid, signal.SIGKILL)
            except Exception:
                pass
        for p in procs:              # by PID
            try:
                p.send_signal(signal.SIGKILL); p.wait(timeout=5)
            except Exception:
                pass
        shutil.rmtree(d, ignore_errors=True)
    for s in setup:
        print("SETUP " + s)
    if setup:
        return 2
    if failures:
        print("FAIL (%d of %d rows)" % (len(failures), n))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d rows -- every value-taking filter is read as a filter, in the same run as its "
          "sibling" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
