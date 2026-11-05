"""A kill of PID -1 or 0 is refused by the signal its kill really sends: a later -s/-n re-sets it,
the literal targets bash expands or skips blanks in are read, and -n/-o beside a host-wide filter
alone names no process (hooks/tests/INVARIANTS.md, mh-a-whole-account-kill-is-refused).

Read by the first signal word alone, `kill -0 -s KILL -1`, `kill -0 -n 9 -1`, `kill -s 0 -s 9 -1`,
`kill -0 -s KILL 0`, `kill -EXIT -s KILL -1`, `kill -0 -s KILL -- -1`, `/bin/kill -0 -s KILL -- -1`,
`kill -9 {-1,99999}` and `kill -9 ' -1'` would pass while bash signals -1 or the process group;
so would `pkill -n --ns $$` at a count of one.

THE GRAMMAR IS ASKED OF THE TWO KILLS, NOT WRITTEN HERE (derived from the tools, not hand-listed). Every sequence of one or two
signal words drawn from each kind both kills could read -- a bare `-SIG` (number and name), `-s
SIG`, `-n NUM`, glued `-sNAME`/`-nNUM`, `--signal=SIG` and `--signal SIG`, each with a zero signal
and a non-zero one, and `--` -- optionally followed by `--`, then the target -1 or 0, is run as
`kill ...` (bash's builtin) and as `/bin/kill ...` (procps) inside bash_oracle, its own pid
namespace and process group. A victim process there, with every signal blocked, reports whether
any signal reached it; the driver blocks every signal too and drains what it got after each row.
The non-zero signal is USR1 (10), not KILL, so the victim can report it and the driver survives
`kill -1`: which word a kill reads as its signal does not depend on which non-zero signal it names.

  G  every option sequence and target the oracle shows signalling -1 or the group, through
     either kill, is refused by the hook with the whole-account message; every one that BOTH
     kills run to exit 0 with no signal delivered (signal 0 in each) passes the hook. The targets
     are -1, 0 and an ordinary pid no process holds: beside it, a sequence neither kill signals
     -1 or the group with passes the hook, so a signal word a later -s re-sets (`-0 -s TERM P`,
     `-1 --signal TERM P`) is never read as a -1/0 target. `-1` (HUP)
     is among the non-zero signal words for that reason. The hook
     reads `kill` and `/bin/kill` with one function, so each pair is asked of it once, in a
     spelling that signals, alternating between the two command words. A sequence one kill reads as signal 0
     and the other as a signal is refused (the hook does not know which kill runs): those rows
     are counted and printed, not asserted either way.
  L  the literal spellings with KILL and 9, and the literal targets: brace expansion in
     the target or in the signal word, a blank-led quoted target. Each is run in its own oracle
     call (SIGKILL reaches the driver, so its silence is the signal) and must signal; the hook
     must refuse it. Negatives: a QUOTED brace (`'{-1,2}'`, never expanded), braces of ordinary
     pids, braces under signal 0, and `kill -s 9 -s 0 -1` (a later -s 0 sends nothing) -- each
     shown unsignalled by the oracle and passed by the hook.
  F  the same re-read where a kill is fed pids: `kill -0 -s KILL $(pgrep -f X)` is a pattern kill
     (refused), as is `kill -$(echo 9) $(pgrep -f X)` (a signal the shell computes may be any), `kill -0 $(pgrep -f X)` and `kill -s KILL -s 0 $(pgrep -f X)` are probes (pass).
  N  the host-wide filters are DERIVED from `pgrep --help` (every option that takes a value and
     whose description matches or selects, less the kinship ones -- parent, session, process group
     -- and the owner ones -- IDs -- plus the option that modifies --ns) and must equal the hook's
     NEWEST_WIDE. Each, with -n and with -o, a literal and a run-time value, through pkill and
     `kill $(pgrep ...)`, is refused at a stub count of ONE with the stub never asked. Negatives
     at one: a pattern beside it, -P $$, -u "$USER" (a stated limit), a pidfile, no -n/-o.
  O  61 ordinary commands still pass.

Controls: the oracle's controls (`kill -USR1 -1` and `kill -USR1 0` signal, `kill -0 -1` and `kill
12345` do not; `kill -9 -1` signals in L, `kill -0 -1` does not) must read both ways, or the run is
red: a grammar table from an instrument that cannot see a signal proves nothing. Nothing is
signalled outside the namespace: every line a real kill runs goes through bash_oracle; the hook
is given text and stub pgrep/ps/pidof.

    python3 hooks/tests/test-block-unsafe-kill-signal-reread.py      (HOOK=<path> to test another)
"""
import concurrent.futures, json, os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bash_oracle  # noqa: E402

HOOK = os.environ.get("HOOK", os.path.join(HERE, "..", "block-unsafe-kill.sh"))
REAL_PGREP = shutil.which("pgrep") or "/usr/bin/pgrep"
WHOLE_MSG = "every process"
NEWEST_MSG = "newest or oldest"

STUB = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(json.dumps([os.path.basename(sys.argv[0])] + sys.argv[1:]) + "\n")
n = int(open(os.environ["STUB_N_FILE"]).read())
print("\n".join([os.environ["STUB_PID"]] * n))
sys.exit(0 if n else 1)
"""

# Inside the namespace: for each line, a victim with every signal blocked waits for a go; the line
# runs under `bash -c` with the default mask; the victim then reports whether a signal is pending
# (or, for SIGKILL, is gone). The driver blocks every signal and drains its own after each row.
DRIVER = r"""
import json, os, signal, sys
ALL = set(signal.valid_signals()) - {signal.SIGKILL, signal.SIGSTOP}
signal.pthread_sigmask(signal.SIG_BLOCK, ALL)
def drain():
    while signal.sigtimedwait(ALL, 0):
        pass
out = []
for line in json.load(sys.stdin):
    r, w = os.pipe(); go_r, go_w = os.pipe()
    v = os.fork()
    if v == 0:
        os.close(r); os.close(go_w); drain(); os.write(w, b"r")
        os.read(go_r, 1)
        os.write(w, b"1" if signal.sigpending() else b"0"); os._exit(0)
    os.close(w); os.close(go_r); os.read(r, 1)
    k = os.fork()
    if k == 0:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, ALL)
        fd = os.open("/dev/null", os.O_RDWR); os.dup2(fd, 1); os.dup2(fd, 2)
        os.execvp("bash", ["bash", "-c", line])
    _, st = os.waitpid(k, 0)
    os.write(go_w, b"g"); got = os.read(r, 1)
    os.close(r); os.close(go_w); os.waitpid(v, 0); drain()
    out.append([line, got != b"0", os.waitstatus_to_exitcode(st)])
print(json.dumps(out), flush=True)
"""


def oracle(lines):
    """{line: (signalled, exit status)} for lines with a trappable non-zero signal (one call)."""
    p = bash_oracle.run(["python3", "-I", "-c", DRIVER], input=json.dumps(lines),
                        capture_output=True, text=True, timeout=280)
    if p.returncode != 0 or not p.stdout.strip():
        raise RuntimeError("oracle driver failed: exit %d, %r" % (p.returncode, p.stderr[-400:]))
    return {l: (g, rc) for l, g, rc in json.loads(p.stdout)}


def oracle_kill(line):
    """Whether `line` (which may send SIGKILL) signals -1 or the group: its own oracle call, and
    a driver killed before it reports is the signal."""
    p = bash_oracle.run(["python3", "-I", "-c", DRIVER], input=json.dumps([line]),
                        capture_output=True, text=True, timeout=60)
    if not p.stdout.strip():
        return True
    return json.loads(p.stdout)[0][1]


class Hook:
    def __init__(self):
        self.d = tempfile.mkdtemp(prefix="signal-reread-")
        os.mkdir(os.path.join(self.d, "bin"))
        for prog in ("pgrep", "ps", "pidof"):
            p = os.path.join(self.d, "bin", prog)
            with open(p, "w") as fh:
                fh.write(STUB)
            os.chmod(p, 0o755)
        self.k = 0

    def __call__(self, cmd, n=3):
        """(exit status, stderr, stub calls) of the hook on cmd, the stub answering n pids."""
        self.k += 1
        sub = os.path.join(self.d, "r%d" % self.k)
        os.mkdir(sub)
        log, nf = os.path.join(sub, "log"), os.path.join(sub, "n")
        open(log, "w").close()
        with open(nf, "w") as fh:
            fh.write(str(n))
        env = dict(os.environ, PATH=os.path.join(self.d, "bin") + os.pathsep + os.environ["PATH"],
                   STUB_LOG=log, STUB_N_FILE=nf, STUB_PID=str(os.getpid()))
        r = subprocess.run(["bash", HOOK], input=json.dumps({"tool_input": {"command": cmd}}),
                           capture_output=True, text=True, env=env, timeout=120)
        calls = [json.loads(l) for l in open(log) if l.strip()]
        return r.returncode, r.stderr, calls


fails, counts = [], {}


def check(sec, ok, what):
    counts.setdefault(sec, [0, 0])[0 if ok else 1] += 1
    if not ok:
        fails.append("%s  %s" % (sec, what))


# --- G: the grammar, of both kills -----------------------------------------------------------------
ZERO = ["-0", "-EXIT", "-s 0", "-n 0", "-sEXIT", "-n0", "--signal=0", "--signal 0"]
# "-1" (HUP) is a non-zero signal word that also spells a whole-account target: an earlier one
# re-set by a later -s must not be read as a target beside an ordinary pid
SIG = ["-USR1", "-10", "-s USR1", "-n 10", "-sUSR1", "-n10", "--signal=USR1", "--signal USR1", "-1"]
WORDS = ZERO + SIG + ["--"]
SEQS = ([[a] for a in WORDS] + [[a, b] for a in WORDS for b in WORDS]
        + [[a, b, "--"] for a in WORDS for b in WORDS if b != "--"])
KILLS = ("kill", "/bin/kill")
# PID is no process in the oracle's namespace: a kill of it alone signals nothing, so a line that
# signals with it as the only target read a signal word as -1 or 0
PID = "12345"
TARGETS = ("-1", "0", PID)
CONTROLS = {"kill -USR1 -1": True, "kill -USR1 0": True, "kill -0 -1": False, "kill 12345": False,
            "/bin/kill -USR1 12345": False}


def grammar(hook):
    lines = [" ".join([k] + s + [t]) for s in SEQS for t in TARGETS for k in KILLS]
    seen = oracle(list(CONTROLS) + lines)
    ctl = all(seen[l][0] == want for l, want in CONTROLS.items())
    check("G", ctl, "oracle controls misread: %s" % {l: seen[l] for l in CONTROLS})
    if not ctl:
        return
    asks, mixed = [], 0
    for s in SEQS:
        for t in TARGETS:
            pair = [" ".join([k] + s + [t]) for k in KILLS]
            # an ordinary pid exits ESRCH: neither kill signalling -1 or the group is the silent side
            probe = all(not seen[l][0] and (seen[l][1] == 0 or t == PID) for l in pair)
            hits = [l for l in pair if seen[l][0]]
            # the hook reads both spellings with one function; each pair is asked once, of a
            # spelling that signals (alternating where both do), so both command words are asked
            if hits:
                asks.append((hits[len(asks) % len(hits)], True))
            elif probe:
                asks.append((pair[len(asks) % 2], False))
            mixed += any(seen[l][0] for l in pair) and any(
                not seen[l][0] and (seen[l][1] == 0 or t == PID) for l in pair)
    with concurrent.futures.ThreadPoolExecutor(8) as ex:
        got = list(ex.map(lambda a: hook(a[0]), asks))
    pos = sum(1 for _, s in asks if s)
    for (l, signalled), (rc, err, _) in zip(asks, got):
        if signalled:
            check("G", rc == 2 and WHOLE_MSG in err, "%s: the oracle signals -1/0, hook rc %d" % (l, rc))
        else:
            check("G", rc == 0, "%s: neither kill signals -1/0, hook rc %d %s" % (l, rc, err.strip()[:80]))
    print("G: %d grammar lines over %d option sequences; %d sequence+target pairs signal -1/0 in "
          "at least one kill (asked of the hook once each, asserted refused), %d signal neither in "
          "both kills (asked once, asserted silent); %d one kill signals and the other does not "
          "(refused by design)" % (len(lines), len(SEQS), pos, len(asks) - pos, mixed))


# --- L: literal spellings -----------------------------------------------------------------------
LIT_POS = ["kill -0 -s KILL -1", "kill -0 -n 9 -1", "kill -s 0 -s 9 -1", "kill -0 -s KILL 0",
           "kill -EXIT -s KILL -1", "kill -0 -s KILL -- -1", "/bin/kill -0 -s KILL -- -1",
           "kill -9 {-1,99999}", "kill -9 ' -1'", "kill -{9,1}", "kill -9 {-1..0}",
           "kill -9 \" 0\"", "/bin/kill -9 -- ' -1'", "kill -s KILL {12345,-1}"]
LIT_NEG = ["kill -9 '{-1,2}'", "kill -9 {12345,12346}", "kill -0 {-1,0}", "kill -s 9 -s 0 -1",
           "/bin/kill -s 9 -s 0 -- -1"]


def literal(hook):
    ctl_pos, ctl_neg = oracle_kill("kill -9 -1"), oracle_kill("kill -0 -1")
    check("L", ctl_pos and not ctl_neg, "oracle controls misread: kill -9 -1 %s, kill -0 -1 %s"
          % (ctl_pos, ctl_neg))
    if not (ctl_pos and not ctl_neg):
        return
    for l in LIT_POS:
        s = oracle_kill(l)
        rc, err, _ = hook(l)
        check("L", s, "%s: the oracle does not show it signalling -1/0 (a row that proves nothing)" % l)
        check("L", rc == 2 and WHOLE_MSG in err, "%s: hook rc %d" % (l, rc))
    for l in LIT_NEG:
        s = oracle_kill(l)
        rc, err, _ = hook(l)
        check("L", not s, "%s: the oracle shows it signalling (not a negative)" % l)
        check("L", rc == 0, "%s: hook rc %d %s" % (l, rc, err.strip()[:80]))


# --- F: the same reading where a kill is fed pids ------------------------------------------------
def fed(hook):
    for cmd, want in [("kill -0 -s KILL $(pgrep -f srv)", 2), ("kill -0 -n 9 `pgrep -f srv`", 2),
                      ("pgrep -f srv | xargs kill -EXIT -s TERM", 2),
                      ("kill -$(echo 9) $(pgrep -f srv)", 2),   # a run-time signal may be any
                      ("kill -0 $(pgrep -f srv)", 0), ("kill -s KILL -s 0 $(pgrep -f srv)", 0),
                      ("kill -9 -s 0 -- $(pgrep -f srv)", 0)]:
        rc, err, _ = hook(cmd)
        check("F", rc == want, "%s: hook rc %d, want %d %s" % (cmd, rc, want, err.strip()[:80]))


# --- N: -n/-o beside a host-wide filter alone ------------------------------------------------------
def derived_wide():
    out = subprocess.run([REAL_PGREP, "--help"], capture_output=True, text=True, timeout=10).stdout
    rows = []
    for line in out.splitlines():
        m = re.match(r"\s*(?:(-\w), )?(--[\w-]+)( <[^>]+>)?\s+(.*)$", line)
        if m and line.lstrip().startswith("-"):
            rows.append([m.group(1), m.group(2), bool(m.group(3)), m.group(4)])
        elif rows and line.startswith(" " * 10):
            rows[-1][3] += " " + line.strip()
    wide = set()
    for short, long_, arg, desc in rows:
        kin = re.search(r"parent|session|process group", desc)
        owner = "IDs" in desc
        if (arg and re.match(r"(match|select)", desc) and not kin and not owner) or "--ns option" in desc:
            wide |= {o for o in (short, long_) if o}
    return wide, len(rows)


def hook_wide():
    src = open(HOOK).read()
    m = re.search(r"^NEWEST_WIDE = (\{[^}]*\})", src, re.M)
    return set(eval(m.group(1))) if m else set()


def newest(hook):
    wide, n = derived_wide()
    have = hook_wide()
    print("N: pgrep --help gave %d options; host-wide filters derived: %s" % (n, " ".join(sorted(wide))))
    check("N", bool(wide) and wide == have, "derived %s != hook NEWEST_WIDE %s" % (sorted(wide), sorted(have)))
    vals = {"--ns": ["$$", "1"], "--nslist": None, "-t": ["pts/0", "$TTY"], "--terminal": ["pts/0"],
            "--cgroup": ["user.slice", "$CG"], "-r": ["R", "$S"], "--runstates": ["S"],
            "-O": ["10", "$T"], "--older": ["10"]}
    for opt in sorted(wide):
        for v in vals.get(opt) or []:
            for no in ("-n", "-o"):
                for cmd in ("pkill %s %s %s" % (no, opt, v), "kill $(pgrep %s %s %s)" % (no, opt, v)):
                    rc, err, calls = hook(cmd, 1)
                    check("N", rc == 2 and NEWEST_MSG in err and not calls,
                          "%s: hook rc %d, stub asked %s" % (cmd, rc, calls))
    for cmd in ["pkill -n --ns $$ --nslist pid", "pkill --newest --ns $$"]:
        rc, err, calls = hook(cmd, 1)
        check("N", rc == 2 and NEWEST_MSG in err, "%s: hook rc %d" % (cmd, rc))
    for cmd in ["pkill -n foo --ns $$", "pkill -n -P $$", 'pkill -n -u "$USER"', "pkill -n -F x.pid",
                "pkill -n -t pts/0 -x foo", "kill $(pgrep -n -P $$ --ns $$)"]:
        rc, err, _ = hook(cmd, 1)
        check("N", rc == 0, "%s: hook rc %d %s" % (cmd, rc, err.strip()[:80]))


# --- O: ordinary commands -------------------------------------------------------------------------
# Ordinary kills an agent writes, each of which must pass.
ORDINARY = [
    ("kill 12345", 3), ("kill -9 12345", 3), ("kill -TERM 12345 12346", 3), ("kill -0 12345", 3),
    ("kill -l", 3), ("kill -l 15", 3), ("kill -s TERM 12345", 3), ("kill -n 15 12345", 3),
    ("kill -- 12345", 3), ("kill %1", 3), ("kill -9 %1", 3), ("kill -1 12345", 3),
    ("kill -9 $!", 3), ('kill "$(cat x.pid)"', 3), ("kill $(jobs -p)", 3),
    ("trap 'kill $(jobs -p)' EXIT; sleep 1", 3), ("while kill -0 $pid; do sleep 1; done", 3),
    ("kill -0 -1", 3), ("kill -s 0 -1", 3), ("/bin/kill -l", 3), ("/bin/kill -L", 3),
    ("/bin/kill --list", 3), ("/bin/kill --table", 3), ("env kill -0 123", 3),
    ("kill -s HUP $(cat /run/x.pid)", 3),
    ('ps -u "$USER" | grep foo', 3), ('ps -u "$USER" -o pid,comm | head', 3),
    ("ps aux | grep x", 3), ("ps -ef | less", 3), ("ps -o pid= -p 123", 3),
    ("ps -p $pid -o comm= && kill $pid", 3), ('ps -u "$USER" -o pid,cmd && kill $pid', 3),
    ("if ps -p $pid >/dev/null; then kill $pid; fi", 3),
    ('if ps -u "$USER" | grep -q foo; then kill 12345; fi', 3),
    ("kill $(ps -o pid= --ppid $$)", 3), ("kill $(ps -o ppid= -p $$)", 3),
    ("kill $(ps --no-headers -o pid= -p 123)", 3), ("kill $(ps -p123 -o pid=)", 3),
    ("kill $(ps -o pid= -g 4242)", 3), ("kill $(ps -o pid= -s 4242)", 3),
    ("kill $(ps o pid= p 123)", 3), ("kill $(ps -o pid= -t pts/3)", 3),
    ("pgrep -n", 1), ("pgrep -o", 1), ("pgrep -n -f foo", 1), ("pgrep -fn foo", 1),
    ("pkill -n foo", 1), ("pkill -n -x foo", 1), ("kill $(pgrep -n -x foo)", 1),
    ("pkill --exact foo", 1), ("pkill --uid $UID -x foo", 1), ("pgrep --list-full foo", 1),
    ("pkill --signal TERM -x foo", 1), ("pkill --sig TERM -x foo", 1),
    ("pkill --signal=TERM -x foo", 1), ("pkill --pidfile /run/x.pid", 1),
    ("pkill -F /run/x.pid", 1), ("pkill --newest foo", 1), ("pkill --oldest -x foo", 1),
    ("pkill --parent $$", 3), ("pkill --pa $$", 3),
]


def ordinary(hook):
    check("O", len(ORDINARY) == 61, "the ordinary list holds %d, not 61" % len(ORDINARY))
    for cmd, n in ORDINARY:
        rc, err, _ = hook(cmd, n)
        check("O", rc == 0, "%s: hook rc %d %s" % (cmd, rc, err.strip()[:80]))


def main():
    hook = Hook()
    try:
        for part in (grammar, literal, fed, newest, ordinary):
            part(hook)
    finally:
        shutil.rmtree(hook.d, ignore_errors=True)
    for sec in sorted(counts):
        print("%s: %d ok, %d failed" % (sec, *counts[sec]))
    for f in fails[:60]:
        print("FAIL " + f)
    if len(fails) > 60:
        print("... and %d more" % (len(fails) - 60))
    total = sum(a + b for a, b in counts.values())
    print("%d of %d rows failed (hook %s)" % (len(fails), total, os.path.relpath(HOOK)))
    return 1 if fails or not total else 0


if __name__ == "__main__":
    sys.exit(main())
