"""A kill whose selection is an owner filter alone is counted like any other selection, and refused
when it reaches more than one process (hooks/tests/INVARIANTS.md, mh-a-pattern-less-kill-is-counted).

`pkill -u "$USER"`, `pkill -U $UID`, `kill $(pgrep -u "$USER")` and `pgrep -u <user> | xargs kill`
each select every process of the account; a count that gives up when there is no pattern would let
them pass.

NO PROCESS IS SIGNALLED AND THE PROCESS TABLE IS NOT READ. Every row runs the hook on the command
TEXT with a stub `pgrep` first on PATH. The stub prints STUB_N pids (this test's own pid, repeated:
the hook only reads /proc/<pid>/cmdline for the message) and appends its argv to a log, so each row
also pins WHAT the hook counted with: the owner filter, its value as the session's own user, and
the every-name pattern `.`.

ROWS
  F  each form with the stub selecting 3: refused, with the owner-only
     message, and the stub was asked with the filter and its resolved value. Its control twin, the
     same text with the stub selecting 1: silent (the verdict is the count, not a word ban).
  K  `killall -u "$USER"`: refused (killall is refused structurally, at the base too; it is here
     because it is an owner form too, and killall is installed: /usr/bin/killall is looked for).
  O  another user (`pkill -u root`): counted with `-u root`, refused at 3.
  D  an owner value the hook cannot resolve (handed to `bash -c`, or an unknown variable): counted
     with the filter left out, saying so; under -v, every process (`-v ^$`).
  N  negatives (each beside a twin that goes red with the same stub):
     N1 `pkill -u "$USER" NARROW`: stub at 1 silent, at 3 refused with the NAME message, counted
        with NARROW (the name-kill rule, unchanged); N2 `pgrep -u "$USER"` with no kill
        downstream: silent at 3, and the stub never asked; N3 no criterion at all (`pkill`,
        `pkill -x`, `pkill -v`): silent and not counted (pkill's own usage error);
     N4 everyday commands: the stub is never asked, and the hook's median wall time over them stays
        under the larger of OWNER_ONLY_MEDIAN_MS (default 250) and OWNER_ONLY_BASELINE_X (default
        8) times the median of a SAME-RUN BASELINE: a script run as `bash FILE` that execs python3 to
        read the payload,
        the least any bash hook that hands its payload to python3 can cost, timed interleaved with
        the hook on the same payloads. What the row guards is the guard's added latency on every
        Bash call a session makes (it runs before each one; settings give it no timeout, so the
        harness default applies). bound = max(250 ms, 8 x same-run baseline): on a loaded host both
        numbers inflate together, so the bound follows the baseline instead of reading a busy host
        as a slow guard. Still caught: a hang, and any regression that makes the guard cost more
        than 8 times the bare interpreter start.
"""
import json, os, pwd, shutil, statistics, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.environ.get("HOOK", os.path.join(HERE, "..", "block-unsafe-kill.sh"))
UID = str(os.getuid())
USER = pwd.getpwuid(os.getuid()).pw_name
OWNER_MSG = "names no process"
NAME_MSG = "a process NAME is not an owner"

STUB = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\n")
n = int(open(os.environ["STUB_N_FILE"]).read())
print("\n".join([os.environ["STUB_PID"]] * n))
sys.exit(0 if n else 1)
"""


def setup():
    d = tempfile.mkdtemp(prefix="owner-only-")
    os.mkdir(os.path.join(d, "bin"))
    p = os.path.join(d, "bin", "pgrep")
    with open(p, "w") as fh:
        fh.write(STUB)
    os.chmod(p, 0o755)
    return d


# A script FILE run as `bash FILE`, the shape the hook itself is run in (and not `bash -c CODE`,
# which hooks/tests may hand a shell only through bash_oracle).
BASELINE_SH = "#!/usr/bin/env bash\nexec python3 -c 'import json, sys; json.load(sys.stdin)'\n"


def baseline(d, cmd):
    """Wall time of the least a bash hook that hands its payload to python3 can cost."""
    path = os.path.join(d, "baseline.sh")
    if not os.path.exists(path):
        with open(path, "w") as fh:
            fh.write(BASELINE_SH)
    t = time.monotonic()
    subprocess.run(["bash", path], input=json.dumps({"tool_input": {"command": cmd}}),
                   capture_output=True, text=True, timeout=60)
    return time.monotonic() - t


def run(d, cmd, n):
    log, nf = os.path.join(d, "log"), os.path.join(d, "n")
    open(log, "w").close()
    with open(nf, "w") as fh:
        fh.write(str(n))
    env = dict(os.environ, PATH=os.path.join(d, "bin") + os.pathsep + os.environ["PATH"],
               STUB_LOG=log, STUB_N_FILE=nf, STUB_PID=str(os.getpid()))
    t = time.monotonic()
    r = subprocess.run(["bash", HOOK], input=json.dumps({"tool_input": {"command": cmd}}),
                       capture_output=True, text=True, env=env, timeout=60)
    dt = time.monotonic() - t
    calls = [json.loads(l) for l in open(log) if l.strip()]
    return r.returncode, r.stderr, calls, dt


FORMS = [  # (label, command, the owner option and value the count must carry)
    ("pkill -u \"$USER\"",        'pkill -u "$USER"',                   ("-u", USER)),
    ("pkill -U $UID",             "pkill -U $UID",                      ("-U", UID)),
    ("pkill --euid=$(id -u)",     "pkill --euid=$(id -u)",              ("--euid", UID)),
    ("kill $(pgrep -u \"$USER\")", 'kill $(pgrep -u "$USER")',          ("-u", USER)),
    ("kill `pgrep -U $UID`",      "kill `pgrep -U $UID`",               ("-U", UID)),
    ("pgrep -u USER | xargs kill", "pgrep -u %s | xargs kill" % USER,   ("-u", USER)),
    ("pkill -u \"$USER\" -x",     'pkill -u "$USER" -x',                ("-u", USER)),
    ("pkill -u\"$USER\" glued",   'pkill -u"$USER"',                    ("-u", USER)),
    ("pkill --uid $UID",          "pkill --uid $UID",                   ("--uid", UID)),
    ("pkill -9 -U $UID",          "pkill -9 -U $UID",                   ("-U", UID)),
    ("pgrep -u $(whoami) | while", 'pgrep -u $(whoami) | while read p; do kill $p; done',
                                                                        ("-u", USER)),
]


def has(argv, opt, val):
    return any(argv[i] == opt and argv[i + 1] == val for i in range(len(argv) - 1))


def main():
    d = setup()
    bad, total = [], 0

    def check(label, ok, why):
        nonlocal total
        total += 1
        if not ok:
            bad.append("%s: %s" % (label, why))

    try:
        for label, cmd, (opt, val) in FORMS:
            rc, err, calls, _ = run(d, cmd, 3)
            check("F " + label, rc == 2 and OWNER_MSG in err,
                  "not refused as owner-only (rc %d): %s" % (rc, err.strip()[:200]))
            check("F " + label + " counted", any(has(c, opt, val) and c[-1] == "." and "-x" not in c
                                                 for c in calls),
                  "stub asked %r, wanted %s %s ... ." % (calls, opt, val))
            rc, err, _, _ = run(d, cmd, 1)
            check("F " + label + ", one", rc == 0, "a one-process selection refused: %s"
                  % err.strip()[:200])

        if shutil.which("killall"):
            rc, err, _, _ = run(d, 'killall -u "$USER"', 3)
            check("K killall -u", rc == 2 and "killall" in err, "not refused: rc %d" % rc)
        else:
            print("  note: killall is not installed; row K not run")

        rc, err, calls, _ = run(d, "pkill -u root", 3)
        check("O another user", rc == 2 and any(has(c, "-u", "root") for c in calls),
              "rc %d, stub asked %r" % (rc, calls))

        rc, err, calls, _ = run(d, "bash -c 'pkill -u \"$USER\"'", 3)
        check("D handed to bash -c", rc == 2 and "counted without -u" in err
              and any(c == ["."] for c in calls), "rc %d, asked %r: %s" % (rc, calls, err[:200]))
        rc, err, calls, _ = run(d, 'pkill -u "$SOMEONE"', 3)
        check("D unknown variable", rc == 2 and "counted without -u" in err,
              "rc %d: %s" % (rc, err[:200]))
        rc, err, calls, _ = run(d, 'pkill -v -u "$SOMEONE"', 3)
        check("D inverse, unknown", rc == 2 and any(c == ["-v", "^$"] for c in calls),
              "rc %d, asked %r" % (rc, calls))

        rc, err, calls, _ = run(d, 'pkill -u "$USER" mhnarrow', 1)
        check("N1 narrow name, one", rc == 0, "refused: %s" % err[:200])
        rc, err, calls, _ = run(d, 'pkill -u "$USER" mhnarrow', 3)
        check("N1 narrow name, three", rc == 2 and NAME_MSG in err and OWNER_MSG not in err
              and any(c[-1] == "mhnarrow" and has(c, "-u", USER) for c in calls),
              "rc %d, asked %r: %s" % (rc, calls, err[:200]))

        rc, err, calls, _ = run(d, 'pgrep -u "$USER"', 3)
        check("N2 pgrep alone", rc == 0 and not calls, "rc %d, asked %r" % (rc, calls))

        for cmd in ("pkill", "pkill -x", "pkill -v", "pkill -i -A"):
            rc, err, calls, _ = run(d, cmd, 3)
            check("N3 no criterion: " + cmd, rc == 0 and not calls,
                  "rc %d, asked %r" % (rc, calls))

        everyday = ["ls -la", "git status --short", "echo hello | wc -c",
                    "cd /tmp && python3 -c 'print(1)'", "grep -rn kill hooks | head"]
        times, base = [], []
        for _ in range(3):
            for cmd in everyday:
                rc, err, calls, dt = run(d, cmd, 3)
                times.append(dt)
                base.append(baseline(d, cmd))   # interleaved: the same host, the same moment
                if calls or rc:
                    check("N4 everyday: " + cmd, False, "rc %d, asked %r" % (rc, calls))
        med = statistics.median(times) * 1000
        bmed = statistics.median(base) * 1000
        floor = float(os.environ.get("OWNER_ONLY_MEDIAN_MS", "250"))
        x = float(os.environ.get("OWNER_ONLY_BASELINE_X", "8"))
        limit = max(floor, x * bmed)
        check("N4 median wall time", med < limit,
              "%.0f ms, bound %.0f ms (max of %.0f ms and %g x baseline %.0f ms)"
              % (med, limit, floor, x, bmed))
        print("  everyday median %.0f ms over %d runs; baseline median %.0f ms; bound %.0f ms"
              % (med, len(times), bmed, limit))
    finally:
        shutil.rmtree(d, ignore_errors=True)

    for b in bad:
        print("  FAIL " + b)
    print("%d of %d rows failed" % (len(bad), total))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
