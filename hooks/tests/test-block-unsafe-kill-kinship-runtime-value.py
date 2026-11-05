"""A pattern-less kill of a process tree whose root is a run-time value is not counted as the whole
host (hooks/tests/INVARIANTS.md, mh-a-pattern-less-kinship-kill-is-not-the-host).

Counted with the dropped-filter widening, `pkill -P $P`, `pkill -s $P`, `kill $(pgrep -P $$)` and
`trap 'pkill -P $$' EXIT` would be `pgrep .`, every process on the host, and refused naming
/sbin/init, though each reaches only P's children, session or group.

NO PROCESS IS SIGNALLED AND THE PROCESS TABLE IS NOT READ. Every row hands the hook the command
TEXT with a stub `pgrep` first on PATH that prints STUB_N pids and logs the argv it was asked with.

THE KINSHIP OPTIONS ARE DERIVED, NOT LISTED: they are read from the installed `pgrep --help`
(before the stub is put on PATH), as every option whose help line selects by a process relation —
"parent", "session", "process group" — in both its short and long spelling. Real-group (-G) and
namespace (--ns) are not relations of a process to another and are not matched by that reading.

ROWS
  W  five constructed shapes of an agent stopping its own background work: the four whose
     only unresolved filter is kinship pass at a stub count of 3; the fifth, `pgrep -u $(id -u)`
     in a for loop, is an OWNER filter, selects every process of the account and stays refused.
  C  the class: each derived kinship option x separate / glued / = spellings x run-time values
     ($P, "$P", ${P}, $!, $$, $(cat pf)) x carriers (pkill, kill $( ), backticks, xargs, a trap):
     silent at a stub count of 3, and the stub never asked (the count is not taken).
  N  controls, each the C row `pkill -P $P` changed in one factor, each refused at 3:
     inverted (-v: every process, `-v ^$`), an unresolved owner filter dropped beside it
     (counted without both), a literal kinship value (counted WITH it, and silent at 1), a NAME
     beside it (the name-kill rule, counted with the name), and the session's own owner filter
     alone. Plus the twin `pkill -P $P -u "$USER"`: only kinship dropped, silent.
"""
import json, os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.environ.get("HOOK", os.path.join(HERE, "..", "block-unsafe-kill.sh"))
USER = __import__("pwd").getpwuid(os.getuid()).pw_name

STUB = r"""#!/usr/bin/env python3
import json, os, sys
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(json.dumps(sys.argv[1:]) + "\n")
n = int(os.environ["STUB_N"])
print("\n".join([os.environ["STUB_PID"]] * n))
sys.exit(0 if n else 1)
"""

RELATION = re.compile(r"\b(parent|session|process group)\b", re.I)


def kinship_options():
    """[(short, long)] of every pgrep option whose help line selects by a process relation."""
    out = subprocess.run(["pgrep", "--help"], capture_output=True, text=True).stdout
    opts = []
    for line in out.splitlines():
        m = re.match(r"\s*-(\w), (--[\w-]+) <[^>]*>\s+(.*)", line)
        if m and RELATION.search(m.group(3)):
            opts.append(("-" + m.group(1), m.group(2)))
    return opts


def setup():
    d = tempfile.mkdtemp(prefix="kinship-")
    os.mkdir(os.path.join(d, "bin"))
    p = os.path.join(d, "bin", "pgrep")
    with open(p, "w") as fh:
        fh.write(STUB)
    os.chmod(p, 0o755)
    return d


def run(d, cmd, n):
    log = os.path.join(d, "log")
    open(log, "w").close()
    env = dict(os.environ, PATH=os.path.join(d, "bin") + os.pathsep + os.environ["PATH"],
               STUB_LOG=log, STUB_N=str(n), STUB_PID=str(os.getpid()))
    r = subprocess.run(["bash", HOOK], input=json.dumps({"tool_input": {"command": cmd}}),
                       capture_output=True, text=True, env=env, timeout=60)
    calls = [json.loads(l) for l in open(log) if l.strip()]
    return r.returncode, r.stderr, calls


AGENT_PASS = [  # constructed, plainly synthetic shapes whose dropped filter is kinship
    ("constructed shape 1", 'P=4242; C=$(pgrep -P $P); echo "children: $C"; kill $P $C; sleep 3; '
                'ps -p $P -o pid= ; ./status.sh | sed -n 1,4p'),
    ("constructed shape 2", "W=$WORKDIR; P=$(cat $W/job.pid); "
                "kill -TERM -- -$P 2>&1; sleep 5; pgrep -s $P | head; "
                "pkill -KILL -s $P 2>/dev/null; sleep 1; pgrep -s $P | wc -l"),
    ("constructed shape 3", "cd $TMPDIR; setsid bash s.sh </dev/null >/dev/null 2>&1 & P=$!; sleep 1\n"
                "kill $P 2>/dev/null; wait $P 2>/dev/null; pkill -P $P 2>/dev/null; "
                "ps -o pid,args --ppid $P 2>/dev/null | tail -n +2"),
    ("constructed shape 4", "( while :; do ./job.sh >/dev/null 2>&1; done ) & bg=$!; "
                "./other.sh; kill $bg; pkill -P $bg 2>/dev/null; wait 2>/dev/null"),
]
AGENT_OWNER = ("constructed shape 5 (owner filter)",
                "W=$WORKDIR; for p in $(pgrep -u $(id -u)); do "
                "c=$(readlink /proc/$p/cwd 2>/dev/null); case \"$c\" in $W/out*) kill $p 2>/dev/null;; "
                "esac; done")

VALUES = ["$P", '"$P"', "${P}", "$!", "$$", "$(cat pf)"]
CARRIERS = [
    ("pkill", "pkill {sel}"),
    ("$( )", "kill $(pgrep {sel})"),
    ("backtick", "kill `pgrep {sel}`"),
    ("xargs", "pgrep {sel} | xargs kill"),
    ("trap", "trap 'pkill {sel}' EXIT; sleep 1"),
]


def main():
    kin = kinship_options()
    d = setup()
    bad, total = [], 0

    def check(label, ok, why):
        nonlocal total
        total += 1
        if not ok:
            bad.append("%s: %s" % (label, why))

    check("derivation", len(kin) >= 3,
          "pgrep --help named %r; a relation option is missing from the reading" % kin)
    try:
        for label, cmd in AGENT_PASS:
            rc, err, calls = run(d, cmd, 3)
            check("W " + label, rc == 0, "refused (rc %d), asked %r: %s"
                  % (rc, calls, err.strip()[:200]))
        label, cmd = AGENT_OWNER
        rc, err, calls = run(d, cmd, 3)
        check("W " + label, rc == 2 and any(c[:2] == ["-u", str(os.getuid())] for c in calls),
              "not refused as an owner selection (rc %d), asked %r" % (rc, calls))

        for short, long_ in kin:
            for val in VALUES:
                spellings = [short + " " + val, short + val, long_ + " " + val, long_ + "=" + val]
                for sel in spellings:
                    for cname, tmpl in CARRIERS:
                        if cname == "trap" and "'" in sel:
                            continue
                        cmd = tmpl.format(sel=sel)
                        rc, err, calls = run(d, cmd, 3)
                        check("C %s | %s" % (cname, sel), rc == 0 and not calls,
                              "rc %d, asked %r: %s" % (rc, calls, err.strip()[:160]))

        rc, err, calls = run(d, "pkill -v -P $P", 3)
        check("N inverted", rc == 2 and ["-v", "^$"] in calls, "rc %d, asked %r" % (rc, calls))
        rc, err, calls = run(d, 'pkill -P $P -u "$SOMEONE"', 3)
        check("N owner dropped too", rc == 2 and "counted without" in err and "-u" in err
              and ["."] in calls, "rc %d, asked %r: %s" % (rc, calls, err[:200]))
        rc, err, calls = run(d, "pkill -P 4242", 3)
        check("N literal parent", rc == 2 and ["-P", "4242", "."] in calls,
              "rc %d, asked %r" % (rc, calls))
        rc, err, calls = run(d, "pkill -P 4242", 1)
        check("N literal parent, one", rc == 0, "refused at a count of one: %s" % err[:200])
        rc, err, calls = run(d, "pkill -P $P mhzz", 3)
        check("N with a name", rc == 2 and ["mhzz"] in calls, "rc %d, asked %r" % (rc, calls))
        rc, err, calls = run(d, 'pkill -u "$USER"', 3)
        check("N own owner alone", rc == 2 and ["-u", USER, "."] in calls,
              "rc %d, asked %r" % (rc, calls))
        rc, err, calls = run(d, 'pkill -P $P -u "$USER"', 3)
        check("N twin: own owner beside a run-time parent", rc == 0 and not calls,
              "rc %d, asked %r: %s" % (rc, calls, err[:200]))
    finally:
        shutil.rmtree(d, ignore_errors=True)

    for b in bad:
        print("  FAIL " + b)
    print("%d of %d rows failed" % (len(bad), total))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
