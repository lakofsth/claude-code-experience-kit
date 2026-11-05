"""Check: a lister reaches a kill through every binding site -- through a name already bound,
and only in the order bash runs it.

The sentence (mh-a-lister-reaches-a-kill-through-every-binding-site):

    hooks/block-unsafe-kill.sh refuses a pgrep or pidof whose pids bash carries to a kill through
    any binding site it has -- a pipeline, the output of a compound command ({ }, ( ), a loop, if,
    case) piped on, an output process substitution >(...), a substitution, a variable assigned by
    =, declare/local, printf -v, ${P:=...} or eval, the positional parameters bound by set, a
    function call or sh -c CODE NAME ARGS, xargs' replace string in sh -c code, a for, a read --
    and through any command that expands such a binding and writes it on; and it refuses none of
    them when bash carries the pids to no kill.

Written from the hooks/tests/INVARIANTS.md clause alone. The sibling check
test-lister-binding-sites-cert.py feeds every site straight from a substitution of the lister,
and kills a pid captured elsewhere on the silent side. This one asks the two directions that
leaves open:

  1. CHAINED  -- a binding site whose value is a name ALREADY bound to the pids (`P=$(L); set --
                 $P; kill "$@"`, `printf -v Q '%s' "$P"`, `read q <<< "$P"`, a function or
                 `sh -c` called with $P, ...) carries them on exactly as one fed by $(L) does,
                 and is refused.
  2. ORDERED  -- a binding bash has not made yet when the kill runs (the kill comes first), or
                 has unmade (the name is rebound, unset, or was bound in a scope that is gone)
                 carries nothing to it, and is refused by none.

THE LABELS ARE BASH'S, NOT THIS FILE'S. Each template is first run by bash with stand-ins: the
lister prints two pids above pid_max, every kill (the builtin, /bin/kill via xargs, and the kill
of a child `sh`/`bash`) only logs its operands, and $SRV is a third such pid. A template is
CARRIED iff a lister pid reached a kill's log. The hook must refuse exactly the carried ones;
a template whose bash run disagrees with the direction it was written for is a defect of this
check and exits 2, never 0.

Each template runs for `pgrep -f <pattern>`, `pgrep -x <name>` and `pidof <name>`, with two live
processes of the name, so a name kill that reaches them is one the hook counts as shared.
Nothing here signals anything but its own two fixture processes, by PID.
"""
import json, os, shutil, signal, stat, subprocess, sys, tempfile, time
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)
from _proc_names import proc_name, sleeper  # noqa: E402  (per-run comm names: host-wide pgrep must see only this run)

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

A = proc_name("mhbon")      # comm is truncated to 15 characters; per-run, distinct from sibling tests
PAT = "mhboundord-no-such-pattern"
LISTERS = [("pgrep -f", "pgrep -f %s" % PAT), ("pgrep -x", "pgrep -x %s" % A),
           ("pidof", "pidof %s" % A)]
FAKE = ("4194401", "4194402")   # what the stand-in lister prints: above any pid_max
SRV = "4194409"

# Direction 1: the pids reach a kill through a site fed by a name already bound to them.
CHAINED = [
    ("= then printf -v",            "P=$({L}); printf -v Q '%s' \"$P\"; kill $Q"),
    ("= then set --",               "P=$({L}); set -- $P; kill \"$@\""),
    ("= then function call",        "P=$({L}); f() { kill \"$@\"; }; f $P"),
    ("= then sh -c CODE NAME ARGS", "P=$({L}); sh -c 'kill \"$@\"' _ $P"),
    ("= then bash -c ... $1",       "P=$({L}); bash -c 'kill $1' x $P"),
    ("= then read <<<",             "P=$({L}); read -r q <<< \"$P\"; kill $q"),
    ("= then mapfile <<<",          "P=$({L}); mapfile -t a <<< \"$P\"; kill \"${a[@]}\""),
    ("= then ${Q:=$P}",             "P=$({L}); : ${Q:=$P}; kill $Q"),
    ("= then eval",                 "P=$({L}); eval \"Q='$P'\"; kill $Q"),
    ("= then declare",              "P=$({L}); declare Q=$P; kill $Q"),
    ("= then local",                "P=$({L}); g() { local Q=$P; kill $Q; }; g"),
    ("= then for",                  "P=$({L}); for q in $P; do kill $q; done"),
    ("= then = then =",             "P=$({L}); Q=$P; R=$Q; kill $R"),
    ("= then xargs -I{} sh -c",     "P=$({L}); echo $P | xargs -I{} sh -c 'kill {}'"),
    ("set then = $1",               "set -- $({L}); Q=$1; kill $Q"),
    ("set then printf -v",          "set -- $({L}); printf -v Q '%s' \"$1\"; kill $Q"),
    ("set then function call",      "set -- $({L}); f() { kill \"$@\"; }; f \"$@\""),
    ("for then set --",             "for p in $({L}); do set -- $p; kill $1; done"),
    ("for then printf -v",          "for p in $({L}); do printf -v Q '%s' \"$p\"; kill $Q; done"),
    ("read then printf -v",         "{L} | while read p; do printf -v Q '%s' \"$p\"; kill $Q; done"),
    ("read then sh -c ARGS",        "{L} | while read p; do sh -c 'kill \"$1\"' _ \"$p\"; done"),
    ("printf -v then set --",       "printf -v P '%s' \"$({L})\"; set -- $P; kill \"$@\""),
    ("function binds a global",     "f() { Q=$1; }; f $({L}); kill $Q"),
    ("{ } into >( )",               "{ {L}; } > >(xargs kill)"),
    ("( ) into >( )",               "( {L} ) > >(xargs kill)"),
]

# Direction 2: the same sites, but bash has not bound the pids when the kill runs, or has unbound
# them. Every kill here is handed $SRV and nothing else bash could give it.
ORDERED = [
    ("kill before =",               "kill \"$SRV\" $P; P=$({L})"),
    ("kill before =, then echo",    "P=$SRV; kill $P; P=$({L}); echo $P"),
    ("= rebound before kill",       "P=$({L}); P=$SRV; kill $P"),
    ("= unset before kill",         "P=$({L}); unset P; kill \"$SRV\" $P"),
    ("= in a subshell",             "( P=$({L}) ); kill \"$SRV\" $P"),
    ("= as the kill's prefix",      "P=$({L}) kill \"$SRV\" $P"),
    ("chain made before =",         "Q=$P; P=$({L}); kill \"$SRV\" $Q"),
    ("chain rebound before kill",   "P=$({L}); Q=$P; Q=$SRV; kill $Q"),
    ("kill before set --",          "kill \"$SRV\" \"$@\"; set -- $({L})"),
    ("set -- rebound before kill",  "set -- $({L}); set -- \"$SRV\"; kill \"$@\""),
    ("kill before printf -v",       "kill \"$SRV\" $P; printf -v P '%s' \"$({L})\""),
    ("printf -v rebound",           "printf -v P '%s' \"$({L})\"; printf -v P '%s' \"$SRV\"; kill $P"),
    ("declare rebound",             "declare P=$({L}); declare P=$SRV; kill $P"),
    ("local gone after return",     "f() { local P=$({L}); }; f; kill \"$SRV\" $P"),
    ("eval rebound",                "eval 'P=$({L})'; P=$SRV; kill $P"),
    ("kill before ${P:=}",          "kill \"$SRV\" $P; : ${P:=$({L})}"),
    ("read rebound",                "read p < <({L}); p=$SRV; kill $p"),
    ("read in a pipe's subshell",   "{L} | read p; kill \"$SRV\" $p"),
    ("for rebound after the loop",  "for p in $({L}); do :; done; p=$SRV; kill $p"),
    ("for reused by a later for",   "for p in $({L}); do echo $p; done; for p in \"$SRV\"; do kill $p; done"),
    ("function ignores its args",   "f() { kill \"$SRV\"; }; f $({L})"),
    ("function args, top-level $1", "f() { echo \"$@\"; }; f $({L}); kill \"$SRV\" $1"),
]


def stand_ins(d, log):
    """A PATH directory whose pgrep/pidof print FAKE and whose kill/sh only log, and the rc
    file every bash of the run reads for a kill function that logs too."""
    def put(name, body):
        p = os.path.join(d, name)
        with open(p, "w") as fh:
            fh.write("#!/bin/bash\n" + body + "\n")
        os.chmod(p, os.stat(p).st_mode | stat.S_IXUSR)
    lister = "printf '%%s\\n' %s" % " ".join(FAKE)
    put("pgrep", lister)
    put("pidof", "echo %s" % " ".join(FAKE))
    put("kill", "printf '%%s\\n' \"$@\" >> %s" % log)
    put("sh", "exec bash \"$@\"")
    rc = os.path.join(d, "rc")
    with open(rc, "w") as fh:
        fh.write("kill() { printf '%%s\\n' \"$@\" >> %s; }\n" % log)
    return rc


def bash_carries(cmd, d, log, rc):
    """Whether bash, running cmd with the stand-ins, hands a lister pid to a kill."""
    open(log, "w").close()
    env = dict(os.environ, PATH=d + ":" + os.environ.get("PATH", ""), SRV=SRV, BASH_ENV=rc)
    for k in ("P", "Q", "R", "p", "q", "a"):
        env.pop(k, None)
    bash_oracle.run(["bash", "-c", ". \"$BASH_ENV\"; " + cmd], env=env, stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
    time.sleep(0.05)                # a >( ) reader may finish after its writer
    with open(log) as fh:
        got = fh.read().split()
    return any(p in got for p in FAKE)


def verdict(cmd):
    """(fired, stderr) -- fired is True iff the hook exited non-zero."""
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


def count(name):
    r = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True)
    return len([x for x in r.stdout.split() if x.isdigit()])


def main():
    d = tempfile.mkdtemp(prefix="mh-bound-order-")
    sd = os.path.join(d, "bin")
    os.mkdir(sd)
    log = os.path.join(d, "kill.log")
    rc = stand_ins(sd, log)
    exe = os.path.join(d, A)
    shutil.copy2("/bin/sleep", exe)
    procs = [sleeper(exe) for _ in range(2)]
    failures, broken, total = [], [], 0
    try:
        for _ in range(50):
            if count(A) >= 2:
                break
            time.sleep(0.05)
        if count(A) != 2:
            print("SETUP FAILED: want 2 x %s, have %d" % (A, count(A)))
            return 2
        for want, rows in ((True, CHAINED), (False, ORDERED)):
            for label, tpl in rows:
                # bash's own verdict, once per template (the stand-in lister ignores its argv)
                truth = bash_carries(tpl.replace("{L}", "pgrep -f x"), sd, log, rc)
                if truth != want:
                    broken.append("[%s] written as %s, bash says %s: %s"
                                  % (label, "carried" if want else "not carried",
                                     "carried" if truth else "not carried", tpl))
                    continue
                for ln, lister in LISTERS:
                    cmd = tpl.replace("{L}", lister)
                    total += 1
                    fired, err = verdict(cmd)
                    if want and not fired:
                        failures.append("NOT REFUSED [%s, %s]: %s" % (label, ln, cmd))
                    elif want and "BLOCKED:" not in err:
                        failures.append("REFUSED but said nothing useful [%s, %s]: %r"
                                        % (label, ln, err[:200]))
                    elif not want and fired:
                        failures.append("FALSE REFUSAL [%s, %s]: %s\n    said: %s"
                                        % (label, ln, cmd, err.splitlines()[0] if err else ""))
    finally:
        for p in procs:             # by PID
            try:
                p.send_signal(signal.SIGTERM)
                p.wait(timeout=5)
            except Exception:
                pass
        shutil.rmtree(d, ignore_errors=True)

    if broken:
        print("CHECK DEFECT: %d template(s) disagree with bash" % len(broken))
        for b in broken:
            print("  " + b)
        return 2
    if failures:
        print("FAIL (%d of %d cases)" % (len(failures), total))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d cases (%d chained x %d listers refused, %d ordered x %d listers silent), "
          "each template's label confirmed by bash"
          % (total, len(CHAINED), len(LISTERS), len(ORDERED), len(LISTERS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
