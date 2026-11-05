"""Check of mh-a-lister-reaches-a-kill-through-every-binding-site (hooks/tests/INVARIANTS.md).

    hooks/block-unsafe-kill.sh refuses a pgrep or pidof whose pids bash carries to a kill
    through any binding site it has -- a pipeline, the output of a compound command ({ }, ( ),
    a loop, if, case) piped on, an output process substitution >(...), a substitution, a
    variable assigned by =, declare/local, printf -v, ${P:=...} or eval, the positional
    parameters bound by set, a function call or sh -c CODE NAME ARGS, xargs' replace string in
    sh -c code, a for, a read -- and through any command that expands such a binding and
    writes it on; and it refuses none of them when bash carries the pids to no kill.

WRITTEN FROM THE SENTENCE, not from the implementation. One row per
way the sentence can be false, grouped by the binding site it names; each site is tried in
more than one spelling, and EVAL in particular with its code in single quotes, in double quotes
with the substitution escaped (so eval, not the outer shell, runs the lister), and with the
eval code itself binding through another site (declare, set, read, for, export, ${P:-...}).

EVERY ROW IS A METAMORPHIC PAIR WITH BASH'S OWN READING. The row is first RUN by bash with
stand-ins on PATH: `pgrep`/`pidof` print two pids above pid_max, and every `kill` word is
rewritten to `swkill`, which only logs its arguments. Bash then says whether the lister's pids
reached the kill, and the row's label must agree (else the row fails as a fixture fault). The
hook is then asked about the real spelling, for `pgrep -f` (refused by structure) and for
`pgrep -x` and `pidof` of a name two live processes share (refused by count): refused exactly
when bash carried the pids to a kill. Every row starts a pid of its own from `$!`, which the
silent rows kill. Nothing real is signalled. Run serially: the live rows read the process table.
"""
import json, os, re, shutil, signal, subprocess, sys, tempfile, time
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)
from _proc_names import proc_name, sleeper  # noqa: E402  (per-run comm names: host-wide pgrep must see only this run)

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "block-unsafe-kill.sh")
PROC_NAME = proc_name("mhevs")
FAKE_PIDS = ("99999996", "99999997")
LISTERS = [("pgrep -f", "pgrep -f mh-cert-no-such-pattern"), ("pgrep -x", "pgrep -x " + PROC_NAME),
           ("pidof", "pidof " + PROC_NAME)]
PRELUDE = "sleep 0.2 & SRV=$!; "

# (site, template); {L} is the lister. Bash carries the pids to a kill in every one of these.
REACH = [
    ("pipeline", "{L} | xargs kill"),
    ("pipeline", "{L} | while read -r p; do kill $p; done"),
    ("pipeline", "{L} | sort | xargs kill"),
    ("compound { }", "{ {L}; } | xargs kill"),
    ("compound ( )", "( {L} ) | xargs kill"),
    ("compound while", "while true; do {L}; break; done | xargs kill"),
    ("compound until", "until false; do {L}; break; done | xargs kill"),
    ("compound if", "if true; then {L}; fi | xargs kill"),
    ("compound if/else", "if false; then :; else {L}; fi | xargs kill"),
    ("compound case", "case a in a) {L} ;; esac | xargs kill"),
    ("output procsub", "{L} > >(xargs kill)"),
    ("output procsub", "{L} | tee >(xargs kill) >/dev/null"),
    ("substitution", "kill $({L})"),
    ("substitution", "kill `{L}`"),
    ("substitution", "kill \"$({L})\""),
    ("= variable", "P=$({L}); kill $P"),
    ("= variable", "P=`{L}`; kill $P"),
    ("= variable", "P=\"$({L})\"; kill \"$P\""),
    ("= variable", "P=$({L}) Q=1; kill $P"),
    ("= variable", "P=($({L})); kill \"${P[@]}\""),
    ("declare", "declare P=$({L}); kill $P"),
    ("declare", "declare -a P=($({L})); kill \"${P[@]}\""),
    ("declare", "typeset P=$({L}); kill $P"),
    ("declare", "export P=$({L}); kill $P"),
    ("declare", "readonly P=$({L}); kill $P"),
    ("local", "f() { local P=$({L}); kill $P; }; f"),
    ("local", "f() { local P; P=$({L}); kill $P; }; f"),
    ("printf -v", "printf -v P '%s' \"$({L})\"; kill $P"),
    ("printf -v", "printf -v P \"%s\" $({L}); kill $P"),
    ("${P:=}", ": ${P:=$({L})}; kill $P"),
    ("${P:=}", ": ${P=$({L})}; kill $P"),
    ("${P:=}", "kill ${P:=$({L})}"),
    ("eval", "eval \"kill $({L})\""),
    ("eval", "eval 'kill $({L})'"),
    ("eval", "eval \"kill \\$({L})\""),
    ("eval", "P=$({L}); eval \"kill $P\""),
    ("eval", "P=$({L}); eval \"kill \\$P\""),
    ("eval", "P=$({L}); eval 'kill $P'"),
    ("eval", "eval 'P=$({L})'; kill $P"),
    ("eval", "eval \"P=$({L})\"; kill $P"),
    ("eval", "eval \"P=\\$({L})\"; kill $P"),
    ("eval", "eval \"P=\\\"\\$({L})\\\"\"; kill $P"),
    ("eval", "eval \"P='$({L})'\"; kill $P"),
    ("eval", "eval P=\\\"\\$\\({L}\\)\\\"; kill $P"),
    ("eval", "eval \"{L} | xargs kill\""),
    ("eval", "eval \"{L}\" | xargs kill"),
    ("eval", "P=$(eval \"{L}\"); kill $P"),
    ("eval", "eval \"P=\\$(eval \\\"{L}\\\")\"; kill $P"),
    ("eval", "X=\"P=\\$({L})\"; eval \"$X\"; kill $P"),
    ("eval", "eval \"f() { kill \\$1; }\"; f $({L})"),
    ("eval+declare", "eval \"declare P=\\$({L})\"; kill $P"),
    ("eval+declare", "eval \"export P=\\$({L})\"; kill $P"),
    ("eval+param", "eval \"P=\\${P:-\\$({L})}\"; kill $P"),
    ("eval+set", "eval \"set -- \\$({L})\"; kill \"$@\""),
    ("eval+read", "eval \"read -r P <<< \\\"\\$({L})\\\"\"; kill $P"),
    ("eval+for", "eval \"for p in \\$({L}); do kill \\$p; done\""),
    ("set", "set -- $({L}); kill \"$@\""),
    ("set", "set -- $({L}); kill $*"),
    ("set", "set -- $({L}); kill ${1}"),
    ("set", "set $({L}); for p; do kill $p; done"),
    ("function", "f() { kill \"$@\"; }; f $({L})"),
    ("function", "f() { kill \"$1\"; }; f \"$({L})\""),
    ("function", "f() { kill $1; }; P=$({L}); f $P"),
    ("function", "function k { kill $1; }; k $({L})"),
    ("function", "f() { g \"$@\"; }; g() { kill \"$@\"; }; f $({L})"),
    ("sh -c ARGS", "sh -c 'kill $1' _ $({L})"),
    ("sh -c ARGS", "bash -c 'kill \"$@\"' sh $({L})"),
    ("sh -c ARGS", "P=$({L}); sh -c 'kill \"$@\"' _ $P"),
    ("sh -c ARGS", "{L} | xargs sh -c 'kill \"$@\"' _"),
    ("xargs -I", "{L} | xargs -I{} sh -c 'kill {}'"),
    ("xargs -I", "{L} | xargs -I % bash -c 'kill %'"),
    ("xargs -I", "{L} | xargs --replace={} sh -c 'kill {}'"),
    ("xargs -I", "{L} | xargs -i sh -c 'kill {}'"),
    ("for", "for p in $({L}); do kill $p; done"),
    ("for", "P=$({L}); for p in $P; do kill $p; done"),
    ("for", "for p in $({L}); do kill -TERM \"$p\"; done"),
    ("read", "read -r P < <({L}); kill $P"),
    ("read", "read -r P <<< \"$({L})\"; kill $P"),
    ("read", "read -ra A <<< \"$({L})\"; kill \"${A[@]}\""),
    ("read", "{L} | { read -r P; kill $P; }"),
    ("written on", "P=$({L}); echo $P | xargs kill"),
    ("written on", "P=$({L}); printf '%s\\n' $P | xargs kill"),
    ("written on", "P=$({L}); kill $(echo \"$P\")"),
    ("written on", "P=$({L}); cat <<< \"$P\" | xargs kill"),
    ("written on", "P=$({L}); Q=\"$P\"; kill $Q"),
    ("written on", "P=$({L}); Q=$(printf '%s' \"$P\"); kill $Q"),
    ("written on", "set -- $({L}); echo \"$@\" | xargs kill"),
    ("written on", "f() { echo \"$@\"; }; f $({L}) | xargs kill"),
]
# Bash carries the lister's pids to no kill in any of these; the kill takes $SRV.
SILENT = [
    ("pipeline", "{L} | wc -l; kill \"$SRV\""),
    ("compound { }", "{ {L}; } | wc -l; kill \"$SRV\""),
    ("compound ( )", "( {L} ) >/dev/null; kill \"$SRV\""),
    ("compound for", "for i in 1; do {L}; done | wc -l; kill \"$SRV\""),
    ("compound if", "if true; then {L}; fi | wc -l; kill \"$SRV\""),
    ("compound case", "case a in a) {L} ;; esac | wc -l; kill \"$SRV\""),
    ("output procsub", "{L} > >(wc -l); kill \"$SRV\""),
    ("substitution", "n=$({L} | wc -l); kill \"$SRV\""),
    ("= variable", "P=$({L}); echo \"$P\"; kill \"$SRV\""),
    ("= variable", "P=$({L}); echo $P | wc -w; kill \"$SRV\""),
    ("= variable", "P=$({L}); P=$SRV; kill $P"),
    ("declare", "declare P=$({L}); echo $P; kill \"$SRV\""),
    ("local", "f() { local P=$({L}); echo $P; }; f; kill \"$SRV\""),
    ("printf -v", "printf -v P '%s' \"$({L})\"; echo $P; kill \"$SRV\""),
    ("${P:=}", ": ${P:=$({L})}; echo $P; kill \"$SRV\""),
    ("eval", "eval \"P=\\$({L})\"; echo $P; kill \"$SRV\""),
    ("eval", "eval \"echo \\$({L})\"; kill \"$SRV\""),
    ("eval", "eval \"n=\\$({L} | wc -l)\"; kill \"$SRV\""),
    ("eval", "eval \"kill \\$SRV\"; {L} | wc -l"),
    ("eval", "P=$({L}); eval \"echo $P\"; kill \"$SRV\""),
    ("eval", "eval \"P=\\$({L})\"; P=$SRV; kill $P"),
    ("set", "set -- $({L}); echo \"$#\"; kill \"$SRV\""),
    ("function", "f() { echo \"$@\"; }; f $({L}); kill \"$SRV\""),
    ("function", "f() { kill \"$SRV\"; }; f $({L})"),
    ("function", "P=$({L}); f() { kill $1; }; f \"$SRV\""),
    ("sh -c ARGS", "sh -c 'echo \"$@\"' _ $({L}); kill \"$SRV\""),
    ("xargs -I", "{L} | xargs -I{} sh -c 'echo {}'; kill \"$SRV\""),
    ("for", "for p in $({L}); do echo $p; done; kill \"$SRV\""),
    ("read", "read -r P < <({L}); echo $P; kill \"$SRV\""),
    ("read", "{L} | while read -r p; do echo $p; done; kill \"$SRV\""),
]


def verdict(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True, timeout=60)
    return p.returncode != 0, p.stderr


def make_stubs(d):
    for name in ("pgrep", "pidof"):
        with open(os.path.join(d, name), "w") as fh:
            fh.write("#!/bin/sh\nprintf '%s\\n' " + " ".join(FAKE_PIDS) + "\n")
    with open(os.path.join(d, "swkill"), "w") as fh:
        fh.write("#!/bin/sh\nprintf 'KILL %s\\n' \"$*\" >> \"$SWKILL_LOG\"\n")
    for name in ("pgrep", "pidof", "swkill"):
        os.chmod(os.path.join(d, name), 0o755)


def bash_reaches(cmd, d):
    log = os.path.join(d, "kill.log")
    if os.path.exists(log):
        os.remove(log)
    env = dict(os.environ, PATH=d + ":" + os.environ["PATH"], SWKILL_LOG=log)
    run = re.sub(r"(?<![\w-])kill(?![\w-])", "swkill", cmd)
    settle = "\nsleep 0.3" if ">(" in cmd else ""
    bash_oracle.run(["bash", "-c", run + "\nwait" + settle], env=env, cwd=d, capture_output=True,
                   timeout=20, stdin=subprocess.DEVNULL)
    text = open(log).read() if os.path.exists(log) else ""
    return any(p in text for p in FAKE_PIDS), text


def start_shared_name(n=2):
    d = tempfile.mkdtemp(prefix="mh-cert-bind-")
    exe = os.path.join(d, PROC_NAME)
    shutil.copy2("/bin/sleep", exe)
    procs = [sleeper(exe) for _ in range(n)]
    for _ in range(50):
        r = subprocess.run(["pgrep", "-x", PROC_NAME], capture_output=True, text=True)
        if len([x for x in r.stdout.split() if x.isdigit()]) >= n:
            break
        time.sleep(0.05)
    return d, procs


def main():
    failures, n = [], 0
    stubs = tempfile.mkdtemp(prefix="mh-cert-stubs-")
    make_stubs(stubs)
    live, procs = start_shared_name()
    try:
        for want, rows in ((True, REACH), (False, SILENT)):
            for site, tmpl in rows:
                reached, log = bash_reaches(PRELUDE + tmpl.replace("{L}", "pgrep -f x"), stubs)
                if reached != want:
                    failures.append("FIXTURE [%s] %s: bash says reached=%s; log %r"
                                    % (site, tmpl, reached, log))
                    continue
                if not want and "KILL" not in log:
                    failures.append("FIXTURE [%s] %s: the pid from $! reached no kill" % (site, tmpl))
                for lname, lister in LISTERS:
                    cmd = PRELUDE + tmpl.replace("{L}", lister)
                    fired, err = verdict(cmd)
                    n += 1
                    if fired != want:
                        failures.append("%s [%s | %s]: %s%s" % (
                            "NOT REFUSED" if want else "FALSE REFUSAL", site, lname, cmd,
                            "" if want else "\n      said: " + err.strip().splitlines()[0][:160]
                            if err.strip() else ""))
                    elif fired and "BLOCKED" not in err:
                        failures.append("REFUSED SAYING NOTHING [%s | %s]: %s" % (site, lname, cmd))
    finally:
        for p in procs:
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=5)
        shutil.rmtree(live, ignore_errors=True)
        shutil.rmtree(stubs, ignore_errors=True)
    if failures:
        print("FAIL (%d of %d cases)" % (len(failures), n))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d cases (%d reach + %d silent templates x %d listers), each agreeing with bash"
          % (n, len(REACH), len(SILENT), len(LISTERS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
