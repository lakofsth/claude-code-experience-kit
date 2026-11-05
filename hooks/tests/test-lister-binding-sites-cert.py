"""Check: a lister reaches a kill through every binding site.

The sentence (mh-a-lister-reaches-a-kill-through-every-binding-site):

    hooks/block-unsafe-kill.sh refuses a pgrep or pidof whose pids bash carries to a kill through
    any binding site it has -- a pipeline, the output of a compound command ({ }, ( ), a loop, if,
    case) piped on, an output process substitution >(...), a substitution, a variable assigned by
    =, declare/local, printf -v, ${P:=...} or eval, the positional parameters bound by set, a
    function call or sh -c CODE NAME ARGS, xargs' replace string in sh -c code, a for, a read --
    and through any command that expands such a binding and writes it on; and it refuses none of
    them when bash carries the pids to no kill.

Written from the hooks/tests/INVARIANTS.md clause alone. Its directions:

  1. REACH    -- every binding site the sentence names, used to carry a lister's pids to a kill,
                 is refused; and each binding, expanded by a command that writes it on into a
                 kill (`echo $P | xargs kill`), is refused too.
  2. NO REACH -- the same binding site, with the pids going nowhere near a kill (the kill in
                 the command is of a pid captured elsewhere), is refused by none of them.

Each template is run for `pgrep -f <pattern>`, `pgrep -x <name>` and `pidof <name>`, with two
live processes of the name, so a name kill that reaches them is one this hook counts as shared.
Fixture: two copies of a uniquely named program of this test's own, stopped by PID afterwards.
Nothing here runs a kill; the hook only reads.
"""
import json, os, shutil, signal, subprocess, sys, tempfile, time
from _proc_names import proc_name, sleeper  # noqa: E402  (per-run comm names: host-wide pgrep must see only this run)

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

A = proc_name("mhbsc")      # comm is truncated to 15 characters; per-run, distinct from sibling tests
PAT = "mhbindsite-no-such-pattern"
LISTERS = [("pgrep -f", "pgrep -f %s" % PAT), ("pgrep -x", "pgrep -x %s" % A),
           ("pidof", "pidof %s" % A)]

# {L} is the lister. Every REACH row carries its pids to a kill; every SILENT row binds them at
# the same site and kills only "$SRV".
REACH = [
    # a pipeline
    ("pipeline",                    "{L} | xargs kill"),
    # the output of a compound command piped on
    ("{ } piped on",                "{ {L}; } | xargs kill"),
    ("( ) piped on",                "( {L} ) | xargs kill"),
    ("for loop piped on",           "for i in 1; do {L}; done | xargs kill"),
    ("while loop piped on",         "while true; do {L}; break; done | xargs kill"),
    ("if piped on",                 "if true; then {L}; fi | xargs kill"),
    ("case piped on",               "case x in x) {L};; esac | xargs kill"),
    # an output process substitution
    ("output procsub >( )",         "{L} > >(xargs kill)"),
    # a substitution
    ("substitution",                "kill $({L})"),
    # a variable: =, declare/local, printf -v, ${P:=...}, eval
    ("assign =",                    "P=$({L}); kill $P"),
    ("declare",                     "declare P=$({L}); kill $P"),
    ("declare -a",                  "declare -a P=($({L})); kill ${P[@]}"),
    ("local in a function",         "f() { local P=$({L}); kill $P; }; f"),
    ("printf -v",                   "printf -v P '%s' \"$({L})\"; kill $P"),
    ("${P:=...}",                   ": ${P:=$({L})}; kill $P"),
    ("eval assignment",             "eval 'P=$({L})'; kill $P"),
    ("eval of \"...\"",             "eval \"P=\\$({L})\"; kill \"$P\""),
    # the positional parameters bound by set
    ("set -- then $@",              "set -- $({L}); kill \"$@\""),
    ("set -- then $1",              "set -- $({L}); kill $1"),
    # a function call
    ("function call $@",            "f() { kill \"$@\"; }; f $({L})"),
    ("function call $1",            "f() { kill $1; }; f $({L})"),
    ("function keyword",            "function g { kill \"$@\"; }; g $({L})"),
    # sh -c CODE NAME ARGS
    ("sh -c CODE NAME ARGS",        "sh -c 'kill \"$@\"' _ $({L})"),
    ("bash -c CODE NAME $1",        "bash -c 'kill $1' x $({L})"),
    # xargs' replace string in sh -c code
    ("xargs -I{} sh -c",            "{L} | xargs -I{} sh -c 'kill {}'"),
    ("xargs -I % bash -c",          "{L} | xargs -I % bash -c 'kill %'"),
    ("xargs -i sh -c",              "{L} | xargs -i sh -c 'kill {}'"),
    # a for, a read
    ("for",                         "for p in $({L}); do kill $p; done"),
    ("read from a pipe",            "{L} | while read p; do kill $p; done"),
    ("read from <( )",              "read p < <({L}); kill $p"),
    # a command that expands such a binding and writes it on
    ("= then echo | xargs kill",    "P=$({L}); echo $P | xargs kill"),
    ("declare then printf | kill",  "declare P=$({L}); printf '%s\\n' $P | xargs kill"),
    ("printf -v then echo | kill",  "printf -v P '%s' \"$({L})\"; echo \"$P\" | xargs kill"),
    ("${P:=} then echo | kill",     ": ${P:=$({L})}; echo $P | xargs kill"),
    ("set then echo $@ | kill",     "set -- $({L}); echo \"$@\" | xargs kill"),
    ("function echoes $1 into kill", "f() { echo \"$1\" | xargs kill; }; f $({L})"),
    ("sh -c echoes $@ into kill",   "sh -c 'echo \"$@\" | xargs kill' _ $({L})"),
    ("for then echo | kill",        "for p in $({L}); do echo $p | xargs kill; done"),
    ("read then echo | kill",       "{L} | while read p; do echo $p | xargs kill; done"),
    ("= then echo into kill $(..)", "P=$({L}); kill $(echo $P)"),
]

SILENT = [
    ("pipeline",                    "{L} | wc -l; kill \"$SRV\""),
    ("{ } piped on",                "{ {L}; } | wc -l; kill \"$SRV\""),
    ("( ) piped on",                "( {L} ) | wc -l; kill \"$SRV\""),
    ("for loop piped on",           "for i in 1; do {L}; done | wc -l; kill \"$SRV\""),
    ("if piped on",                 "if true; then {L}; fi | wc -l; kill \"$SRV\""),
    ("case piped on",               "case x in x) {L};; esac | wc -l; kill \"$SRV\""),
    ("output procsub >( )",         "{L} > >(wc -l); kill \"$SRV\""),
    ("substitution",                "echo $({L}); kill \"$SRV\""),
    ("assign =",                    "P=$({L}); echo $P; kill \"$SRV\""),
    ("declare",                     "declare P=$({L}); echo $P; kill \"$SRV\""),
    ("local in a function",         "f() { local P=$({L}); echo $P; }; f; kill \"$SRV\""),
    ("printf -v",                   "printf -v P '%s' \"$({L})\"; echo $P; kill \"$SRV\""),
    ("${P:=...}",                   ": ${P:=$({L})}; echo $P; kill \"$SRV\""),
    ("eval assignment",             "eval 'P=$({L})'; echo $P; kill \"$SRV\""),
    ("set --",                      "set -- $({L}); echo \"$@\"; kill \"$SRV\""),
    ("function call",               "f() { echo \"$@\"; kill \"$SRV\"; }; f $({L})"),
    ("sh -c CODE NAME ARGS",        "sh -c 'echo \"$@\"' _ $({L}); kill \"$SRV\""),
    ("xargs -I{} sh -c",            "{L} | xargs -I{} sh -c 'echo {}'; kill \"$SRV\""),
    ("for",                         "for p in $({L}); do echo $p; done; kill \"$SRV\""),
    ("read",                        "{L} | while read p; do echo $p; done; kill \"$SRV\""),
    ("= then echo | wc",            "P=$({L}); echo $P | wc -w; kill \"$SRV\""),
    ("set then echo $@ | wc",       "set -- $({L}); echo \"$@\" | wc -w; kill \"$SRV\""),
]


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
    d = tempfile.mkdtemp(prefix="mh-bind-site-")
    exe = os.path.join(d, A)
    shutil.copy2("/bin/sleep", exe)
    procs = [sleeper(exe) for _ in range(2)]
    failures, total = [], 0
    try:
        for _ in range(50):
            if count(A) >= 2:
                break
            time.sleep(0.05)
        if count(A) != 2:
            print("SETUP FAILED: want 2 x %s, have %d" % (A, count(A)))
            return 2
        for ln, lister in LISTERS:
            for label, tpl in REACH:
                cmd = tpl.replace("{L}", lister)
                total += 1
                fired, err = verdict(cmd)
                if not fired:
                    failures.append("NOT REFUSED [%s, %s]: %s" % (label, ln, cmd))
                elif "BLOCKED:" not in err:
                    failures.append("REFUSED but said nothing useful [%s, %s]: %r"
                                    % (label, ln, err[:200]))
            for label, tpl in SILENT:
                cmd = tpl.replace("{L}", lister)
                total += 1
                fired, err = verdict(cmd)
                if fired:
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

    if failures:
        print("FAIL (%d of %d cases)" % (len(failures), total))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d binding-site cases (%d reach x %d listers refused, %d silent x %d listers silent)"
          % (total, len(REACH), len(LISTERS), len(SILENT), len(LISTERS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
