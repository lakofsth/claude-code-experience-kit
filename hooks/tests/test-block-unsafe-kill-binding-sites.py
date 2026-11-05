"""Check of mh-a-lister-reaches-a-kill-through-every-binding-site (hooks/tests/INVARIANTS.md).

    hooks/block-unsafe-kill.sh refuses a pgrep or pidof whose pids reach a kill through any
    binding site bash has -- a pipeline, a compound command's output, a substitution, a
    variable, `printf -v`, the positional parameters (`set --`, a function call, the arguments
    of `sh -c`), `${P:=...}`, a `for`, a `read`, xargs' replace string -- and through any
    command that expands such a binding and writes it on; and it stays silent when they reach
    none.

EVERY ROW IS A METAMORPHIC PAIR WITH BASH'S OWN READING. Each template is first RUN by bash with
the lister and the kill replaced by stand-ins on PATH: `pgrep`/`pidof` print two pids no
process can hold (above pid_max), and every `kill` word is rewritten to `swkill`, which only
logs its arguments. Bash then says whether the lister's pids reached the kill. The hook is
asked about the real spelling, and its verdict must agree: refused when bash carried the pids
there, silent when it did not. Nothing real is listed or signalled; the stand-in kill cannot
reach a process, and a row is skipped as a fixture fault (and fails) if bash says otherwise
than the row's label.

Each template runs for `pgrep -f` (refused by structure) and for `pgrep -x` and `pidof` of a
name two live processes answer to (refused by count), so the binding site is checked apart
from the lister. The must-stay-silent rows kill a pid the command started, read from `$!`.

Run serially: the live-count rows read the process table.
"""
import json, os, re, shutil, signal, subprocess, sys, tempfile, time
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)
from _proc_names import proc_name, sleeper  # noqa: E402  (per-run comm names: host-wide pgrep must see only this run)

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "block-unsafe-kill.sh")
PROC_NAME = proc_name("mhbnd")    # comm is 15 characters at most; pgrep -x matches comm
FAKE_PIDS = ("99999998", "99999999")

LISTER_FORMS = [("pgrep -f", "pgrep -f mh-no-such-pattern"), ("pgrep -x", "pgrep -x " + PROC_NAME),
                ("pidof", "pidof " + PROC_NAME)]

# (label, template). {L} is the lister.
REACH = [
    ("PROCSUB xargs kill < <(L)",               "xargs kill < <({L})"),
    ("PROCSUB xargs -a <(L) kill",              "xargs -a <({L}) kill"),
    ("PROCSUB kill $(cat <(L))",                "kill $(cat <({L}))"),
    ("GROUP { L; } | xargs kill",               "{ {L}; } | xargs kill"),
    ("GROUP ( L ) | xargs kill",                "( {L} ) | xargs kill"),
    ("GROUP a redirection after the group",     "{ {L}; } 2>/dev/null | xargs kill"),
    ("GROUP a loop's output",                   "for i in 1; do {L}; done | xargs kill"),
    ("GROUP an if's output",                    "if true; then {L}; fi | xargs kill"),
    ("GROUP a group into a read loop",          "{ {L}; } | while read -r p; do kill \"$p\"; done"),
    ("GROUP a subshell into a group's read",    "( {L} ) | { read -r p; kill \"$p\"; }"),
    ("GROUP into a subshell's xargs kill",      "{L} | ( xargs kill )"),
    ("GROUP a subshell inside a substitution",  "kill $( ( {L} ) )"),
    ("ECHOED kill $(echo $P)",                  "P=$({L}); kill $(echo $P)"),
    ("ECHOED kill $(printf ...)",               "P=$({L}); kill $(printf '%s ' $P)"),
    ("ECHOED through a herestring passer",      "P=$({L}); kill $(tr ' ' '\\n' <<< \"$P\")"),
    ("ECHOED two hops",                         "P=$({L}); Q=$(echo $P); kill $Q"),
    ("PRINTF-V printf -v P",                    "printf -v P '%s' \"$({L})\"; kill $P"),
    ("PRINTF-V printf -vP",                     "printf -vP '%s' \"$({L})\"; kill $P"),
    ("POSITIONAL set -- and \"$@\"",            "set -- $({L}); kill \"$@\""),
    ("POSITIONAL set -- and $1",                "set -- $({L}); kill $1"),
    ("POSITIONAL set without --, for p;",       "set $({L}); for p; do kill $p; done"),
    ("POSITIONAL written on into xargs",        "set -- $({L}); printf '%s\\n' \"$@\" | xargs kill"),
    ("FUNCTION its arguments",                  "k() { kill \"$@\"; }; k $({L})"),
    ("FUNCTION function keyword",               "function k { kill $1; }; k $({L})"),
    ("PARAM ${P:=$(L)}",                        ": ${P:=$({L})}; kill $P"),
    ("SH-C the arguments of bash -c",           "bash -c 'kill \"$@\"' _ $({L})"),
    ("SH-C xargs sh -c with \"$@\"",            "{L} | xargs sh -c 'kill \"$@\"' _"),
    ("XARGS-I the replace string",              "{L} | xargs -I{} sh -c 'kill {}'"),
    ("XARGS-I a replace string of its own",     "{L} | xargs -I PID sh -c 'kill PID'"),
    ("EVAL eval assigns, quoted",               "eval \"P=$({L})\"; kill $P"),
    ("EVAL eval assigns, escaped",              "eval P=\\$\\({L}\\); kill $P"),
    ("DECLARE local in a function",             "f() { local P=$({L}); kill $P; }; f"),
    ("DECLARE declare",                         "declare P=$({L}); kill $P"),
    ("CLOSER done <<< \"$P\"",                  "P=$({L}); while read -r p; do kill \"$p\"; done <<< \"$P\""),
    ("OUTPROC L > >(xargs kill)",               "{L} > >(xargs kill)"),
    ("OUTPROC tee >(xargs kill)",               "{L} | tee >(xargs kill) >/dev/null"),
    ("OUTPROC into a read loop",                "{L} > >(while read -r p; do kill \"$p\"; done)"),
]
SILENT = [
    ("GROUP a group counted",                   "{ {L}; } | wc -l; kill \"$SRV\""),
    ("GROUP a subshell to /dev/null",           "( {L} ) > /dev/null; kill \"$SRV\""),
    ("GROUP a count of a group's output",       "n=$( { {L}; } | wc -l ); kill \"$SRV\""),
    ("ECHOED a variable echoed into a count",   "P=$({L}); echo $P | wc -w; kill \"$SRV\""),
    ("PRINTF-V a count bound, kill by PID",     "printf -v n '%s' \"$({L} | wc -l)\"; [ \"$n\" -gt 0 ] && kill \"$SRV\""),
    ("POSITIONAL the pid set, lister apart",    "set -- \"$SRV\"; P=$({L}); kill \"$@\""),
    ("POSITIONAL a count of them",              "set -- $({L}); echo \"$#\"; kill \"$SRV\""),
    ("FUNCTION one that only echoes",           "f() { echo \"$@\"; }; f $({L}); kill \"$SRV\""),
    ("SH-C bash -c that only echoes",           "bash -c 'echo \"$@\"' _ $({L}); kill \"$SRV\""),
    ("XARGS-I sh -c that only echoes",          "{L} | xargs -I{} sh -c 'echo {}'; kill \"$SRV\""),
    ("EVAL eval assigns a count",               "eval \"n=$({L} | wc -l)\"; kill \"$SRV\""),
    ("OUTPROC tee into a count",                "{L} | tee >(wc -l) >/dev/null; kill \"$SRV\""),
    ("CLOSER a loop that only echoes",          "P=$({L}); while read -r p; do echo \"$p\"; done <<< \"$P\"; kill \"$SRV\""),
    ("CASE a lister in a case arm",             "case 1 in 1) {L} ;; esac; kill \"$SRV\""),
    ("FUNCTION kills its own argument",         "f() { kill \"$1\"; }; f \"$SRV\"; {L}"),
]
PRELUDE = "sleep 0.2 & SRV=$!; "     # every row: a pid this command started, read from $!


def verdict(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
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
    """Bash's own reading: run cmd with stand-ins and say whether a fake pid reached a kill."""
    log = os.path.join(d, "kill.log")
    if os.path.exists(log):
        os.remove(log)
    env = dict(os.environ, PATH=d + ":" + os.environ["PATH"], SWKILL_LOG=log)
    run = re.sub(r"(?<![\w-])kill(?![\w-])", "swkill", cmd)
    settle = "\nsleep 0.3" if ">(" in cmd else ""   # an output process substitution is async
    bash_oracle.run(["bash", "-c", run + "\nwait" + settle], env=env, cwd=d, capture_output=True,
                   timeout=20, stdin=subprocess.DEVNULL)
    text = open(log).read() if os.path.exists(log) else ""
    return any(p in text for p in FAKE_PIDS), text


def start_shared_name(n=2):
    d = tempfile.mkdtemp(prefix="mh-bind-live-")
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
    stubs = tempfile.mkdtemp(prefix="mh-bind-stubs-")
    make_stubs(stubs)
    live, procs = start_shared_name()
    try:
        for want, rows in ((True, REACH), (False, SILENT)):
            for label, tmpl in rows:
                reached, log = bash_reaches(PRELUDE + tmpl.replace("{L}", "pgrep -f x"), stubs)
                if reached != want:
                    failures.append("FIXTURE [%s]: bash says reached=%s, the row says %s; log %r"
                                    % (label, reached, want, log))
                    continue
                if not want and "KILL" not in log:
                    failures.append("FIXTURE [%s]: the pid from $! reached no kill" % label)
                for lname, lister in LISTER_FORMS:
                    cmd = PRELUDE + tmpl.replace("{L}", lister)
                    fired, err = verdict(cmd)
                    n += 1
                    if fired != want:
                        failures.append("%s [%s | %s]: %s%s" % (
                            "NOT REFUSED" if want else "FALSE REFUSAL", label, lname, cmd,
                            "" if want else "\n    said: " + err[:200]))
                    elif fired and "BLOCKED:" not in err:
                        failures.append("REFUSED SAYING NOTHING [%s | %s]" % (label, lname))
    finally:
        for p in procs:                # by PID, the construct this guard recommends
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=5)
        shutil.rmtree(live, ignore_errors=True)
        shutil.rmtree(stubs, ignore_errors=True)
    if failures:
        print("FAIL (%d of %d)" % (len(failures), n))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d cases (%d reach + %d silent templates x %d listers), each agreeing with bash"
          % (n, len(REACH), len(SILENT), len(LISTER_FORMS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
