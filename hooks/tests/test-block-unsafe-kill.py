"""Verdict test for hooks/block-unsafe-kill.sh, in BOTH directions.

The guard blocks by exit 2 + stderr (not permissionDecision), so "did it fire" and "what did it
say" are both read off the process. Three axes are asserted:

  1. BLOCK   — every dangerous shape exits 2, including a wait gate keyed on a process NAME,
               and a kill by exact name that reaches more than one process.
  2. SILENT  — every correct shape exits 0 with nothing on stderr. A guard that fires on correct
               work teaches you to ignore it, which is this file's own stated design.
  3. RENDERS — the advice text arrives as the words that were written. It is built inside a
               QUOTED python heredoc precisely because an unquoted bash heredoc expands `$!`,
               `$$` and backticks in the guidance itself; this axis fails if that regresses.

The shared-name cases do not rely on whatever happens to be running: the test starts two copies
of a uniquely-named program of its own and stops them by PID afterwards, which is the construct
the guard recommends.
"""
import json, os, shutil, signal, subprocess, sys, tempfile
from _proc_names import proc_name, sleeper  # noqa: E402  (per-run comm names: host-wide pgrep must see only this run)

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

# comm is truncated to 15 characters, and pgrep -x matches comm — keep the name short.
PROC_NAME = proc_name("mhbk")


def verdict(cmd):
    """(fired, stderr) — fired is True iff the hook exited non-zero."""
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


def start_shared_name(n=2):
    """n processes that all answer to PROC_NAME, so `pkill -x PROC_NAME` would stop all of them."""
    d = tempfile.mkdtemp(prefix="mh-unsafe-kill-test-")
    exe = os.path.join(d, PROC_NAME)
    shutil.copy2("/bin/sleep", exe)
    procs = [sleeper(exe) for _ in range(n)]
    for _ in range(50):
        r = subprocess.run(["pgrep", "-x", PROC_NAME], capture_output=True, text=True)
        if len([x for x in r.stdout.split() if x.isdigit()]) >= n:
            break
        import time; time.sleep(0.05)
    return d, procs


def stop_shared_name(d, procs):
    for p in procs:                 # by PID — the construct this guard recommends
        try:
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=5)
        except Exception:
            pass
    shutil.rmtree(d, ignore_errors=True)


GC = "git commit"

MUST_BLOCK = [
    # --- the shapes this file has always blocked ------------------------------------------
    ("pkill -f, the self-kill",                "pkill -f myserver"),
    ("killall",                                 "killall python3"),
    ("pgrep -f resolved into a kill",           "for p in $(pgrep -f myserver); do kill \"$p\"; done"),
    ("D740: apostrophe upstream",                  "echo \"it's fine\" ; pkill -f 'myserver'"),
    ("pgrep -f wait gate",                     "until ! pgrep -f myserver; do sleep 10; done"),
    # --- the wait gate keyed on a NAME ----------------------------------------------------
    ("pgrep -x wait gate",                     "until ! pgrep -x myserver; do sleep 10; done"),
    ("bare pgrep wait gate",                    "while pgrep myserver >/dev/null; do sleep 5; done"),
    ("pgrep -x wait gate, quoted name",         "until ! pgrep -x 'myserver'; do sleep 10; done"),
    ("while-gate waiting for it to APPEAR",     "until pgrep -x myserver; do sleep 2; done"),
    # --- the kill by a name the host shares ----------------------------------------------
    ("pkill -x on a shared name",               "pkill -x " + PROC_NAME),
    ("pkill -x on a shared name, quoted",       "pkill -x '" + PROC_NAME + "'"),
    ("pkill -x with a signal flag first",       "pkill -9 -x " + PROC_NAME),
    ("pkill --exact on a shared name",          "pkill --exact " + PROC_NAME),
    ("pgrep -x on a shared name, into a kill",  "for p in $(pgrep -x " + PROC_NAME + "); do kill \"$p\"; done"),
]

MUST_BE_SILENT = [
    ("kill by the PID you captured",            "SRV=$!; sleep 1; kill \"$SRV\""),
    ("pgrep -f with no kill anywhere",          "pgrep -f myserver"),
    ("pgrep -x with no kill anywhere",          "pgrep -x myserver"),
    ("pgrep -x counted, not killed",            "pgrep -x myserver | wc -l"),
    ("pkill -x on a name nothing answers to",   "pkill -x mh-no-such-process-xyz"),
    ("STATED LIMIT: name in a variable",        "pkill -x \"$NAME\""),
    ("the recommended resource gate",           "until [ \"$(free -m | awk '/^Mem:/{print $7}')\" "
                                                "-gt 4096 ]; do sleep 5; done"),
    ("wait on the PID you started",             "SRV=$!; wait \"$SRV\""),
    ("a loop that merely shares a line",        "while read -r l; do echo \"$l\"; done < f; pgrep -x myserver"),
    ("the danger named in a commit message",    GC + " -m 'stop recommending pkill -x myserver'"),
    ("the danger named in a heredoc",           "cat <<'EOF'\nuntil ! pgrep -x myserver; do sleep 10; done\nEOF"),
    ("the danger echoed as data",               "echo \"until ! pgrep -x myserver; do sleep 10; done\""),
    # the inert forms of a substitution — these are data, and must stay silent.
    ("backticks in a QUOTED heredoc",           "python3 - <<'EOF'\nnote = 'x `pkill -f run.sh` y'\nEOF"),
    ("backticks in a double-QUOTED delimiter",  "cat <<\"EOF\"\n`pkill -f run.sh`\nEOF"),
    ("backticks in a backslash-quoted delim",   "cat <<\\EOF\n$(killall python3)\nEOF"),
    ("backticks in single quotes",              "echo 'x `pkill -f run.sh` y'"),
]

# A substitution is CODE wherever bash runs it — inside an UNQUOTED heredoc body and inside
# "...": a backticked `pkill -f X` inside an unquoted heredoc body runs as code.
MUST_BLOCK += [
    ("pkill -f in backticks, unquoted heredoc", "python3 - <<EOF\nnote = 'x `pkill -f run.sh` y'\nEOF"),
    ("pkill -f in $(), unquoted heredoc",       "cat <<EOF\nline $(pkill -f run.sh) line\nEOF"),
    ("killall in $(), unquoted <<- heredoc",    "cat <<-EOF\n\t$(killall python3)\n\tEOF"),
    ("pkill -f in backticks inside \"...\"",     "echo \"x `pkill -f run.sh` y\""),
    ("killall in $() inside \"...\"",            "msg=\"now $(killall python3) done\""),
]

# A lister's pids are refused exactly when they REACH a kill, through every placement. Each
# template has one {L}, run for pgrep -f (refused by structure) and for pgrep -x and pidof on
# PROC_NAME (two live processes: refused by count).
#   INPUT  -- a herestring or process substitution is read by its host: a kill (`xargs kill <<<`)
#             is reached, a command that passes its input on is climbed out of, and a `read` binds
#             only its own variables.
#   ARITH  -- a lister in arithmetic reaches what its value reaches: a word of the kill, or a
#             variable the arithmetic assigns, never merely because a kill is in the call, so a
#             count beside a kill by PID passes.
#   ARRAY / INNERMOST -- an array literal whose substitution is not its first word, and a lister
#             whose innermost host binds what an outer one does not.
LISTER_FORMS = [("pgrep -f", "pgrep -f mh-no-such-pattern"), ("pgrep -x", "pgrep -x " + PROC_NAME),
                ("pidof", "pidof " + PROC_NAME)]
REACH_REFUSE = [
    ("INPUT xargs kill <<< \"$(L)\"",           "xargs kill <<< \"$({L})\""),
    ("INPUT xargs kill <<<$(L) bare",           "xargs -r kill <<<$({L})"),
    ("INPUT kill $(cat <<< \"$(L)\")",          "kill $(cat <<< \"$({L})\")"),
    ("INPUT xargs kill < <(L)",                 "xargs kill < <({L})"),
    ("INPUT kill $(cat <(L))",                  "kill $(cat <({L}))"),
    ("INPUT xargs -a <(L) kill",                "xargs -a <({L}) kill"),
    ("INPUT a passer piped into a kill",        "cat <<< \"$({L})\" | xargs kill"),
    ("INPUT an echo piped into a kill",         "echo $({L}) | xargs kill"),
    ("INPUT while read; done <<< \"$(L)\"",     "while read -r p; do kill \"$p\"; done <<< \"$({L})\""),
    ("INPUT while read; done < <(L)",           "while read -r p; do kill \"$p\"; done < <({L})"),
    ("INPUT a group's read",                    "{ read -r p; } <<< \"$({L})\"; kill \"$p\""),
    ("ARITH kill $(( $(L) ))",                  "kill $(( $({L}) ))"),
    ("ARITH kill -9 $(( $(L) + 0 ))",           "kill -9 $(( $({L}) + 0 ))"),
    ("ARITH x=$(( $(L) )); kill $x",            "x=$(( $({L}) )); kill $x"),
    ("ARITH (( p = $(L) )); kill $p",           "(( p = $({L}) )); kill $p"),
    ("ARITH (( p += $(L) )); kill $p",          "p=0; (( p += $({L}) )); kill \"$p\""),
    ("ARITH through a passer",                  "kill $(( $(echo $({L})) ))"),
    ("ARRAY the substitution is not first",     "pids=(1 2 $({L})); kill \"${pids[@]}\""),
    ("ARRAY declare, not first",                "declare -a pids=(1 2 $({L})); kill ${pids[@]}"),
    ("INNERMOST the inner host binds",          "out=$(P=$({L}); kill $P)"),
]
REACH_SILENT = [
    ("ARITH a count guarding a kill by PID",    "if (( $({L}) > 0 )); then kill \"$SRV\"; fi"),
    ("ARITH a count assigned, kill by PID",     "x=$(( $({L}) + 0 )); kill \"$SRV\""),
    ("ARITH (( n = $(L) )), kill by PID",       "(( n = $({L}) )); kill \"$SRV\""),
    ("ARITH a comparison, kill by PID",         "[ $(( $({L}) )) -gt 0 ] && kill \"$SRV\""),
    ("INPUT a herestring read beside a pid file", "read -r SRV < f; read -r n <<< \"$({L})\"; kill \"$SRV\""),
    ("INPUT a proc-subst read beside a pid file", "read -r SRV < f; read -r n < <({L}); kill \"$SRV\""),
    ("INPUT a loop that only echoes",           "while read -r n; do echo $n; done <<< \"$({L})\"; kill \"$SRV\""),
    ("INPUT a loop's read beside a pid file",   "read -r SRV < f; while read -r n; do echo $n; done <<< \"$({L})\"; kill \"$SRV\""),
    ("ARITH a name= inside its substitution",   "(( n = $({L} | grep -c pid=) )); kill \"$pid\""),
    ("INPUT a passer counted, kill by PID",     "cat <<< \"$({L})\" | wc -l; kill \"$SRV\""),
    ("INNERMOST the inner host is echoed",      "out=$(P=$({L}); echo $P); kill \"$SRV\""),
]
for _lname, _lister in LISTER_FORMS:
    MUST_BLOCK += [("%s | %s" % (lb, _lname), t.replace("{L}", _lister)) for lb, t in REACH_REFUSE]
    MUST_BE_SILENT += [("%s | %s" % (lb, _lname), t.replace("{L}", _lister)) for lb, t in REACH_SILENT]

# Words that must survive into the rendered advice. Each is a shape an unquoted bash heredoc
# would have destroyed: $! and $$ expand, backticks execute.
MUST_RENDER = ["SRV=$!", "$PPID", "$$", "pgrep -x <name> | wc -l"]


def main():
    d, procs = start_shared_name()
    live = subprocess.run(["pgrep", "-x", PROC_NAME], capture_output=True, text=True)
    if len([x for x in live.stdout.split() if x.isdigit()]) < 2:
        stop_shared_name(d, procs)
        print("SETUP FAILED: could not start two processes named " + PROC_NAME)
        return 2

    failures = []
    try:
        for label, cmd in MUST_BLOCK:
            fired, err = verdict(cmd)
            if not fired:
                failures.append("NOT BLOCKED [%s]: %s" % (label, cmd))
            elif "BLOCKED:" not in err:
                failures.append("BLOCKED but said nothing useful [%s]: %r" % (label, err[:200]))
        for label, cmd in MUST_BE_SILENT:
            fired, err = verdict(cmd)
            if fired:
                failures.append("FALSE POSITIVE [%s]: %s\n    said: %s" % (label, cmd, err[:300]))

        # The rendering axis, read off a real firing.
        _, err = verdict("pkill -f myserver")
        for want in MUST_RENDER:
            if want not in err:
                failures.append("ADVICE DID NOT RENDER: %r missing from the kill advice" % want)
        # Read off the pgrep -f gate, not the -x one: this arm fires in every revision of the
        # hook, so a red-first run against an older copy shows detector misses only, and does
        # not also report "the advice did not render" for a case that simply never fired.
        _, werr = verdict("until ! pgrep -f myserver; do sleep 10; done")
        for want in ("wait \"$PID\"", "$done_marker"):
            if want not in werr:
                failures.append("ADVICE DID NOT RENDER: %r missing from the wait advice" % want)
        if "command not found" in err or "bash:" in err:
            failures.append("ADVICE RENDERED AS SHELL ERRORS: %r" % err[:300])

    finally:
        stop_shared_name(d, procs)

    total = len(MUST_BLOCK) + len(MUST_BE_SILENT)
    if failures:
        print("FAIL (%d of %d cases + render axis)" % (len(failures), total))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d block + %d silent cases, advice renders" % (len(MUST_BLOCK), len(MUST_BE_SILENT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
