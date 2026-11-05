"""Check of hooks/tests/INVARIANTS.md `mh-code-handed-to-a-shell-is-code`, as amended
2026-10-27 to name the programs that run a string as shell code.

The sentence: hooks/block-unsafe-kill.sh analyses as shell code, by the same rules as the
command itself, every string the command hands another shell to run: the argument of
bash|sh -c (behind any wrapper), of eval and of env -S, and a heredoc, herestring or
echo/printf pipe read by a bare shell — and every string a program runs as shell code by
its own documented reading: flock FILE -c, su/runuser -c (and runuser -u U -- CMD), watch's
command words (argv with -x), script -c, trap's action, tmux's shell-command arguments and
send-keys, and an at/batch job read on stdin.

Directions, each derived from the sentence and not from any fix:

  A. the clauses carried over (a few anchors each): bash|sh -c behind a wrapper, eval,
     env -S, heredoc / herestring / echo|printf pipe into a bare shell.
  B. flock FILE -c CMD, with options before the file, the long --command spelling, and a
     lock given as a directory.
  C. su -c and runuser -c, with a user before or after -c, `su -` / `-l`, --command= ;
     and runuser -u U -- CMD (an argv, run as the command it is).
  D. watch's command words: one quoted string, several bare words joined (as watch joins
     them for sh -c), with interval options before them, and -x (exec'd argv).
  E. script -c / --command, with the typescript file after it.
  F. trap's action, with `--` and with several signals.
  G. tmux's shell-command arguments (new-session, new-window, split-window, run-shell,
     respawn-pane, if-shell) and send-keys, whose keys a shell in the pane reads.
  H. an at/batch job read on stdin: a pipe from echo/printf, a heredoc, a herestring.
  I. "by the same rules as the command itself" inside those strings: a wait gate, a
     pgrep -f into kill, a nested bash -c, and a shared-name kill COUNTED with a
     two-process fixture (not merely pattern-matched).
  J. the silent half: each program handed harmless code, or handed the danger as QUOTED
     DATA inside its string, stays silent — exactly as the same text would at top level.
     A check that blocks everything is not a check of this sentence.
"""
import json, os, shutil, signal, subprocess, sys, tempfile, time
from _proc_names import proc_name, sleeper  # noqa: E402  (per-run comm names: host-wide pgrep must see only this run)

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

# comm is truncated to 15 characters, and pgrep -x matches comm — keep the name short.
PROC_NAME = proc_name("mhshp")

K = "pkill -f myserver"            # the structural danger: needs no process table


def verdict(cmd):
    """(fired, stderr) — fired is True iff the hook exited non-zero."""
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


def start_shared_name(n=2):
    d = tempfile.mkdtemp(prefix="mh-shprog-cert-")
    exe = os.path.join(d, PROC_NAME)
    shutil.copy2("/bin/sleep", exe)
    procs = [sleeper(exe) for _ in range(n)]
    for _ in range(50):
        r = subprocess.run(["pgrep", "-x", PROC_NAME], capture_output=True, text=True)
        if len([x for x in r.stdout.split() if x.isdigit()]) >= n:
            break
        time.sleep(0.05)
    return d, procs


def stop_shared_name(d, procs):
    for p in procs:                     # by PID
        try:
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=5)
        except Exception:
            pass
    shutil.rmtree(d, ignore_errors=True)


MUST_BLOCK = [
    ("anchor: the danger at top level",          K),
    # --- A: the clauses carried over --------------------------------------------------------
    ("A bash -c behind timeout",                 "timeout 9 bash -c '%s'" % K),
    ("A sh -c behind sudo -u",                   "sudo -u alice sh -c '%s'" % K),
    ("A eval",                                   "eval '%s'" % K),
    ("A env -S",                                 "env -S '%s'" % K),
    ("A heredoc into bash",                      "bash <<'EOF'\n%s\nEOF" % K),
    ("A herestring into sh",                     "sh <<< '%s'" % K),
    ("A echo pipe into bash",                    "echo '%s' | bash" % K),
    ("A printf pipe into sh",                    "printf '%%s\\n' '%s' | sh" % K),
    # --- B: flock FILE -c -------------------------------------------------------------------
    ("B flock FILE -c",                          "flock /tmp/mh.lock -c '%s'" % K),
    ("B flock -w N FILE -c",                     "flock -w 5 /tmp/mh.lock -c '%s'" % K),
    ("B flock -x -n FILE -c",                    "flock -x -n /tmp/mh.lock -c '%s'" % K),
    ("B flock FILE --command",                   "flock /tmp/mh.lock --command '%s'" % K),
    ("B flock DIR -c, double quotes",            'flock /tmp -c "%s"' % K),
    ("B flock -c behind timeout",                "timeout 30 flock /tmp/mh.lock -c '%s'" % K),
    ("B flock -c after other code",              "cd /tmp && flock mh.lock -c '%s'" % K),
    # --- C: su / runuser ---------------------------------------------------------------------
    ("C su -c CMD",                              "su -c '%s'" % K),
    ("C su USER -c CMD",                         "su alice -c '%s'" % K),
    ("C su -c CMD USER",                         "su -c '%s' alice" % K),
    ("C su - USER -c CMD",                       "su - alice -c '%s'" % K),
    ("C su -l USER -c CMD",                      "su -l alice -c '%s'" % K),
    ("C su --command=CMD",                       "su --command='%s' alice" % K),
    ("C su --command CMD",                       "su --command '%s' alice" % K),
    ("C sudo su -c CMD",                         "sudo su -c '%s'" % K),
    ("C runuser -c CMD",                         "runuser -c '%s'" % K),
    ("C runuser USER -c CMD",                    "runuser alice -c '%s'" % K),
    ("C runuser -l USER -c CMD",                 "runuser -l alice -c '%s'" % K),
    ("C runuser -u U -- CMD",                    "runuser -u alice -- %s" % K),
    ("C sudo runuser -u U -- CMD",               "sudo runuser -u alice -- %s" % K),
    ("C runuser -u U -- killall",                "runuser -u alice -- killall python3"),
    # --- D: watch ------------------------------------------------------------------------------
    ("D watch 'CMD'",                            "watch '%s'" % K),
    ("D watch -n 1 'CMD'",                       "watch -n 1 '%s'" % K),
    ("D watch -n1 -t 'CMD'",                     "watch -n1 -t '%s'" % K),
    ("D watch --interval 2 'CMD'",               "watch --interval 2 '%s'" % K),
    ("D watch bare words",                       "watch %s" % K),
    ("D watch -n 1 bare words",                  "watch -n 1 %s" % K),
    ("D watch -x argv",                          "watch -x %s" % K),
    ("D watch -n 2 -x argv",                     "watch -n 2 -x %s" % K),
    ("D watch -x bash -c",                       "watch -x bash -c '%s'" % K),
    ("D watch --exec argv",                      "watch --exec %s" % K),
    # --- E: script -c --------------------------------------------------------------------------
    ("E script -c CMD FILE",                     "script -c '%s' /tmp/ts.log" % K),
    ("E script -q -c CMD /dev/null",             "script -q -c '%s' /dev/null" % K),
    ("E script --command CMD",                   "script --command '%s' /dev/null" % K),
    ("E script -qc CMD",                         "script -qc '%s' /dev/null" % K),
    # --- F: trap's action ----------------------------------------------------------------------
    ("F trap ACTION EXIT",                       "trap '%s' EXIT" % K),
    ("F trap -- ACTION INT TERM",                "trap -- '%s' INT TERM" % K),
    ("F trap ACTION EXIT; work",                 "trap \"%s\" EXIT; sleep 1" % K),
    ("F trap killall",                           "trap 'killall python3' EXIT"),
    # --- G: tmux ---------------------------------------------------------------------------------
    ("G tmux new-session -d CMD",                "tmux new-session -d '%s'" % K),
    ("G tmux new -d -s NAME CMD",                "tmux new -d -s mh '%s'" % K),
    ("G tmux new-window CMD",                    "tmux new-window '%s'" % K),
    ("G tmux new-window -t T -n N CMD",          "tmux new-window -t mh -n w '%s'" % K),
    ("G tmux split-window CMD",                  "tmux split-window -h '%s'" % K),
    ("G tmux run-shell CMD",                     "tmux run-shell '%s'" % K),
    ("G tmux run CMD",                           "tmux run -b '%s'" % K),
    ("G tmux respawn-pane -k CMD",               "tmux respawn-pane -k -t mh '%s'" % K),
    ("G tmux if-shell CMD",                      "tmux if-shell '%s' 'display ok'" % K),
    ("G tmux send-keys CMD Enter",               "tmux send-keys -t mh '%s' Enter" % K),
    ("G tmux send-keys CMD C-m",                 "tmux send-keys -t mh:0 '%s' C-m" % K),
    ("G tmux send CMD Enter",                    "tmux send -t mh '%s' Enter" % K),
    # --- H: at / batch on stdin --------------------------------------------------------------------
    ("H echo | at",                              "echo '%s' | at now + 1 minute" % K),
    ("H printf | at",                            "printf '%%s\\n' '%s' | at now" % K),
    ("H echo | batch",                           "echo '%s' | batch" % K),
    ("H at heredoc",                             "at now + 5 minutes <<'EOF'\n%s\nEOF" % K),
    ("H at heredoc unquoted",                    "at now <<EOF\n%s\nEOF" % K),
    ("H batch heredoc",                          "batch <<'EOF'\n%s\nEOF" % K),
    ("H at herestring",                          "at now <<< '%s'" % K),
    ("H batch herestring",                       "batch <<< '%s'" % K),
    # --- I: the same rules inside those strings ---------------------------------------------------
    ("I flock -c wait gate",                     "flock /tmp/mh.lock -c 'until ! pgrep -f myserv; do sleep 1; done'"),
    ("I su -c pgrep -f into kill",               "su -c 'kill $(pgrep -f myserver)' alice"),
    ("I trap nested bash -c",                    "trap \"bash -c 'pkill -f myserver'\" EXIT"),
    ("I watch wait gate",                        "watch 'while pgrep -f myserv; do sleep 1; done'"),
    ("I tmux new-window nested sh -c",           "tmux new-window \"sh -c 'pkill -f myserv'\""),
    ("I at heredoc pgrep -f | xargs kill",       "at now <<'EOF'\npgrep -f myserver | xargs kill\nEOF"),
    ("I script -c killall",                      "script -q -c 'killall myserver' /dev/null"),
]

# A shared-name kill must be COUNTED inside these strings, as it would be at top level.
MUST_COUNT = [
    ("I count: anchor at top level",             "pkill -x %s" % PROC_NAME),
    ("I count: flock -c",                        "flock /tmp/mh.lock -c 'pkill -x %s'" % PROC_NAME),
    ("I count: su -c",                           "su -c 'pkill %s' alice" % PROC_NAME),
    ("I count: trap",                            "trap 'pkill -x %s' EXIT" % PROC_NAME),
    ("I count: watch -x",                        "watch -x pkill -x %s" % PROC_NAME),
    ("I count: runuser -u U --",                 "runuser -u alice -- pkill -x %s" % PROC_NAME),
    ("I count: tmux send-keys",                  "tmux send-keys -t mh 'pkill -x %s' Enter" % PROC_NAME),
    ("I count: at herestring",                   "at now <<< 'pkill -x %s'" % PROC_NAME),
]

MUST_STAY_SILENT = [
    # harmless code handed to each program
    ("J flock -c harmless",                      "flock /tmp/mh.lock -c 'make -j4'"),
    ("J su -c harmless",                         "su -c 'systemctl status nginx' alice"),
    ("J runuser -u U -- harmless",               "runuser -u alice -- ls -la"),
    ("J watch harmless",                         "watch -n 1 'uptime'"),
    ("J watch -x harmless",                      "watch -x ls /tmp"),
    ("J script -c harmless",                     "script -q -c 'make test' /dev/null"),
    ("J trap harmless",                          "trap 'rm -f /tmp/mh.lock' EXIT"),
    ("J trap kill by PID",                       "trap 'kill \"$SRV\"' EXIT"),
    ("J tmux new-session harmless",              "tmux new-session -d -s mh 'htop'"),
    ("J tmux send-keys harmless",                "tmux send-keys -t mh 'make' Enter"),
    ("J echo | at harmless",                     "echo 'make test' | at now"),
    ("J at heredoc harmless",                    "at now <<'EOF'\nmake test\nEOF"),
    # the danger as QUOTED DATA inside the string: data at top level, data here
    ("J flock -c danger quoted as data",         "flock /tmp/mh.lock -c 'echo \"%s\"'" % K),
    ("J su -c danger quoted as data",            "su -c 'echo \"%s\"' alice" % K),
    ("J trap danger quoted as data",             "trap 'echo \"%s\" >> /tmp/log' EXIT" % K),
    ("J tmux send-keys danger as data",          "tmux send-keys -t mh 'echo \"%s\"' Enter" % K),
    ("J at heredoc danger as data",              "at now <<'EOF'\necho \"%s\"\nEOF" % K),
    # the programs' non-code arguments are not code
    ("J flock FILE without -c",                  "flock /tmp/mh.lock true"),
    ("J tmux display-message mentions pkill",    "tmux display-message 'pkill -f is refused here'"),
    ("J at -f FILE",                             "at -f /tmp/job.sh now"),
    ("J a grep for the danger is data",          "grep -n '%s' notes.txt" % K),
]


def main():
    fails = []
    for label, cmd in MUST_BLOCK:
        fired, err = verdict(cmd)
        if not fired:
            fails.append("SILENT, must block  [%s]  %r" % (label, cmd))
    d, procs = start_shared_name(2)
    try:
        for label, cmd in MUST_COUNT:
            fired, err = verdict(cmd)
            if not fired:
                fails.append("SILENT, must count (2 processes share %s)  [%s]  %r"
                             % (PROC_NAME, label, cmd))
            elif "2 processes" not in err:
                fails.append("blocked but not COUNTED  [%s]  %r -> %s"
                             % (label, cmd, err.splitlines()[0] if err else ""))
    finally:
        stop_shared_name(d, procs)
    for label, cmd in MUST_STAY_SILENT:
        fired, err = verdict(cmd)
        if fired:
            fails.append("BLOCKED, must stay silent  [%s]  %r -> %s"
                         % (label, cmd, err.splitlines()[0] if err else ""))
    total = len(MUST_BLOCK) + len(MUST_COUNT) + len(MUST_STAY_SILENT)
    for f in fails:
        print("  FAIL " + f)
    print("%d of %d cases failed" % (len(fails), total))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
