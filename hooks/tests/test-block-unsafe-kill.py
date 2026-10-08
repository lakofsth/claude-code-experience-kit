"""Verdict test for hooks/block-unsafe-kill.sh, in BOTH directions.

The guard blocks by exit 2 + stderr (not permissionDecision), so "did it fire" and "what did it
say" are both read off the process. Three axes are asserted:

  1. BLOCK   — every dangerous shape exits 2, including the two added 2026-09-17: a wait gate
               keyed on a process NAME, and a kill by exact name that reaches more than one
               process.
  2. SILENT  — every correct shape exits 0 with nothing on stderr. A guard that fires on correct
               work teaches you to ignore it, which is this file's own stated design.
  3. RENDERS — the advice text arrives as the words that were written. It is built inside a
               QUOTED python heredoc precisely because an unquoted bash heredoc expands `$!`,
               `$$` and backticks in the guidance itself; this axis fails if that regresses.

The shared-name cases do not rely on whatever happens to be running: the test starts two copies
of a uniquely-named program of its own and stops them by PID afterwards, which is the construct
the guard recommends. The llama-server case that founded the 2026-09-17 widening is checked too,
but only when the host actually has more than one — it reports SKIP rather than passing quietly.
"""
import json, os, shutil, signal, subprocess, sys, tempfile

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

# comm is truncated to 15 characters, and pgrep -x matches comm — keep the name short.
PROC_NAME = "mhkilltest"


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
    procs = [subprocess.Popen([exe, "120"]) for _ in range(n)]
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
    ("pkill -f, the founding self-kill",        "pkill -f llama-server"),
    ("killall",                                 "killall python3"),
    ("pgrep -f resolved into a kill",           "for p in $(pgrep -f myserver); do kill \"$p\"; done"),
    ("D740 regression: apostrophe upstream",    "echo \"it's fine\" ; pkill -f 'llama-server'"),
    ("2026-08-31: pgrep -f wait gate",          "until ! pgrep -f llama-server; do sleep 10; done"),
    # --- added 2026-09-17: the wait gate keyed on a NAME -----------------------------------
    ("THE SPECIMEN: pgrep -x wait gate",        "until ! pgrep -x llama-server; do sleep 10; done"),
    ("bare pgrep wait gate",                    "while pgrep llama-server >/dev/null; do sleep 5; done"),
    ("pgrep -x wait gate, quoted name",         "until ! pgrep -x 'llama-server'; do sleep 10; done"),
    ("while-gate waiting for it to APPEAR",     "until pgrep -x llama-server; do sleep 2; done"),
    # --- added 2026-09-17: the kill by a name this host shares ------------------------------
    ("pkill -x on a shared name",               "pkill -x " + PROC_NAME),
    ("pkill -x on a shared name, quoted",       "pkill -x '" + PROC_NAME + "'"),
    ("pkill -x with a signal flag first",       "pkill -9 -x " + PROC_NAME),
    ("pkill --exact on a shared name",          "pkill --exact " + PROC_NAME),
    ("pgrep -x on a shared name, into a kill",  "for p in $(pgrep -x " + PROC_NAME + "); do kill \"$p\"; done"),
]

MUST_BE_SILENT = [
    ("kill by the PID you captured",            "SRV=$!; sleep 1; kill \"$SRV\""),
    ("pgrep -f with no kill anywhere",          "pgrep -f llama-server"),
    ("pgrep -x with no kill anywhere",          "pgrep -x llama-server"),
    ("pgrep -x counted, not killed",            "pgrep -x llama-server | wc -l"),
    ("pkill -x on a name nothing answers to",   "pkill -x mh-no-such-process-xyz"),
    ("STATED LIMIT: name in a variable",        "pkill -x \"$NAME\""),
    ("the recommended resource gate",           "until [ \"$(nvidia-smi --query-gpu=memory.used "
                                                "--format=csv,noheader,nounits)\" -lt 1000 ]; do sleep 5; done"),
    ("wait on the PID you started",             "SRV=$!; wait \"$SRV\""),
    ("a loop that merely shares a line",        "while read -r l; do echo \"$l\"; done < f; pgrep -x llama-server"),
    ("the danger named in a commit message",    GC + " -m 'stop recommending pkill -x llama-server'"),
    ("the danger named in a heredoc",           "cat <<'EOF'\nuntil ! pgrep -x llama-server; do sleep 10; done\nEOF"),
    ("the danger echoed as data",               "echo \"until ! pgrep -x llama-server; do sleep 10; done\""),
    # 2026-09-27: the inert forms of a substitution — these are data, and must stay silent.
    ("backticks in a QUOTED heredoc",           "python3 - <<'EOF'\nnote = 'x `pkill -f run.sh` y'\nEOF"),
    ("backticks in a double-QUOTED delimiter",  "cat <<\"EOF\"\n`pkill -f run.sh`\nEOF"),
    ("backticks in a backslash-quoted delim",   "cat <<\\EOF\n$(killall python3)\nEOF"),
    ("backticks in single quotes",              "echo 'x `pkill -f run.sh` y'"),
]

# 2026-09-27 (session 0fd30f6c): a substitution is CODE wherever bash runs it — inside an
# UNQUOTED heredoc body and inside "...". The strip treated every heredoc and every "..." as
# data, so `python3 - <<EOF` carrying note text with a backticked `pkill -f "tests/run.sh
# --fast"` passed this guard and executed as the operator: it killed its own shell by
# self-match and was refused only by uid for every worker it also matched.
MUST_BLOCK += [
    ("pkill -f in backticks, unquoted heredoc", "python3 - <<EOF\nnote = 'x `pkill -f run.sh` y'\nEOF"),
    ("pkill -f in $(), unquoted heredoc",       "cat <<EOF\nline $(pkill -f run.sh) line\nEOF"),
    ("killall in $(), unquoted <<- heredoc",    "cat <<-EOF\n\t$(killall python3)\n\tEOF"),
    ("pkill -f in backticks inside \"...\"",     "echo \"x `pkill -f run.sh` y\""),
    ("killall in $() inside \"...\"",            "msg=\"now $(killall python3) done\""),
]

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
        _, err = verdict("pkill -f llama-server")
        for want in MUST_RENDER:
            if want not in err:
                failures.append("ADVICE DID NOT RENDER: %r missing from the kill advice" % want)
        # Read off the pgrep -f gate, not the -x one: this arm fires in every revision of the
        # hook, so a red-first run against an older copy shows detector misses only, and does
        # not also report "the advice did not render" for a case that simply never fired.
        _, werr = verdict("until ! pgrep -f llama-server; do sleep 10; done")
        for want in ("wait \"$PID\"", "$done_marker"):
            if want not in werr:
                failures.append("ADVICE DID NOT RENDER: %r missing from the wait advice" % want)
        if "command not found" in err or "bash:" in err:
            failures.append("ADVICE RENDERED AS SHELL ERRORS: %r" % err[:300])

        # The founding case, against the live host. Reported, never passed quietly.
        real = subprocess.run(["pgrep", "-x", "llama-server"], capture_output=True, text=True)
        n = len([x for x in real.stdout.split() if x.isdigit()])
        if n > 1:
            fired, err = verdict("pkill -x llama-server")
            if not fired:
                failures.append("NOT BLOCKED [founding case]: pkill -x llama-server, "
                                "with %d live on this host" % n)
            else:
                print("founding case: pkill -x llama-server blocked, %d live processes named" % n)
        else:
            print("founding case: SKIPPED — only %d process named llama-server on this host "
                  "right now, so the shared-name branch has nothing to catch" % n)
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
