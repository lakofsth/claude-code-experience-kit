"""Check of hooks/tests/INVARIANTS.md `mh-code-handed-to-a-shell-is-code`.

The sentence: hooks/block-unsafe-kill.sh analyses as shell code, by the same rules as
the command itself, every string the command hands another shell to run — the argument
of bash|sh -c (behind any wrapper), of eval and of env -S, and a heredoc, herestring or
echo/printf pipe read by a bare shell.

Directions pinned here, each derived from the sentence and not from any fix:

  1. -c argument: bash and sh, with the shell behind a wrapper (sudo, sudo -u, timeout,
     nohup, env VAR=), and a combined -lc.
  2. eval: quoted argument and bare words.
  3. env -S / env --split-string.
  4. heredoc fed to a bare shell: quoted and unquoted delimiters, and the SAME stdin
     spelled with the `-` operand (`bash - <<EOF`) or `-s`.
  5. herestring fed to a bare shell, bare and with `-`.
  6. echo/printf pipe into a bare shell, bare, wrapped, and with `-`.
  7. "the same rules as the command itself" INSIDE the handed string: a wait gate, a
     nested bash -c, a pgrep-into-kill, and a shared-name kill COUNTED (not just
     pattern-matched) with the two-process fixture.
  8. The quote rule travels with the code: a danger quoted inside a -c string is data
     and stays silent, exactly as it would at the top level.

The silent half matters as much as the blocked half: a check that blocks everything is
not a check of this sentence.
"""
import json, os, shutil, signal, subprocess, sys, tempfile, time
from _proc_names import proc_name, sleeper  # noqa: E402  (per-run comm names: host-wide pgrep must see only this run)

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

# comm is truncated to 15 characters, and pgrep -x matches comm — keep the name short.
PROC_NAME = proc_name("mhhnd")


def verdict(cmd):
    """(fired, stderr) — fired is True iff the hook exited non-zero."""
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


def start_shared_name(n=2):
    """n processes that all answer to PROC_NAME, so a name-keyed kill would stop all of them."""
    d = tempfile.mkdtemp(prefix="mh-handed-code-test-")
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
    for p in procs:                 # by PID — the construct the guard recommends
        try:
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=5)
        except Exception:
            pass
    shutil.rmtree(d, ignore_errors=True)


MUST_BLOCK = [
    # --- top-level anchor: the same rules, applied to the command itself --------------------
    ("anchor: bare pkill -f",                 "pkill -f myserver"),
    # --- direction 1: the argument of bash|sh -c, the shell behind any wrapper --------------
    ("bash -c argument",                      "bash -c 'pkill -f myserver'"),
    ("sh -c argument",                        "sh -c 'pkill -f myserver'"),
    ("bash -c behind sudo",                   "sudo bash -c 'pkill -f myserver'"),
    ("sh -c behind sudo -u USER",             "sudo -u alice sh -c 'killall python3'"),
    ("bash -c behind timeout",                "timeout 10 bash -c 'pkill -f myserver'"),
    ("bash -c behind nohup",                  "nohup bash -c 'pkill -f myserver'"),
    ("bash -c behind an assignment",          "env FOO=1 bash -c 'pkill -f myserver'"),
    ("bash -lc combined flag",                "bash -lc 'pkill -f myserver'"),
    # --- direction 2: the argument of eval ---------------------------------------------------
    ("eval, quoted argument",                 "eval 'pkill -f myserver'"),
    ("eval, bare words",                      "eval pkill -f myserver"),
    ("eval, killall",                         "eval \"killall python3\""),
    # --- direction 3: env -S -----------------------------------------------------------------
    ("env -S split string",                   "env -S 'pkill -f myserver'"),
    ("env --split-string=",                   "env --split-string='pkill -f myserver'"),
    # --- direction 4: a heredoc read by a bare shell, every spelling of its stdin -----------
    ("heredoc, quoted delimiter",             "bash <<'EOF'\npkill -f myserver\nEOF"),
    ("heredoc, unquoted delimiter",           "sh <<EOF\npkill -f myserver\nEOF"),
    ("heredoc to bash - (stdin script)",      "bash - <<'EOF'\npkill -f myserver\nEOF"),
    ("heredoc to sh -",                       "sh - <<'EOF'\npkill -f myserver\nEOF"),
    ("heredoc to sudo bash -",                "sudo bash - <<'EOF'\npkill -f myserver\nEOF"),
    ("heredoc to bash -s",                    "bash -s <<'EOF'\npkill -f myserver\nEOF"),
    # --- direction 5: a herestring read by a bare shell --------------------------------------
    ("herestring to bare bash",               "bash <<< 'pkill -f myserver'"),
    ("herestring to bare sh",                 "sh <<< 'killall python3'"),
    ("herestring to bash -",                  "bash - <<< 'pkill -f myserver'"),
    # --- direction 6: an echo/printf pipe read by a bare shell -------------------------------
    ("echo pipe into bare bash",              "echo 'pkill -f myserver' | bash"),
    ("printf pipe into bare sh",              "printf '%s\\n' 'pkill -f myserver' | sh"),
    ("printf pipe into bash -",               "printf '%s\\n' 'pkill -f myserver' | bash -"),
    ("echo pipe into sudo bash",              "echo 'pkill -f myserver' | sudo bash"),
    # --- direction 7: the same rules apply INSIDE the handed string --------------------------
    ("wait gate inside bash -c",              "bash -c 'until ! pgrep -f myserver; do sleep 1; done'"),
    ("nested bash -c inside bash -c",         "bash -c 'bash -c \"pkill -f myserver\"'"),
    ("pgrep -f into a kill inside a heredoc",
     "bash <<'EOF'\nfor p in $(pgrep -f myserver); do kill \"$p\"; done\nEOF"),
]

# The shared-name rule (count with the command's own matcher, deny above one) must reach
# into handed code too — that is what "by the same rules as the command itself" promises.
MUST_BLOCK += [
    ("shared-name kill counted inside bash -c",   "bash -c 'pkill -x " + PROC_NAME + "'"),
    ("shared-name kill counted inside heredoc",
     "bash <<'EOF'\npkill -x " + PROC_NAME + "\nEOF"),
]

MUST_BE_SILENT = [
    ("kill by the PID you captured",        "SRV=$!; sleep 1; kill \"$SRV\""),
    ("a data heredoc (cat, not a shell)",   "cat <<'EOF'\npkill -f myserver\nEOF"),
    ("a danger merely echoed",              "echo 'pkill -f myserver'"),
    ("a script path is not a handed string", "bash script.sh"),
    ("a harmless -c argument",              "bash -c 'echo hello'"),
    ("a harmless heredoc to bash -",        "bash - <<'EOF'\necho hello\nEOF"),
    ("python is not another shell",         "python3 - <<'EOF'\nprint('pkill -f myserver')\nEOF"),
    # direction 8: the quote rule travels with the code — quoted inside is data inside.
    ("danger quoted inside a -c string",    "bash -c 'echo \"pkill -f myserver\"'"),
]


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
    finally:
        stop_shared_name(d, procs)

    total = len(MUST_BLOCK) + len(MUST_BE_SILENT)
    if failures:
        print("FAIL (%d of %d cases)" % (len(failures), total))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d block + %d silent cases of handed shell code" % (len(MUST_BLOCK),
                                                                   len(MUST_BE_SILENT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
