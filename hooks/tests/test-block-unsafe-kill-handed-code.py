"""Check of mh-code-handed-to-a-shell-is-code.

    hooks/block-unsafe-kill.sh analyses as shell code, by the same rules as the command
    itself, every string the command hands another shell to run: the argument of bash|sh -c
    (behind any wrapper), of eval and of env -S, and a heredoc, herestring or echo/printf
    pipe read by a bare shell.

Every case below is derived from a direction of that sentence, not from the guard's code:

  A  the argument of `bash -c` / `sh -c`, spelled with any quoting, any shell of the family,
     any flag combination that carries `-c`, and an absolute path;
  B  the same argument BEHIND ANY WRAPPER (sudo, timeout, env, command, nohup, nice, xargs);
  C  the argument of `eval`;
  D  the argument of `env -S` / `--split-string`, which reaches the nested shell already split;
  E  a heredoc read by a bare shell (quoted, unquoted, tab-stripped, behind a wrapper);
  F  a herestring read by a bare shell;
  G  an `echo` pipe read by a bare shell;
  H  a `printf` pipe read by a bare shell — including the FORMAT-ARGUMENT spelling, where the
     string the shell runs is printf's ARGUMENT and the format string is only `%s`/`%b`;
  I  "by the same rules as the command itself": the nested code is judged by every arm of the
     guard, not only the pkill -f one — a pgrep -f + kill loop, an until/while wait gate, a
     ps listing piped into a kill, and a danger that is not the first thing in the string;
  J  nesting: code handed to a shell that itself hands code to a shell;
  K  the same three stdin channels (heredoc, herestring, pipe) read by a shell that says so with
     an explicit operand: `-`, `-s`, `--`. A shell told to read its script from stdin is the
     paradigm bare shell, and each of these spellings really does run what it reads.

  L  a PROGRAM that hands its argument to a shell itself:
     flock FILE -c, su/runuser -c (any position, `-lc`, `--command=`, `--session-command`),
     watch (its arguments joined and given to `sh -c`; argv with -x), script -c, trap's action,
     tmux's shell-command arguments and send-keys, and at/batch reading their job on stdin.
     Every host template is a METAMORPHIC PAIR: it is run with each danger above and with a
     harmless command, and the verdict must be the danger's own (refused) and the harmless
     command's own (silent). Where the host can be run here (flock, script, trap) it is first
     RUN with `echo RAN > marker`, and the marker must appear: bash and the host themselves say
     the string is code, not this file. su needs a password, at would queue a real job, and
     watch and tmux need a terminal or a server; for those the man page is the reading
     (watch, run under `script`, writes the marker).

SILENT cases pin the other half of the same reading: a string that is NOT handed to a shell
(data, a commit message, a heredoc read by cat) is still data, and a shell running a script
path is not handed a string. A guard that fires on those teaches you to ignore it.
"""
import json, os, subprocess, sys
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "block-unsafe-kill.sh")

# Structural dangers — each is one arm of the guard, so "by the same rules as the command
# itself" is tested against more than one rule.
D_PAT = "pkill -f myserver"                        # a pattern kill
D_ALL = "killall python3"                              # killall
D_LOOP = "for p in $(pgrep -f srv); do kill $p; done"  # pgrep -f resolved into a kill
D_GATE = "until ! pgrep -f myserver; do sleep 5; done"  # a wait gate
D_PS = "ps aux | grep srv | xargs kill"                # pids read off a ps listing


def verdict(cmd):
    """(fired, stderr) — fired is True iff the hook exited non-zero."""
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


MUST_BLOCK = [
    # --- A: the argument of bash|sh -c ---------------------------------------------------
    ("A bash -c, single-quoted", "bash -c '" + D_PAT + "'"),
    ("A bash -c, double-quoted", 'bash -c "' + D_ALL + '"'),
    ("A sh -c", "sh -c '" + D_PAT + "'"),
    ("A dash -c", "dash -c '" + D_ALL + "'"),
    ("A zsh -c", "zsh -c '" + D_PAT + "'"),
    ("A bash -lc (c inside a combined flag)", "bash -lc '" + D_PAT + "'"),
    ("A bash -x -c (c as its own flag)", "bash -x -c '" + D_ALL + "'"),
    ("A bash --norc -c (long option before -c)", "bash --norc -c '" + D_PAT + "'"),
    ("A /bin/bash -c (absolute path)", "/bin/bash -c '" + D_PAT + "'"),
    ("A bash -c with a redirection after it", "bash -c '" + D_PAT + "' 2>/dev/null"),
    # --- B: the same argument behind any wrapper -----------------------------------------
    ("B sudo bash -c", "sudo bash -c '" + D_PAT + "'"),
    ("B timeout N bash -c", "timeout 60 bash -c '" + D_PAT + "'"),
    ("B env VAR=1 bash -c", "env FOO=1 bash -c '" + D_ALL + "'"),
    ("B command bash -c", "command bash -c '" + D_PAT + "'"),
    ("B nohup sh -c", "nohup sh -c '" + D_ALL + "'"),
    ("B nice -n 5 bash -c", "nice -n 5 bash -c '" + D_PAT + "'"),
    ("B wrapper, danger not first", "timeout 60 bash -c 'echo x && " + D_ALL + "'"),
    ("B xargs bash -c", "echo x | xargs bash -c '" + D_PAT + "'"),
    # --- C: the argument of eval ----------------------------------------------------------
    ("C eval, single-quoted", "eval '" + D_PAT + "'"),
    ("C eval, double-quoted", 'eval "' + D_ALL + '"'),
    ("C eval, danger not first", "eval 'echo hi; " + D_PAT + "'"),
    ("C eval holding a wait gate", "eval '" + D_GATE + "'"),
    # --- D: the argument of env -S ---------------------------------------------------------
    ("D env -S handing bash -c", "env -S 'bash -c \"" + D_PAT + "\"'"),
    ("D env -S handing sh -c", "env -S \"sh -c '" + D_ALL + "'\""),
    ("D env --split-string= handing bash -c", "env --split-string='bash -c \"" + D_PAT + "\"'"),
    ("D env -S behind a wrapper", "timeout 5 env -S 'bash -c \"" + D_ALL + "\"'"),
    # --- E: a heredoc read by a bare shell ---------------------------------------------------
    ("E bash <<'EOF'", "bash <<'EOF'\n" + D_PAT + "\nEOF"),
    ("E bash <<EOF (unquoted body)", "bash <<EOF\n" + D_ALL + "\nEOF"),
    ("E bash <<-EOF (tab-stripped)", "bash <<-EOF\n\t" + D_PAT + "\n\tEOF"),
    ("E sh <<'EOF'", "sh <<'EOF'\n" + D_PAT + "\nEOF"),
    ("E bash <<'EOF' behind a wrapper", "timeout 60 bash <<'EOF'\n" + D_ALL + "\nEOF"),
    ("E bash <<'EOF', danger not first", "bash <<'EOF'\necho hi\n" + D_PAT + "\nEOF"),
    ("E bash <<'EOF' holding a wait gate", "bash <<'EOF'\n" + D_GATE + "\nEOF"),
    ("E bash <<'EOF' holding a ps listing into a kill", "bash <<'EOF'\n" + D_PS + "\nEOF"),
    # --- F: a herestring read by a bare shell -------------------------------------------------
    ("F bash <<<", "bash <<< '" + D_PAT + "'"),
    ("F sh <<<", 'sh <<< "' + D_ALL + '"'),
    ("F bash <<< holding a wait gate", "bash <<< '" + D_GATE + "'"),
    # --- G: an echo pipe read by a bare shell --------------------------------------------------
    ("G echo '...' | bash", "echo '" + D_PAT + "' | bash"),
    ("G echo \"...\" | sh", 'echo "' + D_ALL + '" | sh'),
    ("G echo -n '...' | bash (flag before the string)", "echo -n '" + D_PAT + "' | bash"),
    ("G echo, danger not first", "echo 'echo hi; " + D_PAT + "' | bash"),
    ("G echo | bash behind a wrapper", "echo '" + D_PAT + "' | nohup bash"),
    ("G echo | bash holding a pgrep -f + kill loop", "echo '" + D_LOOP + "' | bash"),
    # --- H: a printf pipe read by a bare shell --------------------------------------------------
    ("H printf FORMAT-only | bash", "printf '" + D_PAT + "\\n' | bash"),
    ("H printf '%s\\n' ARGUMENT | bash", "printf '%s\\n' '" + D_PAT + "' | bash"),
    ("H printf '%s' ARGUMENT | bash", "printf '%s' '" + D_ALL + "' | bash"),
    ("H printf '%b' ARGUMENT | bash", "printf '%b' '" + D_PAT + "' | bash"),
    ("H printf '%s\\n' ARGUMENT | sh", "printf '%s\\n' '" + D_PAT + "' | sh"),
    ("H printf ARGUMENT, danger not first", "printf '%s\\n' 'echo hi; " + D_PAT + "' | bash"),
    ("H printf ARGUMENT holding a wait gate", "printf '%s\\n' '" + D_GATE + "' | bash"),
    ("H printf ARGUMENT handing a nested shell",
     "printf '%s\\n' \"bash -c '" + D_PAT + "'\" | bash"),
    ("H printf ARGUMENT | bash behind a wrapper",
     "printf '%s\\n' '" + D_PAT + "' | nohup bash"),
    # --- I: the nested code judged by every arm of the guard ------------------------------------
    ("I bash -c holding a pgrep -f + kill loop", "bash -c '" + D_LOOP + "'"),
    ("I bash -c holding a wait gate", "bash -c '" + D_GATE + "'"),
    ("I bash -c holding a ps listing into a kill", "bash -c '" + D_PS + "'"),
    ("I bash -c, danger not first", "bash -c 'echo hi; " + D_PAT + "'"),
    # --- J: nesting ------------------------------------------------------------------------------
    ("J bash -c inside bash -c", "bash -c \"bash -c '" + D_PAT + "'\""),
    ("J eval of a bash -c", "eval \"bash -c '" + D_PAT + "'\""),
    ("J a substitution carrying a bash -c", "echo \"$(bash -c '" + D_PAT + "')\""),
    # --- K: a bare shell that names stdin as its script operand ------------------------------------
    ("K bash - <<'EOF' (heredoc, '-' operand)", "bash - <<'EOF'\n" + D_PAT + "\nEOF"),
    ("K sh - <<'EOF'", "sh - <<'EOF'\n" + D_PAT + "\nEOF"),
    ("K bash -s <<'EOF' ('-s' operand)", "bash -s <<'EOF'\n" + D_PAT + "\nEOF"),
    ("K bash -- <<'EOF' ('--' operand)", "bash -- <<'EOF'\n" + D_PAT + "\nEOF"),
    ("K bash - <<'EOF' behind a wrapper", "timeout 5 bash - <<'EOF'\n" + D_PAT + "\nEOF"),
    ("K bash - <<'EOF' holding a wait gate", "bash - <<'EOF'\n" + D_GATE + "\nEOF"),
    ("K bash - <<< (herestring, '-' operand)", "bash - <<< '" + D_PAT + "'"),
    ("K sh - <<< (herestring, '-' operand)", "sh - <<< '" + D_PAT + "'"),
    ("K bash -s <<< (herestring, '-s' operand)", "bash -s <<< '" + D_PAT + "'"),
    ("K echo ... | bash - (pipe, '-' operand)", "echo '" + D_PAT + "' | bash -"),
    ("K echo ... | bash -s (pipe, '-s' operand)", "echo '" + D_PAT + "' | bash -s"),
    ("K printf ... | sh - (pipe, '-' operand)", "printf '%s\\n' '" + D_PAT + "' | sh -"),
]

MUST_BE_SILENT = [
    ("echo as data — no shell reads it", "echo '" + D_PAT + "'"),
    ("printf as data — no shell reads it", "printf '%s\\n' '" + D_PAT + "'"),
    ("echo into cat", "echo '" + D_PAT + "' | cat"),
    ("the danger in a commit message", "git commit -m 'stop recommending " + D_PAT + "'"),
    ("a heredoc read by cat is data", "cat <<'EOF'\n" + D_PAT + "\nEOF"),
    ("a herestring read by cat is data", "cat <<< '" + D_PAT + "'"),
    ("a shell running a script path", "bash ./restart.sh"),
    ("a bare shell on harmless code", "bash -c 'echo hello'"),
    ("printf of harmless code into a shell", "printf '%s\\n' 'echo hello' | bash"),
    ("a '-' stdin shell on harmless code", "bash - <<< 'echo hello'"),
    ("python -c is not a shell", 'python3 -c \'print("' + D_PAT + '")\''),
    ("kill by the PID you captured", 'SRV=$!; kill "$SRV"'),
]


# --- L: programs that run their string argument as shell code ------------------------------
# (template, runnable here). {C} is the code; ./lk is a lock file in the oracle's directory.
HOSTS = [
    ("flock ./lk -c '{C}'", True),
    ("flock -w 5 ./lk --command '{C}'", True),
    ("timeout 9 flock -n ./lk -c '{C}'", True),
    ("su -c '{C}'", False),
    ("su - root -c '{C}'", False),
    ("su root -lc '{C}'", False),
    ("su --command='{C}' root", False),
    ("su --session-command '{C}'", False),
    ("sudo su -c '{C}'", False),
    ("runuser -l alice -c '{C}'", False),
    ("watch '{C}'", False),
    ("watch -n 5 -t '{C}'", False),
    ("watch --differences=permanent -n1 '{C}'", False),
    ("script -qec '{C}' /dev/null", True),
    ("script -q --command '{C}' /dev/null", True),
    ("trap '{C}' EXIT", True),
    ("trap -- '{C}' INT TERM EXIT", True),
    ("tmux new-session -d -s w '{C}'", False),
    ("tmux new -d '{C}'", False),
    ("tmux -L s split-window -t w '{C}'", False),
    ("tmux run-shell '{C}'", False),
    ("tmux send-keys -t w '{C}' Enter", False),
    ("tmux if-shell '{C}' 'display ok'", False),
    ("tmux -c '{C}'", False),
    ("echo '{C}' | at now", False),
    ("at now + 1 minute <<< '{C}'", False),
    ("at now <<'EOF'\n{C}\nEOF", False),
    ("batch <<< '{C}'", False),
]
DANGERS = [("pattern kill", D_PAT), ("killall", D_ALL), ("pgrep -f loop", D_LOOP),
           ("wait gate", D_GATE), ("ps listing", D_PS)]
HARMLESS = "echo hello"
for _h, _run in HOSTS:
    MUST_BLOCK += [("L %s | %s" % (_h, _dn), _h.replace("{C}", _d)) for _dn, _d in DANGERS]
MUST_BLOCK += [
    ("L watch, the command as its words", "watch -n 5 " + D_PAT),
    ("L watch -x, argv", "watch -x " + D_PAT),
    ("L flock FILE CMD, argv", "flock ./lk " + D_PAT),
    ("L runuser -u USER -- CMD, argv", "runuser -u alice -- " + D_PAT),
]
MUST_BE_SILENT += [("L %s | harmless" % _h, _h.replace("{C}", HARMLESS)) for _h, _ in HOSTS]
MUST_BE_SILENT += [
    ("L trap killing a captured PID", "trap 'kill \"$SRV\"' EXIT"),
    ("L trap killing its own jobs", "trap 'kill $(jobs -p)' EXIT"),
    ("L flock running argv that kills nothing", "flock ./lk make test"),
    ("L watch on a lister alone", "watch -n 5 'pgrep -fa myserver'"),
    ("L at listing its queue", "at -l"),
    ("L a host spelled as data", "echo \"flock ./lk -c '" + D_PAT + "'\""),
]


def host_runs_code(tmpl):
    """Bash's and the host's own reading: run tmpl with a redirect only a shell performs."""
    import tempfile, shutil
    d = tempfile.mkdtemp(prefix="mh-handed-host-")
    try:
        bash_oracle.run(["bash", "-c", tmpl.replace("{C}", "echo RAN > marker")], cwd=d,
                       capture_output=True, timeout=20, stdin=subprocess.DEVNULL)
        m = os.path.join(d, "marker")
        return os.path.exists(m) and open(m).read().strip() == "RAN"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main():
    failures = []
    for h, runnable in HOSTS:
        if runnable and not host_runs_code(h):
            failures.append("ORACLE: `%s` did not run its string as shell code here" % h)
    for label, cmd in MUST_BLOCK:
        fired, err = verdict(cmd)
        if not fired:
            failures.append("NOT BLOCKED [%s]: %s" % (label, cmd.replace("\n", "\\n")))
        elif "BLOCKED:" not in err:
            failures.append("BLOCKED but said nothing useful [%s]: %r" % (label, err[:200]))
    for label, cmd in MUST_BE_SILENT:
        fired, err = verdict(cmd)
        if fired:
            failures.append("FALSE POSITIVE [%s]: %s\n    said: %s"
                            % (label, cmd.replace("\n", "\\n"), err[:300]))

    if failures:
        print("FAIL (%d of %d cases)" % (len(failures),
                                         len(MUST_BLOCK) + len(MUST_BE_SILENT)))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d block + %d silent cases — every string handed to another shell is read as code"
          % (len(MUST_BLOCK), len(MUST_BE_SILENT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
