"""Check of mh-no-substring-allows-a-command, for hooks/block-unsafe-kill.sh.

The sentence: no word or substring anywhere in a command exempts it from the guard — naming the
safe helper safe_kill_pat allows only that helper's own invocation, and every other simple command
in the same command is still inspected.

Written from the hooks/tests/INVARIANTS.md clause alone. The ways it can be false:

  A. A MENTION exempts: the name appears where it is not an invocation — a comment, an echo's
     argument, a quoted string, a variable assignment — beside a dangerous simple command.
  B. A SUBSTRING exempts: a longer word that merely contains the name (safe_kill_pattern,
     my_safe_kill_pat, a path ending in it) beside a dangerous simple command.
  C. The REAL INVOCATION exempts its neighbours: the helper is genuinely called, and a second
     simple command in the same command — after ; && || | a newline, inside $(...), or inside a
     loop — is a dangerous shape. Each neighbour must still be inspected.
  D. A function DEFINED under the helper's name whose body is a dangerous simple command: the
     body is not the helper's invocation.
  E. The other direction, so the check cannot pass by blocking everything: the helper's own
     invocation, alone or beside harmless commands, stays silent.

Each dangerous neighbour is a shape the guard blocks on its own (asserted first, so a red here is
the exemption's red and not a detector gap).
"""
import json, os, subprocess, sys

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

SRC = "source ./your-safe-kill-helper.sh"


def verdict(cmd):
    """(fired, stderr) — fired is True iff the hook exited non-zero."""
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


# The dangerous neighbours: each blocked on its own, without any mention of the helper.
DANGER = [
    "pkill -f myserver",
    "killall python3",
    "until ! pgrep -f myserver; do sleep 10; done",
]

MUST_BLOCK = [
    # --- A. a mention that is not an invocation ------------------------------------------
    ("A: name in a trailing comment",            "pkill -f myserver  # not safe_kill_pat"),
    ("A: name in a leading comment line",        "# use safe_kill_pat next time\nkillall python3"),
    ("A: name echoed as data",                   "echo 'prefer safe_kill_pat'; pkill -f myserver"),
    ("A: name in a double-quoted string",        "echo \"see safe_kill_pat\" && killall python3"),
    ("A: name in an assignment",                 "HELPER=safe_kill_pat; pkill -f myserver"),
    ("A: name in a commit message",              "git commit -m 'safe_kill_pat'; pkill -f run.sh"),
    ("A: name in a heredoc body",                "cat <<'EOF'\nsafe_kill_pat\nEOF\nkillall python3"),
    ("A: name as a pgrep pattern in a gate",     "until ! pgrep -f safe_kill_pat; do sleep 1; done"),
    # --- B. a longer word that merely contains the name -----------------------------------
    ("B: name as a prefix of a word",            "safe_kill_pattern=1; pkill -f myserver"),
    ("B: name as a suffix of a word",            "my_safe_kill_pat myserv; killall python3"),
    ("B: name inside a path",                    "ls /tmp/safe_kill_pat.d; pkill -f myserver"),
    ("B: name as the pkill pattern itself",      "pkill -f safe_kill_pat"),
    # --- C. the real invocation beside a dangerous simple command -------------------------
    ("C: helper ; pkill -f",                     SRC + "; safe_kill_pat 'myserv'; pkill -f myserver"),
    ("C: pkill -f ; helper",                     SRC + "; pkill -f myserver; safe_kill_pat 'myserv'"),
    ("C: helper && killall",                     SRC + " && safe_kill_pat 'myserv' && killall python3"),
    ("C: helper || killall",                     SRC + "; safe_kill_pat 'myserv' || killall python3"),
    ("C: helper, newline, pkill -f",             SRC + "\nsafe_kill_pat 'myserv'\npkill -f myserver"),
    ("C: helper then a pgrep -f wait gate",      SRC + "; safe_kill_pat 'myserv'; "
                                                 "until ! pgrep -f myserver; do sleep 10; done"),
    ("C: helper then a pgrep -x wait gate",      SRC + "; safe_kill_pat 'myserv'; "
                                                 "until ! pgrep -x myserver; do sleep 10; done"),
    ("C: helper then pgrep -f into kill",        SRC + "; safe_kill_pat 'myserv'; "
                                                 "for p in $(pgrep -f myserver); do kill \"$p\"; done"),
    ("C: helper, pkill -f in $()",               SRC + "; safe_kill_pat 'myserv'; x=$(pkill -f run.sh)"),
    ("C: helper piped into killall",             SRC + "; safe_kill_pat 'myserv' | killall python3"),
    ("C: helper inside a loop with pkill -f",    SRC + "; for i in 1 2; do safe_kill_pat 'myserv'; "
                                                 "pkill -f myserver; done"),
    ("C: helper backgrounded, then killall",     SRC + "; safe_kill_pat 'myserv' & killall python3"),
    # --- D. a function defined under the helper's name ------------------------------------
    ("D: redefine the helper as pkill -f",       "safe_kill_pat() { pkill -f \"$1\"; }; safe_kill_pat myserv"),
]

MUST_BE_SILENT = [
    # --- E. the helper's own invocation stays allowed -------------------------------------
    ("E: the helper, sourced and called",        SRC + "; safe_kill_pat 'myserv'"),
    ("E: the helper, double-quoted pattern",     SRC + " && safe_kill_pat \"myserver\""),
    ("E: the helper, unquoted pattern",          SRC + "; safe_kill_pat myserver"),
    ("E: the helper beside harmless commands",   SRC + "; safe_kill_pat 'myserv'; sleep 2; uptime"),
    ("E: the helper, then a PID kill",           SRC + "; safe_kill_pat 'myserv'; kill \"$SRV\""),
    ("E: the helper on its own line",            SRC + "\nsafe_kill_pat 'myserv'\necho done"),
]


def main():
    failures = []
    # Precondition: every dangerous neighbour is blocked on its own, so a miss below is the
    # exemption at work and not a shape the detector never had.
    for cmd in DANGER:
        fired, _ = verdict(cmd)
        if not fired:
            print("PRECONDITION FAILED: the guard does not block %r on its own" % cmd)
            return 2
    for label, cmd in MUST_BLOCK:
        fired, err = verdict(cmd)
        if not fired:
            failures.append("EXEMPTED [%s]: %r" % (label, cmd))
        elif "BLOCKED:" not in err:
            failures.append("BLOCKED but said nothing useful [%s]: %r" % (label, err[:200]))
    for label, cmd in MUST_BE_SILENT:
        fired, err = verdict(cmd)
        if fired:
            failures.append("FALSE POSITIVE [%s]: %r\n    said: %s" % (label, cmd, err[:300]))

    total = len(MUST_BLOCK) + len(MUST_BE_SILENT)
    if failures:
        print("FAIL (%d of %d cases)" % (len(failures), total))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d block + %d silent cases — safe_kill_pat exempts only its own invocation"
          % (len(MUST_BLOCK), len(MUST_BE_SILENT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
