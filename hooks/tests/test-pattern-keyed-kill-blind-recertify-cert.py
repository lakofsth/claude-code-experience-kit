"""Check of mh-every-pattern-keyed-kill-is-refused, written from the hooks/tests/INVARIANTS.md clause alone.

The sentence: hooks/block-unsafe-kill.sh refuses a kill whose pids are chosen by matching a
full command line — pkill -f/--full with any options or option arguments around it, pgrep -f
into a kill, and a ps listing piped on into a kill — whatever path, escape or wrapper (sudo,
timeout, env, xargs, ...) precedes the command word, where a wrapper is every program that runs
its operands as a command by its own man page (chroot, systemd-run, nsenter, docker exec, find's
-exec, ...).

Written from the hooks/tests/INVARIANTS.md clause alone. The directions it has, and the rows that pin each:

  R1  a ps listing piped on into a kill, whatever consumes the pipe: not only xargs but a
      while/until read loop, a brace group, a subshell, or a shell reading the pipe on stdin.
  R2  pgrep -f piped on into a kill through a shell that reads the pipe (bash -c 'read p; ...').
  R3  env as the wrapper, in every spelling its man page gives the command: -S with the string
      unquoted (env -S pkill -f X splits "pkill" and runs it with the rest), -S combined with
      another short option (-vS), -S after another option (-i -S).
  R4  screen as the wrapper: `screen [-opts] cmd [args]` runs cmd by its man page, detached
      (-dm, -d -m, -dmS NAME) or not (-S NAME, -L, bare) — carrying pkill -f, a pgrep -f the
      outer shell expands into a kill's arguments, or sh -c code.
  R5  a shell other than bash/sh/dash/zsh/ksh as the runner of its -c operand (fish, tcsh,
      csh, rbash, yash, posh): each runs its operand as a command by its man page.
  S   scope: an explicit-pid kill, a pattern match with no kill, and each wrapper above
      running something that is no kill, are NOT refused.

The hook is a PreToolUse(Bash) guard: payload JSON on stdin, exit 2 + "BLOCKED:" on stderr to
refuse. Only the command string is inspected; nothing here executes.
"""
import json
import os
import subprocess
import sys

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))


def verdict(cmd):
    """(fired, stderr) — fired is True iff the hook refused."""
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


PS = "ps aux | grep myserv | awk '{print $2}'"
PSEF = "ps -ef | grep myserv | awk '{print $2}'"

MUST_BLOCK = [
    # --- R1: a ps listing piped on into a kill, any consumer -----------------------------------
    ("R1 ps | while read; kill",            PS + " | while read p; do kill $p; done"),
    ("R1 ps -ef | while read -r; kill -9",  PSEF + ' | while read -r p; do kill -9 "$p"; done'),
    ("R1 ps | while read; echo; kill",      PS + " | while read p; do echo $p; kill $p; done"),
    ("R1 ps | until ! read; kill",          PS + " | until ! read p; do kill $p; done"),
    ("R1 ps | { read; kill; }",             PS + " | { read p; kill $p; }"),
    ("R1 ps | ( read; kill )",              PS + " | ( read p; kill $p )"),
    ("R1 ps | bash -c 'read; kill'",        PS + " | bash -c 'read p; kill $p'"),
    # --- R2: pgrep -f piped into a shell that reads it and kills --------------------------------
    ("R2 pgrep -f | bash -c 'read; kill'",  "pgrep -f myserver | bash -c 'read p; kill $p'"),
    # --- R3: env, every spelling of -S ----------------------------------------------------------
    ("R3 env -S unquoted",                  "env -S pkill -f myserver"),
    ("R3 env -vS 'string'",                 "env -vS 'pkill -f myserver'"),
    ("R3 env -i -S unquoted",               "env -i -S pkill -f myserver"),
    ("R3 kill $(env -i -S pgrep -f)",       "kill $(env -i -S pgrep -f myserver)"),
    # --- R4: screen runs its operands as a command ----------------------------------------------
    ("R4 screen -dm pkill -f",              "screen -dm pkill -f myserver"),
    ("R4 screen -d -m pkill -f",            "screen -d -m pkill -f myserver"),
    ("R4 screen -dmS job pkill -f",         "screen -dmS job pkill -f myserver"),
    ("R4 screen -S x pkill -f",             "screen -S x pkill -f myserver"),
    ("R4 screen -L pkill -f",               "screen -L pkill -f myserver"),
    ("R4 screen pkill -f",                  "screen pkill -f myserver"),
    ("R4 screen -dm kill $(pgrep -f)",      "screen -dm kill $(pgrep -f myserver)"),
    ("R4 screen -dm sh -c 'kill $(pgrep)'", "screen -dm sh -c 'kill $(pgrep -f myserver)'"),
    ("R4 screen -dmS j sh -c pgrep|xargs",  "screen -dmS j sh -c 'pgrep -f myserv | xargs kill'"),
    # --- R5: other shells running their -c operand ----------------------------------------------
    ("R5 fish -c",                          "fish -c 'pkill -f myserver'"),
    ("R5 fish --command=",                  "fish --command='pkill -f myserver'"),
    ("R5 sudo fish -c",                     "sudo fish -c 'pkill -f myserver'"),
    ("R5 /bin/fish -c kill (pgrep -f)",     "/bin/fish -c 'kill (pgrep -f myserver)'"),
    ("R5 tcsh -c",                          "tcsh -c 'pkill -f myserver'"),
    ("R5 csh -c",                           "csh -c 'pkill -f myserver'"),
    ("R5 rbash -c",                         "rbash -c 'pkill -f myserver'"),
    ("R5 yash -c",                          "yash -c 'pkill -f myserver'"),
    ("R5 posh -c",                          "posh -c 'pkill -f myserver'"),
]

MUST_PASS = [
    ("S kill by explicit pid",              "kill 12345"),
    ("S pgrep -f, no kill",                 "pgrep -f myserver"),
    ("S ps | while read; echo",             PS + " | while read p; do echo $p; done"),
    ("S env -S non-kill",                   "env -S 'echo hello'"),
    ("S screen -dmS non-kill",              "screen -dmS job top"),
    ("S fish -c non-kill",                  "fish -c 'echo hello'"),
    ("S tcsh -c pgrep -f, no kill",         "tcsh -c 'pgrep -f myserver'"),
]


def main():
    bad = []
    for name, cmd in MUST_BLOCK:
        fired, err = verdict(cmd)
        print("  %s %-38s %s" % ("refused" if fired else "SILENT ", name, cmd))
        if not fired:
            bad.append("must refuse, was silent: %s :: %s" % (name, cmd))
    for name, cmd in MUST_PASS:
        fired, err = verdict(cmd)
        print("  %s %-38s %s" % ("REFUSED" if fired else "silent ", name, cmd))
        if fired:
            bad.append("must stay silent, was refused: %s :: %s :: %s"
                       % (name, cmd, err.strip().splitlines()[:1]))
    print("%d must-refuse, %d must-stay-silent, %d wrong"
          % (len(MUST_BLOCK), len(MUST_PASS), len(bad)))
    for b in bad:
        print("FAIL:", b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
