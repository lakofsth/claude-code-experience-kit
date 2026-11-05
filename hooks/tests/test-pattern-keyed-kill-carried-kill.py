"""Pin the structural rule of mh-every-pattern-keyed-kill-is-refused.

A wrapper table cannot name every program that runs its operands (pkill -f behind valgrind,
numactl, ..., and a pgrep -f carried by `xargs -I{}` into find's -exec kill, are what
test-pattern-keyed-kill-every-command-runner-cert.py checks). So the guard reads a program it
cannot read, with pkill, pgrep or kill among its operands, from that word on (carried_kill() in
hooks/block-unsafe-kill.sh). This file pins the halves of that rule the other check does not
reach:

  C1  the KILL word carried by an unlisted program, the pids from pgrep -f or a ps listing
      (in a substitution the kill expands, and through xargs);
  C2  the LISTER carried by an unlisted program, its pids into a kill;
  S   scope: a program that reads its operands as data, a kill by PID behind an unlisted
      program, a command sent to another host, and xargs -I{} into a find that runs no kill
      stay silent.

"""
import json
import os
import subprocess
import sys

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))


def fired(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0 and "BLOCKED:" in p.stderr


MUST_BLOCK = [
    ("C1 numactl kill $(pgrep -f)",          "numactl -N 0 kill $(pgrep -f srv)"),
    ("C1 bwrap kill $(pgrep -f)",            "bwrap --bind / / kill $(pgrep -f srv)"),
    ("C1 pgrep -f | xargs valgrind kill",    "pgrep -f srv | xargs valgrind kill"),
    ("C1 ps | ... | xargs ltrace kill",      "ps aux | grep srv | awk '{print $2}' | xargs ltrace kill"),
    ("C2 kill $(valgrind pgrep -f)",         "kill $(valgrind pgrep -f srv)"),
    ("C2 firejail pgrep -f | xargs kill",    "firejail --quiet pgrep -f srv | xargs kill"),
    ("C2 by path, long option",              "cgexec -g cpu:x /usr/bin/pkill --full srv"),
]

MUST_BE_SILENT = [
    ("S ps | grep kill",                     "ps aux | grep kill"),
    ("S pgrep -af | grep -v kill",           "pgrep -af srv | grep -v kill"),
    ("S grep for pkill, -f is grep's",       "grep -rn pkill -f pats.txt"),
    ("S echo pkill -f",                      "echo pkill -f srv"),
    ("S valgrind kill by PID",               "valgrind kill 4242"),
    ("S systemctl kill a unit",              "systemctl --user kill foo.service"),
    ("S ssh to another host",                "ssh build-host pkill -f srv"),
    ("S xargs -I{} into a find with no kill", "pgrep -f srv | xargs -I{} find /proc/{} -maxdepth 0 -print"),
]


def main():
    bad = ["NOT BLOCKED [%s]: %s" % (l, c) for l, c in MUST_BLOCK if not fired(c)]
    bad += ["FALSE POSITIVE [%s]: %s" % (l, c) for l, c in MUST_BE_SILENT if fired(c)]
    total = len(MUST_BLOCK) + len(MUST_BE_SILENT)
    if bad:
        print("FAIL (%d of %d cases)" % (len(bad), total))
        for b in bad:
            print("  " + b)
        return 1
    print("OK: %d block + %d silent cases" % (len(MUST_BLOCK), len(MUST_BE_SILENT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
