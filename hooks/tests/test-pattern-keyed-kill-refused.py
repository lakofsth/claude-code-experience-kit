"""Check of mh-every-pattern-keyed-kill-is-refused.

The sentence: hooks/block-unsafe-kill.sh refuses a kill whose pids are chosen by matching
a full command line (pkill -f/--full with any options or option arguments around it,
pgrep -f into a kill, and a ps listing piped on into a kill), whatever path, escape or
wrapper (sudo, timeout, env, xargs, ...) precedes the command word.

Directions derived from the sentence, each pinned below:

  D1  pkill -f / pkill --full, with options AND option arguments (values that consume a
      token) sitting between the command word and the pattern flag.
  D2  pgrep -f / pgrep --full resolved into a kill — command substitution, pipe into
      xargs, for-loop — with option arguments around the flag too.
  D3  a ps listing piped on into a kill, through any middle filter (grep/awk/cut).
  D4  every shape above behind a path (/usr/bin/pkill), an escape (\\pkill) or a wrapper
      (sudo, timeout, env, command, xargs) — on the pkill/pgrep word AND on the kill word.
  D2b pgrep -f's pids carried to the kill through any binding site bash has: a group or subshell piped on, a
      variable echoed back, printf -v, set -- and "$@", a function's arguments.
  D4b a pattern kill handed to a program that runs it as shell code (flock -c, su -c, watch,
      script -c, trap), the code-reading analogue of a wrapper (ledger D1243).
  D4c every program that runs its operands as a command, by its man page (2026-10-28): argv
      runners (chroot, systemd-run, nsenter, setarch, strace, docker exec, find -exec,
      moreutils parallel) and string runners (parallel --, git rebase -x, sg -c, ssh to this
      host), and a pgrep -f the outer shell expands into such a string.
  D5  scope: a kill by explicit PID, and pattern matching with no kill in the command,
      are NOT refused — the sentence refuses kills keyed on a pattern, nothing else; nor is a
      command run on ANOTHER host, whose processes are not this host's.

The hook is a PreToolUse(Bash) guard: payload JSON on stdin, exit 2 + "BLOCKED:" on
stderr to refuse. It only inspects the command string; nothing here executes.
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


MUST_BLOCK = [
    # --- D1: pkill -f/--full, options and option arguments around the flag ---------------
    ("D1 pkill -f, plain",                  "pkill -f myserver"),
    ("D1 pkill option before -f",           "pkill -9 -f myserver"),
    ("D1 pkill -f with trailing option",    "pkill -f -9 myserver"),
    ("D1 pkill option ARGUMENT before -f",  "pkill -u root -f myserver"),
    ("D1 pkill -s KILL -f",                 "pkill -s KILL -f myserver"),
    ("D1 pkill --signal=KILL -f",           "pkill --signal=KILL -f myserver"),
    ("D1 pkill --full",                     "pkill --full myserver"),
    ("D1 pkill -9 --full",                  "pkill -9 --full myserver"),
    ("D1 pkill -u root --full",             "pkill -u root --full myserver"),
    # --- D2: pgrep -f/--full resolved into a kill -----------------------------------------
    ("D2 kill $(pgrep -f ...)",             "kill $(pgrep -f myserver)"),
    ("D2 pgrep -f | xargs kill",            "pgrep -f myserver | xargs kill"),
    ("D2 for-loop over pgrep -f",           "for p in $(pgrep -f myserver); do kill \"$p\"; done"),
    ("D2 pids=$(pgrep -f ...) ; kill",      "pids=$(pgrep -f myserver); kill $pids"),
    ("D2 pgrep option ARGUMENT -f | kill",  "pgrep -u root -f myserver | xargs kill"),
    ("D2 kill $(pgrep -u root -f ...)",     "kill -9 $(pgrep -u root -f myserver)"),
    ("D2 pgrep --full | xargs kill",        "pgrep --full myserver | xargs kill"),
    ("D2 kill $(pgrep --full ...)",         "kill $(pgrep --full myserver)"),
    ("D2 for-loop over pgrep --full",       "for p in $(pgrep --full myserver); do kill \"$p\"; done"),
    # --- D3: a ps listing piped on into a kill --------------------------------------------
    ("D3 ps aux | grep | awk | xargs kill", "ps aux | grep myserver | awk '{print $2}' | xargs kill"),
    ("D3 ps -eo pid,cmd | ... | kill -9",   "ps -eo pid,cmd | grep myserver | awk '{print $1}' | xargs kill -9"),
    ("D3 ps -ef | grep -v grep | kill",     "ps -ef | grep myserver | grep -v grep | awk '{print $2}' | xargs -r kill"),
    ("D3 ps | bracketed grep | kill",       "ps aux | grep '[l]lama-server' | awk '{print $2}' | xargs kill"),
    # --- D4: path, escape or wrapper before the command word ------------------------------
    ("D4 sudo pkill -f",                    "sudo pkill -f myserver"),
    ("D4 timeout pkill -f",                 "timeout 30 pkill -f myserver"),
    ("D4 env pkill -f",                     "env pkill -f myserver"),
    ("D4 command pkill -f",                 "command pkill -f myserver"),
    ("D4 xargs pkill -f",                   "printf myserver | xargs pkill -f"),
    ("D4 PATH pkill -f",                    "/usr/bin/pkill -f myserver"),
    ("D4 sudo PATH pkill -9 -f",            "sudo /usr/bin/pkill -9 -f myserver"),
    ("D4 env VAR=1 PATH pkill --full",      "env LC_ALL=C /usr/bin/pkill --full myserver"),
    ("D4 escaped \\pkill -f",               "\\pkill -f myserver"),
    ("D4 PATH kill $(pgrep -f ...)",        "/usr/bin/kill $(pgrep -f myserver)"),
    ("D4 pgrep -f | xargs PATH kill",       "pgrep -f myserver | xargs /usr/bin/kill"),
    ("D4 sudo pgrep -u root -f | kill",     "sudo pgrep -u root -f myserver | xargs kill"),
    # --- D2b: through a binding site --------------------------------------------------------
    ("D2b { pgrep -f; } | xargs kill",      "{ pgrep -f myserver; } | xargs kill"),
    ("D2b ( pgrep -f ) | xargs kill",       "( pgrep -f myserver ) | xargs kill"),
    ("D2b kill $(echo $P)",                 "P=$(pgrep -f myserver); kill $(echo $P)"),
    ("D2b printf -v P",                     "printf -v P '%s' \"$(pgrep -f myserver)\"; kill $P"),
    ("D2b set -- ; kill \"$@\"",            "set -- $(pgrep -f myserver); kill \"$@\""),
    ("D2b a function's arguments",          "k() { kill \"$@\"; }; k $(pgrep -f myserver)"),
    # --- D4b: handed to a program that runs it as shell code ---------------------------------
    ("D4b flock FILE -c",                   "flock /tmp/l -c 'pkill -f myserver'"),
    ("D4b su -c",                           "su -c 'pkill -f myserver'"),
    ("D4b watch",                           "watch -n 5 'pkill -f myserver'"),
    ("D4b script -c",                       "script -qec 'pkill -f myserver' /dev/null"),
    ("D4b trap",                            "trap 'pkill -f myserver' EXIT"),
    ("D4b the first command of a `function NAME {` body", "function k { pkill -f myserver; }; k"),
    # --- D4c: every program that runs its operands as a command (2026-10-28) ---------------------
    ("D4c chroot NEWROOT CMD",              "chroot / pkill -f myserver"),
    ("D4c systemd-run CMD",                 "systemd-run --user --scope pkill -f myserver"),
    ("D4c nsenter -t PID CMD",              "nsenter -t 1 -p pkill -f myserver"),
    ("D4c setarch ARCH CMD",                "setarch x86_64 -R pkill -f myserver"),
    ("D4c strace -o FILE CMD",              "strace -o /dev/null pkill -f myserver"),
    ("D4c docker exec CONTAINER CMD",       "docker exec ctr pkill -f myserver"),
    ("D4c find -exec ... \\;",              "find . -maxdepth 0 -exec pkill -f myserver \\;"),
    ("D4c find -execdir ... {} +",          "find . -execdir pkill -f myserver {} +"),
    ("D4c moreutils parallel CMD --",       "parallel pkill -f -- myserver"),
    ("D4c parallel -- CODE",                "parallel -- 'pkill -f myserver'"),
    ("D4c git rebase -x CODE",              "git rebase -x 'pkill -f myserver' main"),
    ("D4c sg GROUP -c CODE",                "sg alice -c 'pkill -f myserver'"),
    ("D4c ssh to this host",                "ssh localhost 'pkill -f myserver'"),
    ("D4c pgrep -f expanded into bash -c",  "bash -c \"kill $(pgrep -f myserver)\""),
    ("D4c pgrep -f expanded into find -exec", "find . -exec kill $(pgrep -f myserver) \\;"),
]

MUST_BE_SILENT = [
    ("D5 kill by explicit PID",             "kill 4242"),
    ("D5 kill -9 by explicit PID",          "kill -9 4242"),
    ("D5 pgrep -f with no kill",            "pgrep -f myserver"),
    ("D5 ps | grep with no kill",           "ps aux | grep myserver"),
    ("D5 the danger named in single quotes","echo 'pkill -f myserver'"),
    ("D5 the safe helper",                  "source ./your-safe-kill-helper.sh; safe_kill_pat 'myserv'"),
    ("D5 a pid from $! beside pgrep -f",    "sleep 9 & SRV=$!; { pgrep -f myserver; } | wc -l; kill \"$SRV\""),
    ("D5 set -- of the pid from $!",        "sleep 9 & SRV=$!; set -- \"$SRV\"; P=$(pgrep -f myserver); kill \"$@\""),
    ("D5 flock -c of a PID kill",           "sleep 9 & SRV=$!; flock /tmp/l -c \"kill $SRV\""),
    ("D5 find -exec grepping for the words", "find . -name '*.py' -exec grep -l 'pkill -f' {} +"),
    ("D5 ssh to ANOTHER host (not this host's processes)", "ssh build-host 'pkill -f myserver'"),
]


def main():
    failures = []
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

    total = len(MUST_BLOCK) + len(MUST_BE_SILENT)
    if failures:
        print("FAIL (%d of %d cases)" % (len(failures), total))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d block + %d silent cases" % (len(MUST_BLOCK), len(MUST_BE_SILENT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
