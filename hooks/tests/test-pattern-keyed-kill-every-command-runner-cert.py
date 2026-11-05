"""Check of mh-every-pattern-keyed-kill-is-refused, as amended 2026-10-28.

The sentence: hooks/block-unsafe-kill.sh refuses a kill whose pids are chosen by matching
a full command line (pkill -f/--full with any options or option arguments around it,
pgrep -f into a kill, and a ps listing piped on into a kill), whatever path, escape or
wrapper (sudo, timeout, env, xargs, ...) precedes the command word, where a wrapper is
every program that runs its operands as a command by its own man page (chroot,
systemd-run, nsenter, docker exec, find's -exec, ...).

The amendment is the part this check is about: the sentence no longer names a list of
wrappers, it names a CLASS — a program whose man page says it runs its operands as a
command. Directions derived from that, each pinned below:

  W1  each wrapper the sentence names by example, with and without its own options and
      option arguments between it and the command word (chroot, systemd-run, nsenter,
      docker exec, find -exec).
  W2  the rest of the class: other programs whose man page SYNOPSIS is "PROG [OPTION]...
      COMMAND [ARG]..." or equivalent — the "..." of the sentence. A list is a sample of
      the class, not its definition; these are the members a reader of man pages on a
      Debian host meets first.
  W3  find's other command-running actions (-execdir, -ok, -okdir) and the `{} +` form.
  W4  the wrapper in front of the KILL word, with the pids chosen by pgrep -f or a ps
      listing — not only in front of pkill.
  W5  the wrapper in front of the LISTER: pgrep -f run under a wrapper, its pids into a
      kill.
  W6  the wrapper reached by path, and wrappers stacked on wrappers.
  S   scope: the same wrappers running something that is not a pattern-keyed kill stay
      silent — the amendment widens what a wrapper is, not what is refused.

Not covered, stated: ssh (its man page runs the command on a REMOTE host, so the kill is
not on this host's process table); gdb --args (gdb does not run the program until told
to); programs that run their operand as SHELL CODE (sh -c, su -c, flock -c, watch) are
another sentence's (mh-code-handed-to-a-shell-is-code) and the existing check's D4b.

The hook is a PreToolUse(Bash) guard: payload JSON on stdin, exit 2 + "BLOCKED:" on
stderr to refuse. It only inspects the command string; nothing here executes.
"""
import json
import os
import subprocess
import sys

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

PK = "pkill -f myserver"


def verdict(cmd):
    """(fired, stderr) — fired is True iff the hook refused."""
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


MUST_BLOCK = [
    # --- W1: the wrappers the sentence names ------------------------------------------------
    ("W1 chroot",                            "chroot / " + PK),
    ("W1 chroot --userspec=U",               "chroot --userspec=nobody / " + PK),
    ("W1 systemd-run",                       "systemd-run " + PK),
    ("W1 systemd-run --user --scope",        "systemd-run --user --scope " + PK),
    ("W1 systemd-run -p PROP",               "systemd-run -p MemoryMax=1G " + PK),
    ("W1 nsenter -t PID -m -p",              "nsenter -t 1 -m -p " + PK),
    ("W1 nsenter --target PID --all",        "nsenter --target 1 --all " + PK),
    ("W1 docker exec",                       "docker exec web " + PK),
    ("W1 docker exec -it",                   "docker exec -it web " + PK),
    ("W1 docker exec -u USER",               "docker exec -u root web " + PK),
    ("W1 find -exec ... \\;",                "find /proc -maxdepth 0 -exec " + PK + " \\;"),
    # --- W2: the rest of the class ----------------------------------------------------------
    ("W2 unshare",                           "unshare -p " + PK),
    ("W2 podman exec",                       "podman exec web " + PK),
    ("W2 kubectl exec POD --",               "kubectl exec pod -- " + PK),
    ("W2 chrt",                              "chrt -i 0 " + PK),
    ("W2 setpriv",                           "setpriv --reuid=0 " + PK),
    ("W2 prlimit",                           "prlimit --nofile=10 " + PK),
    ("W2 numactl",                           "numactl -N 0 " + PK),
    ("W2 strace",                            "strace -f " + PK),
    ("W2 ltrace",                            "ltrace " + PK),
    ("W2 valgrind",                          "valgrind " + PK),
    ("W2 cgexec",                            "cgexec -g cpu:x " + PK),
    ("W2 firejail",                          "firejail " + PK),
    ("W2 bwrap",                             "bwrap --bind / / " + PK),
    ("W2 fakeroot",                          "fakeroot " + PK),
    ("W2 ip netns exec",                     "ip netns exec ns1 " + PK),
    ("W2 systemd-inhibit",                   "systemd-inhibit " + PK),
    ("W2 dbus-run-session",                  "dbus-run-session " + PK),
    ("W2 xvfb-run",                          "xvfb-run " + PK),
    ("W2 pkexec",                            "pkexec " + PK),
    ("W2 busybox APPLET",                    "busybox " + PK),
    # --- W3: find's other command-running actions ---------------------------------------------
    ("W3 find -execdir",                     "find . -maxdepth 0 -execdir " + PK + " \\;"),
    ("W3 find -ok",                          "find . -maxdepth 0 -ok " + PK + " \\;"),
    ("W3 find -okdir",                       "find . -maxdepth 0 -okdir " + PK + " \\;"),
    ("W3 find -exec ... {} +",               "find . -maxdepth 0 -exec " + PK + " {} +"),
    # --- W4: the wrapper in front of the kill word --------------------------------------------
    ("W4 chroot / kill $(pgrep -f)",         "chroot / kill $(pgrep -f myserver)"),
    ("W4 pgrep -f | xargs chroot / kill",    "pgrep -f myserver | xargs chroot / kill"),
    ("W4 nsenter kill $(pgrep -f)",          "nsenter -t 1 -m kill $(pgrep -f myserver)"),
    ("W4 ps | ... | xargs systemd-run kill", "ps aux | grep myserver | awk '{print $2}' | xargs systemd-run kill"),
    ("W4 ps | ... | xargs chroot / kill",    "ps aux | grep myserver | awk '{print $2}' | xargs chroot / kill"),
    ("W4 pgrep -f | xargs -I{} find -exec kill",
     "pgrep -f myserver | xargs -I{} find /proc/{} -maxdepth 0 -exec kill {} \\;"),
    # --- W5: the wrapper in front of the lister ----------------------------------------------
    ("W5 kill $(chroot / pgrep -f)",         "kill $(chroot / pgrep -f myserver)"),
    ("W5 nsenter pgrep -f | xargs kill",     "nsenter -t 1 -p pgrep -f myserver | xargs kill"),
    # --- W6: by path, and stacked ------------------------------------------------------------
    ("W6 /usr/sbin/chroot",                  "/usr/sbin/chroot / " + PK),
    ("W6 /usr/bin/systemd-run",              "/usr/bin/systemd-run --scope " + PK),
    ("W6 sudo chroot",                       "sudo chroot / " + PK),
    ("W6 timeout 5 docker exec",             "timeout 5 docker exec web " + PK),
    ("W6 sudo nsenter ... /usr/bin/pkill --full",
     "sudo nsenter -t 1 -m /usr/bin/pkill --full myserver"),
]

MUST_BE_SILENT = [
    ("S chroot / ls",                        "chroot / ls"),
    ("S docker exec web ls",                 "docker exec web ls"),
    ("S systemd-run a non-kill",             "systemd-run --user --scope sleep 5"),
    ("S find -exec rm",                      "find /tmp/x -name '*.o' -exec rm {} \\;"),
    ("S nsenter kill by explicit PID",       "nsenter -t 1 -p kill 4242"),
    ("S strace pgrep -f with no kill",       "strace -f pgrep -f myserver"),
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
