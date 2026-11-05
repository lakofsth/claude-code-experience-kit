"""Every program that runs its operands as a command is seen through (mh-code-handed-to-a-shell-is-code,
mh-every-pattern-keyed-kill-is-refused; amended 2026-10-28).

A guard that follows argv only through the wrappers it has listed (sudo, nohup, timeout, xargs,
...) and reads as code only the strings of the programs it has listed (bash -c, flock -c, su -c,
watch, ...) misses a pattern kill run through any other program that runs a command: `find . -exec
pkill -f X \\;`, `parallel -- 'pkill -f X'`, `git rebase -x 'pkill -f X'`, `chroot / pkill -f X`,
`systemd-run pkill -f X`, `ssh localhost 'pkill -f X'`.

THE HOST TABLE IS DERIVED FROM THE MAN PAGES, not from those names. The general rule, read off
every installed man1/man8 SYNOPSIS (the scanning script is original only):
  ARGV  a program whose synopsis ends `COMMAND [ARG]...` / `program [arguments]` execs its trailing
        operands: chroot, chrt, nsenter, unshare, setpriv, prlimit, setarch and its arch aliases,
        choom, uclampset, runcon, systemd-run, run0, systemd-inhibit, systemd-cat, dbus-run-session,
        nocache, fstab-decode, fakeroot, trickle, sshpass, strace, busybox, `docker|podman exec`,
        moreutils `parallel CMD -- ARGS`; and in mid-line, find's -exec/-execdir/-ok/-okdir up to
        `;` or `{} +`.
  CODE  a program whose page says the string goes to a shell: moreutils `parallel -- CMD...` (each
        to `sh -c`; GNU parallel's `::: CMD...` too), sg/newgrp (`-c CMD`, or the operand after the
        group), git rebase -x/--exec, git submodule foreach, git bisect run, git filter-branch's
        --*-filter, and ssh to THIS host (its words joined and run by the login shell).
  OUT, by the guard's purpose (the processes of this host): ssh, mosh and `systemd-run -H` to
  another host, and a docker daemon reached at a remote -H. Those are pinned silent below.

Each host template is a METAMORPHIC PAIR: run with every danger, the hook must refuse; run with a
harmless command, it must stay silent; run with the danger spelled as an ARGUMENT of a harmless
argv command (`echo 'pkill -f X'`), it must stay silent too, because the host passes it as data.
Where the host can run here without root, a unit, a container or the network, bash runs the
template first: with `touch marker` (argv) or `echo RAN > marker` (code) the marker must appear,
and with `echo 'touch marker'` it must not. chroot and nsenter need root, systemd-run and run0
start a unit, docker exec needs a container, ssh a login, git submodule foreach / bisect run /
filter-branch a prepared repository, and -ok a terminal: for those the man page is the reading.
"""
import json, os, grp, shutil, socket, subprocess, sys, tempfile
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "block-unsafe-kill.sh")
G = grp.getgrgid(os.getgid()).gr_name
HOST = socket.gethostname()

D_PAT = "pkill -f myserver"
D_ALL = "killall python3"
D_LOOP = "for p in $(pgrep -f srv); do kill $p; done"
D_GATE = "until ! pgrep -f myserver; do sleep 5; done"
D_PS = "ps aux | grep srv | xargs kill"

# Dangers as ARGV (one simple command each; a substitution in it is the outer shell's).
ARGV_DANGERS = [("pattern kill", D_PAT), ("killall", D_ALL),
                ("pgrep -f into the kill", "kill $(pgrep -f srv)"),
                ("sh -c holding a pgrep loop", "sh -c '" + D_LOOP + "'"),
                ("bash -c holding a ps listing", "bash -c '" + D_PS + "'")]
CODE_DANGERS = [("pattern kill", D_PAT), ("killall", D_ALL), ("pgrep -f loop", D_LOOP),
                ("wait gate", D_GATE), ("ps listing", D_PS)]


def verdict(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


# (template, runnable here). {A} is a command spelled as words, run as argv.
ARGV_HOSTS = [
    ("find . -maxdepth 0 -exec {A} \\;", True),
    ("find . -maxdepth 0 -execdir {A} ';'", True),
    ("find . -maxdepth 0 -exec {A} {} +", True),
    ("find . -type d -print -exec {A} \\; -quit", True),
    ("find . -maxdepth 0 -ok {A} \\;", False),
    ("find . -okdir {A} \\;", False),
    ("parallel {A} -- x", True),
    ("parallel -j 2 {A} -- x y", True),
    ("chroot / {A}", False),
    ("chroot --userspec=alice:alice / {A}", False),
    ("chrt -o 0 {A}", True),
    ("chrt --sched-runtime 5 -d 0 {A}", False),
    ("nsenter -t 1 -p {A}", False),
    ("nsenter --target 1 --mount --pid -- {A}", False),
    ("unshare {A}", True),
    ("unshare -r -w . {A}", True),
    ("setpriv --no-new-privs {A}", True),
    ("setpriv --reuid alice --regid alice --init-groups {A}", False),
    ("prlimit --nofile=1024 {A}", True),
    ("prlimit -o RESOURCE {A}", False),
    ("setarch x86_64 -R {A}", True),
    ("linux64 {A}", True),
    ("choom -n 1 {A}", True),
    ("uclampset -m 0 {A}", False),
    ("runcon -t unconfined_t {A}", False),
    ("runcon system_u:system_r:unconfined_t:s0 {A}", False),
    ("systemd-run --user --scope {A}", False),
    ("systemd-run -u kill1 -p MemoryMax=1G --wait {A}", False),
    ("run0 -u root {A}", False),
    ("systemd-inhibit --why=work {A}", False),
    ("systemd-cat -t tag {A}", False),
    ("dbus-run-session -- {A}", False),
    ("nocache {A}", True),
    ("fstab-decode {A}", True),
    ("fakeroot {A}", True),
    ("trickle -d 100 {A}", False),
    ("sshpass -p pw {A}", False),
    ("strace -o /dev/null {A}", True),
    ("strace -f -e trace=signal -o log {A}", True),
    ("busybox {A}", True),
    ("docker exec ctr {A}", False),
    ("docker exec -u root -w / -e A=1 ctr {A}", False),
    ("docker container exec -it ctr {A}", False),
    ("podman exec -l {A}", False),
    ("sudo chroot / {A}", False),
    ("timeout 9 nice chrt -o 0 {A}", True),
]
# (template, runnable here). {C} is a string the host hands a shell.
CODE_HOSTS = [
    ("parallel -- '{C}'", True),
    ("parallel -j 2 -- 'echo hi' '{C}'", True),
    ("parallel ::: '{C}'", False),
    ("echo '{C}' | parallel", False),
    ("parallel -j 4 <<< '{C}'", False),
    ("sg %s -c '{C}'" % G, True),
    ("sg %s '{C}'" % G, True),
    ("newgrp %s '{C}'" % G, True),
    ("newgrp -c '{C}' %s" % G, True),
    ("git rebase -x '{C}' HEAD~1", True),
    ("git rebase --exec='{C}' --root", True),
    ("git -C . -c core.pager=cat rebase -i --exec '{C}' HEAD~1", False),
    ("git submodule foreach '{C}'", False),
    ("git submodule --quiet foreach --recursive '{C}'", False),
    ("git bisect run sh -c '{C}'", False),
    ("git filter-branch --tree-filter '{C}' HEAD", False),
    ("ssh localhost '{C}'", False),
    ("ssh -p 22 -o BatchMode=yes alice@127.0.0.1 '{C}'", False),
    ("ssh %s '{C}'" % HOST, False),
    ("ssh -t ssh://alice@localhost:22 '{C}'", False),
    ("docker exec ctr sh -c '{C}'", False),
    ("systemd-run --user bash -c '{C}'", False),
    ("find . -maxdepth 0 -exec sh -c '{C}' \\;", True),
]


def setup(d):
    """A repository with two commits, so a git host has something to run against."""
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@t", GIT_EDITOR="true", GIT_SEQUENCE_EDITOR="true")
    for argv in (["git", "init", "-q"], ["git", "commit", "-q", "--allow-empty", "-m", "1"],
                 ["git", "commit", "-q", "--allow-empty", "-m", "2"]):
        subprocess.run(argv, cwd=d, env=env, capture_output=True)
    return env


def ran(tmpl, fill):
    """Bash's and the host's own reading: did the host run `fill` (it writes ./marker)?"""
    d = tempfile.mkdtemp(prefix="mh-runner-")
    try:
        env = setup(d)
        bash_oracle.run(["bash", "-c", tmpl.replace("{A}", fill).replace("{C}", fill)], cwd=d,
                       env=env, capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
        return os.path.exists(os.path.join(d, "marker"))
    finally:
        shutil.rmtree(d, ignore_errors=True)


MUST_BLOCK, MUST_BE_SILENT = [], []
for h, _ in ARGV_HOSTS:
    MUST_BLOCK += [("argv %s | %s" % (h, n), h.replace("{A}", d)) for n, d in ARGV_DANGERS]
    MUST_BE_SILENT += [("argv %s | harmless" % h, h.replace("{A}", "make test")),
                       ("argv %s | danger as data" % h, h.replace("{A}", "echo '" + D_PAT + "'"))]
for h, _ in CODE_HOSTS:
    MUST_BLOCK += [("code %s | %s" % (h, n), h.replace("{C}", d)) for n, d in CODE_DANGERS]
    MUST_BE_SILENT += [("code %s | harmless" % h, h.replace("{C}", "echo hello"))]
MUST_BLOCK += [
    ("argv: the kill and its lister both through find", "find /proc -maxdepth 0 -exec kill $(pgrep -f srv) {} +"),
    ("argv: lister piped into parallel's kill", "parallel kill -- $(pgrep -f myserver)"),
    ("argv: sshpass into ssh to this host", "sshpass -p pw ssh localhost '" + D_PAT + "'"),
    ("argv: two -exec clauses, the second kills", "find . -exec true \\; -exec " + D_PAT + " \\;"),
    ("argv: a {} + clause ends before the next", "find . -exec true {} + -exec " + D_PAT + " \\;"),
    ("code: ssh joins its words for the shell", "ssh localhost echo hi\\; " + D_PAT),
    ("code: GNU parallel's command form", "parallel '" + D_PAT + " {}' ::: x"),
    ("code: git rebase -x glued", "git rebase -x'" + D_PAT + "' main"),
    ("code: sg's -c before its group", "sg -c '" + D_PAT + "' " + G),
]
# A lister the OUTER shell expands into the string a host runs: its pids reach the host's kill
# (mh-a-lister-reaches-a-kill-through-every-binding-site). Silent at 20fd779 for every host,
# `bash -c` included, because the reader cut the string at the substitution's `$(`.
SUBST_HOSTS = ['bash -c "{K}"', 'flock ./lk -c "{K}"', 'su -c "{K}"', 'watch "{K}"',
               'sg %s -c "{K}"' % G, 'git rebase -x "{K}" main', 'parallel -- "{K}"',
               'ssh localhost "{K}"', 'ssh localhost {K}', 'find . -exec {K} \\;',
               'timeout 5 chroot / {K}', 'docker exec ctr {K}']
MUST_BLOCK += [("lister expanded into %s" % h, h.replace("{K}", "kill $(pgrep -f myserver)"))
               for h in SUBST_HOSTS]
MUST_BE_SILENT += [("lister expanded into %s, no kill" % h,
                    h.replace("{K}", "echo $(pgrep -f myserver)")) for h in SUBST_HOSTS]
MUST_BE_SILENT += [("a pid you started, expanded into %s" % h,
                    "sleep 9 & SRV=$!; " + h.replace("{K}", "kill $SRV")) for h in SUBST_HOSTS]
# Refused by mh-a-kill-the-runtime-guard-cannot-see-is-refused: a
# lister in the text and a kill handed to ssh, whichever host the text names (it cannot show that
# build-host is not this one, and this host's pids sent to a kill there are wrong pids anyway).
MUST_BLOCK += [("lister expanded into ssh to another host",
                'ssh build-host "kill $(pgrep -f myserver)"')]
MUST_BE_SILENT += [
    ("a kill of the pid you started, through find", "sleep 9 & SRV=$!; find . -maxdepth 0 -exec kill \"$SRV\" \\;"),
    ("a kill of the pid you started, through chrt", "sleep 9 & SRV=$!; chrt -o 0 kill \"$SRV\""),
    ("a kill of the pid you started, through ssh localhost", "sleep 9 & SRV=$!; ssh localhost \"kill $SRV\""),
    ("find -exec grep for the word pkill", "find . -name '*.py' -exec grep -l 'pkill -f' {} +"),
    ("find -exec with a harmless command", "find . -name '*.pyc' -exec rm -f {} +"),
    ("the host spelled as data", "echo \"find . -exec " + D_PAT + " \\;\""),
    ("parallel -- spelled in a commit message", "git commit -m \"parallel -- '" + D_PAT + "'\""),
    ("parallel with a harmless argv command", "parallel gzip -- a.log b.log"),
    ("git rebase -x a test run", "git rebase -x 'make test' main"),
    ("git rebase without -x", "git rebase -i main"),
    ("strace attached to a pid, no command", "strace -p 4242 -e trace=kill"),
    ("prlimit of a pid, no command", "prlimit --pid 4242 --nofile=1024"),
    ("chrt of a pid, no command", "chrt -p 0 4242"),
    # Out of purpose: the processes of ANOTHER host (mh-code-handed-to-a-shell-is-code).
    ("ssh to another host", "ssh build-host '" + D_PAT + "'"),
    ("ssh to another host, user and port", "ssh -p 2222 me@192.0.2.7 '" + D_PAT + "'"),
    ("systemd-run -H to another host", "systemd-run -H me@build-host " + D_PAT),
    ("docker against a remote daemon", "docker -H tcp://build-host:2375 exec ctr " + D_PAT),
]


def main():
    failures = []
    for h, runnable in ARGV_HOSTS:
        if runnable:
            if not ran(h, "touch marker"):
                failures.append("ORACLE: `%s` did not run its operands as a command here" % h)
            if ran(h, "echo 'touch marker'"):
                failures.append("ORACLE: `%s` ran an argument as code here" % h)
    for h, runnable in CODE_HOSTS:
        if runnable and not ran(h, "echo RAN > marker"):
            failures.append("ORACLE: `%s` did not run its string as shell code here" % h)
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
    if failures:
        print("FAIL (%d of %d cases)" % (len(failures), len(MUST_BLOCK) + len(MUST_BE_SILENT)))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d block + %d silent cases — every program that runs a command is seen through"
          % (len(MUST_BLOCK), len(MUST_BE_SILENT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
