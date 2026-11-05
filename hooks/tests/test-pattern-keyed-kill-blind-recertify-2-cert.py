"""Check of mh-every-pattern-keyed-kill-is-refused, amended 2026-10-28. Written from the hooks/tests/INVARIANTS.md clause alone.

The sentence: hooks/block-unsafe-kill.sh refuses a kill whose pids are chosen by matching a
full command line -- pkill -f/--full with any options or option arguments around it, pgrep -f
into a kill, and a ps listing piped on into a kill -- whatever path, escape or wrapper (sudo,
timeout, env, xargs, ...) precedes the command word, where a wrapper is every program that
runs its operands as a command by its own man page (chroot, systemd-run, nsenter, docker
exec, find's -exec, ...).

Directions derived from the sentence. The cases are a PRODUCT, not a list: every way of
choosing pids by command line (K) is put behind every wrapper (W), at every word a wrapper
can precede (the pkill/pgrep/ps word, the kill word, the xargs that carries the pids), and
behind every path and escape spelling of the command word (E).

  K1  pkill -f / --full, options and option arguments before, between and after the flag.
  K2  pgrep -f / --full into a kill: $( ), backticks, a pipe into xargs, a for loop.
  K3  a ps listing piped on into a kill, through grep/awk filters.
  E   a path (/usr/bin/X), a backslash escape (\\X), a quoted command word ('X', "X", p\\kill).
  W   every program that runs its operands as a command by its man page: argv runners
      (`W [opts] COMMAND [ARG]...`), runners with a fixed operand before the command
      (chroot DIR, timeout DUR, flock FILE, ip netns exec NS, kubectl exec POD --), and
      find's -exec/-execdir/-ok/-okdir; nested wrappers too.
  S   scope: a kill by explicit pid, a pgrep/ps with no kill, and the wrappers running a
      harmless command stay silent -- the sentence refuses pattern-keyed kills, not wrappers.

The hook is a PreToolUse(Bash) guard: payload JSON on stdin, exit 2 + "BLOCKED:" on stderr
to refuse. Only the command string is inspected; nothing here executes it.
"""
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))
PAT = "myserver"


def verdict(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True, timeout=60)
    return p.returncode != 0 and "BLOCKED" in p.stderr


# W: argv-runner prefixes, each `PREFIX COMMAND [ARG]...` by the program's man page. A
# prefix carries the wrapper's own options and option arguments, as it is used.
WRAPPERS = [
    "sudo", "sudo -u root", "sudo -E -u root --", "sudo -n -H", "doas", "doas -u root",
    "run0", "pkexec", "runuser -u alice --", "setpriv --reuid=1000 --regid=1000 --clear-groups",
    "timeout 30", "timeout -s KILL 30", "timeout --kill-after=5 30", "timeout -k 5s 1m",
    "env", "env -i", "env -i PATH=/usr/bin", "env FOO=bar", "env -u HOME", "env -C /", "env --",
    "nice", "nice -n 10", "nice -n10", "ionice -c3", "ionice -c 2 -n 7", "chrt -f 10",
    "chrt --idle 0", "taskset 0x1", "taskset -c 0", "stdbuf -oL", "stdbuf -o L -e L",
    "nohup", "setsid", "setsid -f", "command", "command -p", "exec", "exec -a foo", "builtin",
    "time", "time -p", "/usr/bin/time", "/usr/bin/time -v", "/usr/bin/time -f %e",
    "unbuffer", "chronic", "eatmydata", "fakeroot", "nocache", "faketime 2020-01-01",
    "chroot /", "chroot --userspec=alice /", "nsenter -t 1 -m -p --", "nsenter --target 1 --pid",
    "unshare -m", "unshare --mount --", "setarch x86_64", "setarch x86_64 -R", "linux64",
    "prlimit --nofile=1024", "choom -n 100 --", "runcon -t unconfined_t",
    "systemd-run", "systemd-run --user --scope", "systemd-run -p MemoryMax=1G --wait",
    "systemd-run --unit=foo --", "systemd-inhibit", "systemd-inhibit --why=x",
    "systemd-cat", "systemd-cat -t foo", "dbus-run-session --",
    "strace -f -o /dev/null", "strace -e trace=none", "ltrace -f", "valgrind -q",
    "perf stat", "perf stat -e cycles --", "perf record -o /dev/null --", "perf trace --",
    "numactl -N 0", "numactl --interleave=all", "cgexec -g cpu:foo", "firejail --quiet",
    "firejail --noprofile", "bwrap --bind / / --", "bwrap --dev-bind / /",
    "xvfb-run -a", "torsocks", "proxychains4 -q", "trickle -d 100", "catchsegv",
    "flock /tmp/x.lock", "flock -w 5 /tmp/x.lock", "flock -x /tmp/x.lock", "flock -n /tmp/x.lock",
    "watch -n1", "watch -n 1 -x", "screen -dm", "screen -dmS foo", "tmux new-session -d",
    "docker exec c1", "docker exec -it c1", "docker exec -u root c1", "podman exec c1",
    "docker container exec c1", "kubectl exec pod1 --", "kubectl exec -it pod1 -c box --",
    "ip netns exec ns1", "ip -n ns1 exec", "lxc-attach -n c1 --", "schroot -c sid --",
    "machinectl shell .host", "mpirun -np 1", "srun -n1", "aa-exec -p unconfined --",
    "sg wheel -c", "busybox", "toybox", "gdb -batch -ex run --args", "rr record",
    "nohup nice -n 5", "sudo timeout 30", "sudo -u root env -i", "timeout 30 sudo -n",
    "env -i nice -n 5 setsid", "systemd-run --scope sudo", "chroot / env -i",
    "cpulimit -l 50 --", "chpst -u alice", "softlimit -m 1000000", "envdir /tmp",
    "setuidgid alice", "ssh-agent", "dbus-launch", "flatpak-spawn --host", "toolbox run",
    "distrobox-enter -n box --", "conda run -n base", "poetry run", "uv run", "bundle exec",
    "direnv exec .", "fakechroot", "proot -0", "lxc exec c1 --", "incus exec c1 --",
    "nerdctl exec c1", "runc exec c1", "apptainer exec img.sif", "singularity exec img.sif",
    "rlwrap", "logsave /dev/null", "tsp", "sem", "daemonize", "watchexec --",
    "xterm -e", "gnome-terminal --", "konsole -e", "sudo -s", "sudo -i",
    "FOO=1", "2>/dev/null", "coproc", "!", "nice -n 5 --",
    "xargs", "xargs -r", "xargs -0", "xargs -n1", "xargs -I{}", "xargs -P4 -n 1",
]

# W that take the command as ONE string by their man page (`-c STRING`, a single operand).
STRING_RUNNERS = [
    "bash -c", "sh -c", "dash -c", "zsh -c", "bash -lc", "sudo sh -c", "sudo bash -c",
    "su -c", "su root -c", "su - root -c", "runuser -u alice -- sh -c", "sg wheel -c",
    "flock /tmp/x.lock -c", "flock -w 5 /tmp/x.lock -c", "script -qc", "script -q /dev/null -c",
    "watch -n1", "nohup sh -c", "timeout 30 bash -c", "env -S", "docker exec c1 sh -c",
    "kubectl exec pod1 -- sh -c", "chroot / sh -c", "systemd-run --scope sh -c",
    "tmux new-session -d", "nix-shell --run", "screen -dm sh -c", "ksh -c", "mksh -c",
    "busybox sh -c", "tmux new-window", "tmux split-window", "parallel :::", "parallel --",
    "ssh localhost", "ssh 127.0.0.1", "xterm -e sh -c", "sudo -s", "su alice -c",
    "podman exec c1 bash -c", "nsenter -t 1 -a sh -c", "flatpak-spawn --host sh -c",
    "distrobox-enter -n box -- sh -c", "lxc exec c1 -- sh -c", "toolbox run sh -c",
]

# find's -exec family: the command sits between the primary and its `;` or `+`.
FIND_EXEC = [
    ("find /tmp -maxdepth 0 -exec", " \\;"), ("find /tmp -maxdepth 0 -exec", " {} +"),
    ("find /tmp -maxdepth 0 -execdir", " \\;"), ("find /tmp -maxdepth 0 -ok", " \\;"),
    ("find /tmp -maxdepth 0 -okdir", " \\;"), ("find . -name x -exec", " ';'"),
]

# K: argv commands that choose pids by full command line (a fragment a wrapper may precede).
PKILLS = [
    f"pkill -f {PAT}", f"pkill --full {PAT}", f"pkill -9 -f {PAT}", f"pkill -f -9 {PAT}",
    f"pkill -u root -f {PAT}", f"pkill --signal TERM -f {PAT}", f"pkill -fe {PAT}",
    f"pkill -ef {PAT}", f"pkill -f -u root {PAT}", f"pkill -SIGKILL --full -u root {PAT}",
    f"pkill -o -f {PAT}", f"pkill -n -f {PAT}", f"pkill -P 1 -f {PAT}",
]
ESCAPES = [f"/usr/bin/pkill -f {PAT}", f"/bin/pkill -f {PAT}", f"\\pkill -f {PAT}",
           f"'pkill' -f {PAT}", f'"pkill" -f {PAT}', f"p\\kill -f {PAT}", f"pk''ill -f {PAT}",
           f"$'pkill' -f {PAT}", f"./../../usr/bin/pkill -f {PAT}"]

AWK = "awk '{print $2}'"
SILENT_INNER = ["kill 12345", "kill -9 12345", f"pgrep -f {PAT}", "echo hi", f"pkill -x {PAT}zz"]


def must_refuse():
    cases = []
    for k in PKILLS + ESCAPES:
        cases.append(("K1/E bare", k))
    # Every K behind every argv wrapper, at every word it can precede.
    for w in WRAPPERS:
        cases += [
            (f"K1 behind [{w}]", f"{w} pkill -f {PAT}"),
            (f"K1 opts behind [{w}]", f"{w} pkill -u root --full {PAT}"),
            (f"K1 path behind [{w}]", f"{w} /usr/bin/pkill -f {PAT}"),
            (f"K2 pgrep in $( ) behind [{w}]", f"kill $({w} pgrep -f {PAT})"),
            (f"K2 kill word behind [{w}]", f"{w} kill $(pgrep -f {PAT})"),
            (f"K2 pgrep | xargs kill, pgrep behind [{w}]", f"{w} pgrep -f {PAT} | xargs kill"),
            (f"K2 pgrep | kill word behind [{w}]", f"pgrep -f {PAT} | xargs {w} kill"),
            (f"K2 backticks behind [{w}]", f"{w} kill `pgrep -f {PAT}`"),
            (f"K3 ps behind [{w}]", f"{w} ps aux | grep {PAT} | {AWK} | xargs kill"),
            (f"K3 kill word behind [{w}]", f"ps aux | grep {PAT} | {AWK} | xargs {w} kill"),
            (f"K3 ps -eo behind [{w}]", f"{w} ps -eo pid,args | grep {PAT} | {AWK} | xargs -r kill -9"),
            # A wrapper's command may itself be a shell, whose -c operand is the command.
            (f"K1 [{w}] sh -c", f"{w} sh -c 'pkill -f {PAT}'"),
            (f"K2 [{w}] bash -c", f"{w} bash -c 'kill $(pgrep -f {PAT})'"),
            (f"K3 [{w}] sh -c", f"{w} sh -c \"ps aux | grep {PAT} | {AWK} | xargs kill\""),
        ]
        if not w.startswith("xargs"):
            cases.append((f"K2 pgrep | [{w}] xargs kill", f"pgrep -f {PAT} | {w} xargs kill"))
            cases.append((f"K3 ps | [{w}] xargs kill", f"ps aux | grep {PAT} | {AWK} | {w} xargs kill"))
    # Behind a path or escape on the wrapper word itself.
    for w in ["sudo", "timeout 30", "env", "nice", "nohup", "setsid", "chroot /", "strace -f",
              "systemd-run", "numactl -N 0", "valgrind", "faketime 2020-01-01", "xargs"]:
        head, _, tail = w.partition(" ")
        rest = (" " + tail) if tail else ""
        for spelled in (f"/usr/bin/{head}", f"\\{head}", f"'{head}'"):
            cases.append((f"E on wrapper [{spelled}{rest}]", f"{spelled}{rest} pkill -f {PAT}"))
            cases.append((f"E on wrapper, K2 [{spelled}{rest}]",
                          f"pgrep -f {PAT} | {spelled}{rest} kill" if head == "xargs"
                          else f"{spelled}{rest} kill $(pgrep -f {PAT})"))
    # String runners: the command is one operand.
    for w in STRING_RUNNERS:
        cases += [
            (f"K1 in string [{w}]", f"{w} 'pkill -f {PAT}'"),
            (f"K2 in string [{w}]", f"{w} 'kill $(pgrep -f {PAT})'"),
            (f"K3 in string [{w}]", f"{w} \"ps aux | grep {PAT} | {AWK} | xargs kill\""),
        ]
    # find's -exec family.
    for pre, end in FIND_EXEC:
        cases += [
            (f"K1 find [{pre} ..{end}]", f"{pre} pkill -f {PAT}{end}"),
            (f"K2 find [{pre} ..{end}]", f"pgrep -f {PAT} | xargs -I@ {pre} kill @{end}"),
            (f"K3 find ps [{pre} ..{end}]", f"{pre} ps aux{end} | grep {PAT} | {AWK} | xargs kill"),
            (f"K1 find sh -c [{pre} ..{end}]", f"{pre} sh -c 'pkill -f {PAT}'{end}"),
        ]
    # Other pgrep -f -> kill carriers and ps listings, bare and behind one wrapper.
    for pre in ("", "sudo ", "timeout 30 ", "valgrind -q ", "chroot / "):
        cases += [
            (f"K2 kill -s TERM [{pre}]", f"{pre}kill -s TERM $(pgrep -f {PAT})"),
            (f"K2 kill -- [{pre}]", f"{pre}kill -9 -- $(pgrep -d ' ' -f {PAT})"),
            (f"K2 while read [{pre}]", f"{pre}pgrep -f {PAT} | while read p; do kill $p; done"),
            (f"K2 pgrep -af | awk [{pre}]", f"{pre}pgrep -af {PAT} | {AWK.replace('$2', '$1')} | xargs kill"),
            (f"K2 var [{pre}]", f"P=$({pre}pgrep -f {PAT}); kill $P"),
            (f"K3 kill $(ps ..) [{pre}]", f"{pre}kill $(ps aux | grep {PAT} | {AWK})"),
            (f"K3 ps -C [{pre}]", f"{pre}ps -o pid= -C myserv | xargs kill"),
            (f"K3 ps axo [{pre}]", f"{pre}ps axo pid,cmd | grep {PAT} | cut -d' ' -f1 | xargs kill"),
            (f"K3 ps awk-filter [{pre}]", f"{pre}ps -ef | awk '/{PAT}/{{print $2}}' | xargs kill"),
            (f"K3 ps while read [{pre}]", f"{pre}ps aux | grep {PAT} | {AWK} | while read p; do kill $p; done"),
            (f"K1 in if [{pre}]", f"if true; then {pre}pkill -f {PAT}; fi"),
            (f"K1 in group [{pre}]", f"{{ {pre}pkill -f {PAT}; }}"),
            (f"K1 in subshell [{pre}]", f"({pre}pkill -f {PAT})"),
            (f"K1 after && [{pre}]", f"true && {pre}pkill -f {PAT}"),
        ]
    return cases


def must_stay_silent():
    cases = [("S bare " + s, s) for s in SILENT_INNER]
    cases += [("S ps listing, no kill", f"ps aux | grep {PAT}"),
              ("S pgrep -f, no kill", f"pgrep -fa {PAT}"),
              ("S kill by $!", "sleep 100 & SRV=$!; kill \"$SRV\"")]
    for w in WRAPPERS:
        for s in ("kill 12345", "echo hi", "sh -c 'echo hi'"):
            cases.append((f"S [{w}] {s}", f"{w} {s}"))
    for w in STRING_RUNNERS:
        cases.append((f"S string [{w}] echo", f"{w} 'echo hi'"))
    for pre, end in FIND_EXEC:
        cases.append((f"S find [{pre}] echo", f"{pre} echo {{}}{end}"))
    return cases


def main():
    refuse, silent = must_refuse(), must_stay_silent()
    with ThreadPoolExecutor(max_workers=8) as ex:
        rv = list(ex.map(lambda c: verdict(c[1]), refuse))
        sv = list(ex.map(lambda c: verdict(c[1]), silent))
    wrong = 0
    for (name, cmd), fired in zip(refuse, rv):
        if not fired:
            wrong += 1
            print(f"RED  must-refuse  {name}\n       silent: {cmd}")
    for (name, cmd), fired in zip(silent, sv):
        if fired:
            wrong += 1
            print(f"RED  must-stay-silent  {name}\n       refused: {cmd}")
    print(f"{len(refuse)} must-refuse, {len(silent)} must-stay-silent; {wrong} wrong")
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
