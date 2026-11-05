"""mh-every-pattern-keyed-kill-is-refused: every shell, every reader of the listing, every env -S.

Five classes, beside test-pattern-keyed-kill-blind-recertify-cert.py; this check derives the
sites the classes bind instead of naming the ones met:

  SHELLS  every program the registries call a shell -- the host's /etc/shells and the Debian
          archive's `shells` section (the apt lists) -- is read (bash_parse.SHELLS, or a wrapper
          or code runner the guard reads), or is stated out below with its reason; and EVERY
          member of SHELLS, asked with `NAME -c 'pkill -f X'` and with `kill $(NAME -c 'pgrep -f
          X')`, is refused, and with `NAME -c 'echo hi'` is not.
  READERS a pattern listing (pgrep -f, a ps listing piped on) reaches a kill through every
          construct that reads it on stdin: a while/until read loop, a brace group, a subshell,
          and code a command runs (bash -c, any shell of SHELLS, env -S, flock -c, sudo bash -c).
  RUNNERS a lister inside code a command runs prints into the kill that takes its output
          (`kill $(bash -c 'pgrep -f X')`, `kill $(env -i -S pgrep -f X)`).
  CLUSTER a wrapper's option cluster takes its argument as getopt does: env -S in any spelling
          (unquoted, -vS, -i -S, --split-string), screen -dmS NAME, sudo -iu USER.

The registries are read whole and printed; an empty one is red, not a vacuous green (the controls).
"""
import glob
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
HOOK = os.environ.get("HOOK", os.path.join(HERE, "..", "block-unsafe-kill.sh"))
sys.path.insert(0, os.path.join(HERE, ".."))
from bash_parse import SHELLS, WRAPPERS  # noqa: E402

# Members of the registries that are no program running a command string, or that the guard
# reads by another route. Each says why; a new member of either registry fails until it is here
# or in SHELLS.
STATED_OUT = {
    "tmux": "a session runs its shell-command arguments: read by bash_parse.handed_code()",
    "screen": "runs its operands as a command: a wrapper (bash_parse.WRAPPERS)",
    "busybox-static": "busybox: a wrapper (`busybox sh -c`), bash_parse.WRAPPERS",
    "autojump": "a directory jumper, sourced into a shell; runs no command string",
    "bash-completion": "completion functions sourced into bash; no program",
    "bashacks": "a library of bash functions; no program",
    "cleo": "plays back commands from a FILE (a script path, which the guard does not read)",
    "esh": "a templating engine over a FILE; no -c",
    "fdclone": "an interactive file manager",
    "fish-common": "data files of fish",
    "zsh-common": "data files of zsh",
    "mono-csharp-shell": "a C# REPL, not shell code",
    "screenie": "an interactive menu over screen sessions; runs no operand",
    "zgen": "a zsh plugin manager", "zplug": "a zsh plugin manager",
    "zsh-antidote": "a zsh plugin manager", "zsh-antigen": "a zsh plugin manager",
    "zsh-autosuggestions": "a zsh plugin", "zsh-syntax-highlighting": "a zsh plugin",
}
# Package -> the program names it installs as shells, where they differ from the package's.
PROGRAMS = {"csh": ["csh", "bsd-csh"], "ksh93u+m": ["ksh93", "ksh"], "ksh": ["ksh"],
            "mksh": ["mksh", "lksh", "mksh-static"]}


def etc_shells():
    try:
        lines = open("/etc/shells").read().splitlines()
    except OSError:
        return []
    return sorted({os.path.basename(l.strip()) for l in lines if l.strip().startswith("/")})


def debian_shells():
    out = set()
    for f in glob.glob("/var/lib/apt/lists/*_Packages"):
        for st in open(f, encoding="utf-8", errors="replace").read().split("\n\n"):
            d = {}
            for line in st.splitlines():
                if line[:1] not in (" ", "\t") and ":" in line:
                    k, _, v = line.partition(":")
                    d[k] = v.strip()
            if d.get("Section") == "shells" and d.get("Package"):
                out.add(d["Package"])
    return sorted(out)


def verdict(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0


PS = "ps aux | grep mhfix-no-such | awk '{print $2}'"
PG = "pgrep -f mhfix-no-such"

MUST_BLOCK = [
    # READERS: a listing read on stdin, by every reader
    ("ps | while read; kill",              PS + " | while read p; do kill $p; done"),
    ("ps | while IFS= read -r; kill -9",   PS + ' | while IFS= read -r p; do kill -9 "$p"; done'),
    ("ps | until ! read; kill",            PS + " | until ! read p; do kill $p; done"),
    ("ps | { read; kill; }",               PS + " | { read p; kill $p; }"),
    ("ps | ( read; kill )",                PS + " | ( read p; kill $p )"),
    ("ps | mapfile; kill",                 PS + ' | { mapfile -t a; kill "${a[@]}"; }'),
    ("ps -ef | bash -c 'read; kill'",      "ps -ef | awk '/x/{print $2}' | bash -c 'read p; kill $p'"),
    ("ps | sh -c xargs kill",              PS + " | sh -c 'xargs kill'"),
    ("ps | sudo bash -c read",             PS + " | sudo bash -c 'read p; kill $p'"),
    ("ps | env -S 'xargs kill'",           PS + " | env -S 'xargs kill'"),
    ("ps | flock -c xargs kill",           PS + " | flock /tmp/l -c 'xargs kill'"),
    ("ps | fish -c read",                  PS + " | fish -c 'read p; kill $p'"),
    ("pgrep -f | bash -c 'read; kill'",    PG + " | bash -c 'read p; kill $p'"),
    ("pgrep -f | bash -c 'xargs kill'",    PG + " | bash -c 'xargs kill'"),
    ("pgrep -f | zsh -c kill $(cat)",      PG + " | zsh -c 'kill $(cat)'"),
    ("pgrep -f | env -i -S 'xargs kill'",  PG + " | env -i -S 'xargs kill'"),
    # RUNNERS: the lister inside code whose output the kill takes
    ("kill $(bash -c pgrep -f)",           "kill $(bash -c 'pgrep -f mhfix-no-such')"),
    ("kill $(env -S 'pgrep -f')",          "kill $(env -S 'pgrep -f mhfix-no-such')"),
    ("kill $(env -i -S pgrep -f)",         "kill $(env -i -S pgrep -f mhfix-no-such)"),
    ("kill `sh -c pgrep -f`",              "kill `sh -c 'pgrep -f mhfix-no-such'`"),
    ("bash -c ps | xargs kill",            "bash -c 'ps aux' | grep x | awk '{print $2}' | xargs kill"),
    ("P=$(sudo sh -c pgrep -f); kill $P",  "P=$(sudo sh -c 'pgrep -f mhfix-no-such'); kill $P"),
    # CLUSTER: env -S and wrapper option clusters
    ("env -S unquoted",                    "env -S pkill -f mhfix-no-such"),
    ("env -vS quoted",                     "env -vS 'pkill -f mhfix-no-such'"),
    ("env -i -S unquoted",                 "env -i -S pkill -f mhfix-no-such"),
    ("env -u X -S",                        "env -u FOO -S pkill -f mhfix-no-such"),
    ("env -SSTR",                          "env '-Spkill -f mhfix-no-such'"),
    ("env --split-string STR",             "env --split-string 'pkill -f mhfix-no-such'"),
    ("env --split-string=STR",             "env --split-string='pkill -f mhfix-no-such'"),
    ("env -S 'pkill' -f X (args after)",   "env -S 'pkill' -f mhfix-no-such"),
    ("sudo env -iS",                       "sudo env -iS 'pkill -f mhfix-no-such'"),
    ("screen -dm",                         "screen -dm pkill -f mhfix-no-such"),
    ("screen -dmS NAME",                   "screen -dmS job pkill -f mhfix-no-such"),
    ("screen -S NAME -dm",                 "screen -S job -dm pkill -f mhfix-no-such"),
    ("screen -dmSjob",                     "screen -dmSjob pkill -f mhfix-no-such"),
    ("screen -L -Logfile F -dm",           "screen -L -Logfile /tmp/l -dm pkill -f mhfix-no-such"),
    ("screen -dm bash -c",                 "screen -dm bash -c 'pkill -f mhfix-no-such'"),
    ("screen -X exec",                     "screen -S job -X exec pkill -f mhfix-no-such"),
    ("/usr/bin/screen -dm kill $(pgrep)",  "/usr/bin/screen -dm kill $(pgrep -f mhfix-no-such)"),
    ("sudo -iu root pkill -f",             "sudo -iu root pkill -f mhfix-no-such"),
    ("sudo -iu root bash -c",              "sudo -iu root bash -c 'pkill -f mhfix-no-such'"),
    ("screen -dmS NAME sh -c",             "screen -dmS job sh -c 'pkill -f mhfix-no-such'"),
    ("timeout -k 5 10 bash -c",            "timeout -k5 10 bash -c 'pkill -f mhfix-no-such'"),
    ("fish --command STR",                 "fish --command 'pkill -f mhfix-no-such'"),
    ("fish -l -c",                         "fish -l -c 'pkill -f mhfix-no-such'"),
    ("fish -p FILE -c",                    "fish -p /tmp/prof -c 'pkill -f mhfix-no-such'"),
    ("fish kill (pgrep -f)",               "fish -c 'kill (pgrep -f mhfix-no-such)'"),
    ("fish set p (pgrep); kill $p",        "fish -c 'set p (pgrep -f mhfix-no-such); kill $p'"),
    ("tcsh -fc",                           "tcsh -fc 'pkill -f mhfix-no-such'"),
    ("csh kill `pgrep -f`",                "csh -c 'kill `pgrep -f mhfix-no-such`'"),
]
MUST_PASS = [
    ("kill by pid",                        "kill 12345"),
    ("ps | while read; echo",              PS + " | while read p; do echo $p; done"),
    ("ps | bash -c read; echo",            PS + " | bash -c 'read p; echo $p'"),
    ("pgrep -f | bash -c 'wc -l'",         PG + " | bash -c 'wc -l'"),
    ("bash -c pgrep -f, no kill",          "bash -c 'pgrep -f mhfix-no-such'"),
    ("x=$(bash -c pgrep); echo",           "x=$(bash -c 'pgrep -f mhfix-no-such'); echo $x"),
    ("env -S echo",                        "env -S echo hello"),
    ("env -uS echo (S is a name)",         "env -uS echo pkill"),
    ("screen -dmS job top",                "screen -dmS job top"),
    ("screen -ls",                         "screen -ls"),
    ("sudo -iu root id",                   "sudo -iu root id"),
    ("fish -c echo (date)",                "fish -c 'echo (date)'"),
    ("fish -c quoted paren",               "fish -c 'echo \"(pkill -f x)\"'"),
    ("kill $(bash -c 'echo 5')",           "kill $(bash -c 'echo 5')"),
]


def main():
    bad = []
    hosts, deb = etc_shells(), debian_shells()
    print("registry /etc/shells: %d name(s): %s" % (len(hosts), " ".join(hosts)))
    print("registry apt lists, Section shells: %d package(s): %s" % (len(deb), " ".join(deb)))
    if not hosts:
        bad.append("/etc/shells named no shell: the derivation walked nothing")
    if not deb:
        bad.append("no package of Section shells in /var/lib/apt/lists: the derivation walked nothing")
    for name in hosts:
        if name not in SHELLS and name not in STATED_OUT:
            bad.append("/etc/shells names %s, which is neither in SHELLS nor stated out" % name)
    for pkg in deb:
        if pkg in STATED_OUT:
            continue
        for prog in PROGRAMS.get(pkg, [pkg]):
            if prog not in SHELLS:
                bad.append("Debian's shells section has %s (program %s), neither in SHELLS nor "
                           "stated out" % (pkg, prog))
    for name in ("screen", "busybox"):
        if name not in WRAPPERS:
            bad.append("%s is stated out as a wrapper, and is not in WRAPPERS" % name)

    rows = list(MUST_BLOCK)
    for sh in sorted(SHELLS):
        rows.append(("SHELLS %s -c pkill -f" % sh, "%s -c 'pkill -f mhfix-no-such'" % sh))
        rows.append(("SHELLS kill $(%s -c pgrep)" % sh, "kill $(%s -c 'pgrep -f mhfix-no-such')" % sh))
    silent = list(MUST_PASS) + [("SHELLS %s -c echo" % sh, "%s -c 'echo hi'" % sh)
                                for sh in sorted(SHELLS)]
    for name, cmd in rows:
        ok = verdict(cmd)
        print("  %s %-36s %s" % ("refused" if ok else "SILENT ", name, cmd))
        if not ok:
            bad.append("must refuse, was silent: %s :: %s" % (name, cmd))
    for name, cmd in silent:
        ok = not verdict(cmd)
        print("  %s %-36s %s" % ("silent " if ok else "REFUSED", name, cmd))
        if not ok:
            bad.append("must stay silent, was refused: %s :: %s" % (name, cmd))
    print("%d must-refuse, %d must-stay-silent, %d wrong" % (len(rows), len(silent), len(bad)))
    for b in bad:
        print("FAIL:", b)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
