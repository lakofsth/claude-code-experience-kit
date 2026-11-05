"""Check of hooks/tests/INVARIANTS.md `mh-a-kill-the-runtime-guard-cannot-see-is-refused`.

The sentence: hooks/block-unsafe-kill.sh refuses every command whose text holds a process
lister (a pgrep or pidof command, or a ps command piped on, in the command or in any code the
guard reads as code) together with a kill sent by a route a run-time kill guard
(not part of this kit) cannot see: a kill, pkill or killall command in code a shell other
than bash runs (its -c string; a pipe, herestring or heredoc into it; the string watch, at,
batch, git, sg or newgrp hands to /bin/sh); one among the words after ssh or mosh, to any host;
one run by sudo, doas, su, runuser, pkexec, run0 or env -i; one named by a path, or after
builtin or command; one beside unset -f kill, or beside an assignment to, or unset or export
of, KILL_GUARD_RUNTIME, CLAUDE_PID or BASH_ENV; and code handed to an interpreter (awk and sed
included) on its argv, a herestring, a heredoc or an echo/printf pipe, that holds `kill` after
no letter but `p`, or `send_signal`.

Written from the hooks/tests/INVARIANTS.md clause alone. The sentence is ONE-SIDED: it asks for a refusal whenever the
two are together, and says nothing about whether the lister's pids reach the kill. So every
kill here is a kill of a literal PID that no lister feeds (2147480000, which is no process), and
every lister names a process that does not exist — nothing is counted, nothing reaches; the
only thing that can make the hook refuse is the pairing the sentence names.

Directions, each derived from the sentence:

  R1. a non-bash shell's -c string (sh, dash, zsh, ksh, /bin/sh, behind a wrapper), and a
      pipe, herestring or heredoc into one; and the string watch, at, batch, git, sg and
      newgrp hand to /bin/sh.
  R2. the words after ssh or mosh, to a remote host and to this host's own names.
  R3. a kill run by sudo, doas, su, runuser, pkexec, run0, env -i.
  R4. a kill named by a path, or after `builtin` or `command`.
  R5. a kill beside `unset -f kill`, or beside an assignment to / unset / export of
      KILL_GUARD_RUNTIME, CLAUDE_PID or BASH_ENV.
  R6. code handed to an interpreter (python, perl, node, ruby, php, awk, sed) on argv, a
      herestring, a heredoc or an echo/printf pipe, holding `kill` after no letter or after
      `p` (os.kill, kill(, posix_kill, pkill, killpg), or `send_signal`.
  K.  each kill word the sentence names: kill, pkill, killall.
  L.  each lister the sentence names: pgrep -f, pgrep (by name), pidof, `ps … |` piped on.
  P.  where the lister sits: before the kill, after it, joined by && or a newline, inside a
      $(…) substitution, and inside code the guard reads as code (a bash -c string).
"""
import json, os, subprocess, sys
from concurrent.futures import ThreadPoolExecutor

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

PID = "2147480000"                 # no process holds it; a kill of a literal PID
NAME = "mhrtgcertnoproc"           # no process holds it; a lister finds nothing
K = "kill %s" % PID

LISTERS = [
    ("pgrep -f",   "pgrep -f %s" % NAME),
    ("pgrep name", "pgrep %s" % NAME),
    ("pidof",      "pidof %s" % NAME),
    ("ps | grep",  "ps aux | grep %s" % NAME),
]

# (direction label, a kill sent by a route the run-time guard cannot see; no lister in it)
ROUTES = [
    # --- R1: a shell other than bash ----------------------------------------------------------
    ("R1 sh -c",                      "sh -c '%s'" % K),
    ("R1 dash -c",                    "dash -c '%s'" % K),
    ("R1 zsh -c",                     "zsh -c '%s'" % K),
    ("R1 ksh -c",                     "ksh -c '%s'" % K),
    ("R1 /bin/sh -c",                 "/bin/sh -c '%s'" % K),
    ("R1 timeout 5 sh -c",            "timeout 5 sh -c '%s'" % K),
    ("R1 sh -c double quotes",        'sh -c "%s"' % K),
    ("R1 echo | sh",                  "echo '%s' | sh" % K),
    ("R1 printf | dash",              "printf '%%s\\n' '%s' | dash" % K),
    ("R1 sh herestring",              "sh <<< '%s'" % K),
    ("R1 sh heredoc",                 "sh <<'EOF'\n%s\nEOF" % K),
    ("R1 dash heredoc unquoted",      "dash <<EOF\n%s\nEOF" % K),
    ("R1 watch string",               "watch '%s'" % K),
    ("R1 watch -n 1 words",           "watch -n 1 %s" % K),
    ("R1 echo | at",                  "echo '%s' | at now" % K),
    ("R1 at herestring",              "at now + 1 minute <<< '%s'" % K),
    ("R1 batch heredoc",              "batch <<'EOF'\n%s\nEOF" % K),
    ("R1 git rebase -x",              "git rebase -x '%s' HEAD~1" % K),
    ("R1 git submodule foreach",      "git submodule foreach '%s'" % K),
    ("R1 sg GROUP -c",                "sg wheel -c '%s'" % K),
    ("R1 sg GROUP CMD",               "sg wheel '%s'" % K),
    ("R1 newgrp GROUP -c",            "newgrp wheel -c '%s'" % K),
    ("R1 K: sh -c pkill",             "sh -c 'pkill -x %s'" % NAME),
    ("R1 K: dash -c killall",         "dash -c 'killall %s'" % NAME),
    # --- R2: ssh / mosh, any host -----------------------------------------------------------------
    ("R2 ssh remote words",           "ssh build-host %s" % K),
    ("R2 ssh remote string",          "ssh build-host '%s'" % K),
    ("R2 ssh -p 22 user@host",        "ssh -p 22 alice@build-host '%s'" % K),
    ("R2 ssh localhost",              "ssh localhost '%s'" % K),
    ("R2 ssh 127.0.0.1",              "ssh 127.0.0.1 %s" % K),
    ("R2 ssh host sudo kill",         "ssh build-host sudo %s" % K),
    ("R2 mosh host --",               "mosh build-host -- %s" % K),
    ("R2 mosh localhost --",          "mosh localhost -- %s" % K),
    ("R2 K: ssh pkill",               "ssh build-host pkill -x %s" % NAME),
    # --- R3: run by another identity / a cleared environment ----------------------------------------
    ("R3 sudo",                       "sudo %s" % K),
    ("R3 sudo -u root",               "sudo -u root %s" % K),
    ("R3 sudo -n",                    "sudo -n %s" % K),
    ("R3 doas",                       "doas %s" % K),
    ("R3 doas -u root",               "doas -u root %s" % K),
    ("R3 su -c",                      "su -c '%s'" % K),
    ("R3 su root -c",                 "su root -c '%s'" % K),
    ("R3 runuser -u U --",            "runuser -u alice -- %s" % K),
    ("R3 runuser -c",                 "runuser alice -c '%s'" % K),
    ("R3 pkexec",                     "pkexec %s" % K),
    ("R3 run0",                       "run0 %s" % K),
    ("R3 env -i",                     "env -i %s" % K),
    ("R3 env -i PATH=",               "env -i PATH=/usr/bin:/bin %s" % K),
    ("R3 K: sudo pkill",              "sudo pkill -x %s" % NAME),
    ("R3 K: doas killall",            "doas killall %s" % NAME),
    # --- R4: named by a path, or after builtin / command --------------------------------------------
    ("R4 /bin/kill",                  "/bin/kill %s" % PID),
    ("R4 /usr/bin/kill",              "/usr/bin/kill %s" % PID),
    ("R4 /usr/bin/kill -9",           "/usr/bin/kill -9 %s" % PID),
    ("R4 builtin kill",               "builtin kill %s" % PID),
    ("R4 command kill",               "command kill %s" % PID),
    ("R4 command -p kill",            "command -p kill %s" % PID),
    ("R4 K: /usr/bin/pkill",          "/usr/bin/pkill -x %s" % NAME),
    ("R4 K: command pkill",           "command pkill -x %s" % NAME),
    # --- R5: beside a disarming of the guard ---------------------------------------------------------
    ("R5 unset -f kill;",             "unset -f kill; %s" % K),
    ("R5 unset -f kill &&",           "unset -f kill && %s" % K),
    ("R5 KILL_GUARD_RUNTIME=0 prefix", "KILL_GUARD_RUNTIME=0 %s" % K),
    ("R5 KILL_GUARD_RUNTIME= ;",      "KILL_GUARD_RUNTIME=; %s" % K),
    ("R5 export KILL_GUARD_RUNTIME",  "export KILL_GUARD_RUNTIME=0; %s" % K),
    ("R5 unset KILL_GUARD_RUNTIME",   "unset KILL_GUARD_RUNTIME; %s" % K),
    ("R5 CLAUDE_PID= prefix",         "CLAUDE_PID= %s" % K),
    ("R5 unset CLAUDE_PID",           "unset CLAUDE_PID; %s" % K),
    ("R5 export CLAUDE_PID",          "export CLAUDE_PID=1; %s" % K),
    ("R5 BASH_ENV= assignment",       "BASH_ENV=/dev/null; %s" % K),
    ("R5 unset BASH_ENV",             "unset BASH_ENV; %s" % K),
    ("R5 export BASH_ENV",            "export BASH_ENV=/dev/null; %s" % K),
    ("R5 export -n KILL_GUARD_RUNTIME", "export -n KILL_GUARD_RUNTIME; %s" % K),
    ("R5 K: unset -f kill; pkill",    "unset -f kill; pkill -x %s" % NAME),
    # --- R6: code handed to an interpreter -------------------------------------------------------------
    ("R6 python3 -c os.kill",         "python3 -c 'import os; os.kill(%s, 15)'" % PID),
    ("R6 python -c os.killpg",        "python -c 'import os; os.killpg(%s, 15)'" % PID),
    ("R6 python3 send_signal",        "python3 -c 'import subprocess as s; p = s.Popen([\"true\"]); p.send_signal(15)'"),
    ("R6 python3 pkill via run",      "python3 -c 'import subprocess; subprocess.run([\"pkill\", \"-x\", \"%s\"])'" % NAME),
    ("R6 python3 heredoc",            "python3 - <<'EOF'\nimport os\nos.kill(%s, 15)\nEOF" % PID),
    ("R6 python3 herestring",         "python3 <<< 'import os; os.kill(%s, 15)'" % PID),
    ("R6 echo | python3",             "echo 'import os; os.kill(%s, 15)' | python3" % PID),
    ("R6 printf | python3",           "printf '%%s\\n' 'import os; os.kill(%s, 15)' | python3" % PID),
    ("R6 perl -e kill",               "perl -e 'kill 15, %s'" % PID),
    ("R6 perl -e kill TERM",          "perl -e 'kill \"TERM\", %s'" % PID),
    ("R6 node -e process.kill",       "node -e 'process.kill(%s)'" % PID),
    ("R6 ruby -e Process.kill",       "ruby -e 'Process.kill(15, %s)'" % PID),
    ("R6 php -r posix_kill",          "php -r 'posix_kill(%s, 15);'" % PID),
    ("R6 awk system kill",            "awk 'BEGIN { system(\"kill %s\") }'" % PID),
    ("R6 awk pipe to kill",           "awk 'BEGIN { print %s | \"xargs kill\" }'" % PID),
    ("R6 sed e command",              "sed '1e kill %s' /dev/null" % PID),
    ("R6 perl heredoc",               "perl <<'EOF'\nkill 15, %s;\nEOF" % PID),
    ("R6 echo | node",                "echo 'process.kill(%s)' | node" % PID),
]

PLACEMENTS = [
    ("L; R",        lambda l, r: "%s; %s" % (l, r)),
    # a heredoc ends only at a line that is its delimiter alone, so after one the lister
    # goes on the next line, not after `;` on the delimiter's line (where it would be data)
    ("R; L",        lambda l, r: "%s%s%s" % (r, "\n" if r.endswith("EOF") else "; ", l)),
    ("L && R",      lambda l, r: "%s && %s" % (l, r)),
    ("L \\n R",     lambda l, r: "%s\n%s" % (l, r)),
    ("$(L); R",     lambda l, r: "n=$(%s | wc -l); %s" % (l, r)),
    ("bash -c L; R", lambda l, r: "bash -c '%s'; %s" % (l.replace("'", ""), r)),
]


def fired(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True, timeout=120)
    return p.returncode != 0


def cases():
    out = []
    for rl, r in ROUTES:                       # every route with every lister, lister first
        for ll, l in LISTERS:
            out.append(("%s | L=%s | L; R" % (rl, ll), "%s; %s" % (l, r)))
    for rl, r in ROUTES:                       # every route in every placement, pgrep -f
        for pl, f in PLACEMENTS[1:]:
            out.append(("%s | L=pgrep -f | %s" % (rl, pl), f(LISTERS[0][1], r)))
    return out


def main():
    cs = cases()
    with ThreadPoolExecutor(max_workers=int(os.environ.get("CERT_JOBS", "8"))) as ex:
        res = list(ex.map(lambda c: fired(c[1]), cs))
    bad = [(lab, cmd) for (lab, cmd), f in zip(cs, res) if not f]
    for lab, cmd in bad:
        print("NOT REFUSED: %s\n    %s" % (lab, cmd.replace("\n", "\\n")))
    by_dir = {}
    for (lab, _), f in zip(cs, res):
        d = lab.split()[0]
        by_dir.setdefault(d, [0, 0])
        by_dir[d][0] += 1
        by_dir[d][1] += 0 if f else 1
    for d in sorted(by_dir):
        print("direction %s: %d cases, %d not refused" % (d, by_dir[d][0], by_dir[d][1]))
    print("%d of %d cases not refused" % (len(bad), len(cs)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
