"""Check of hooks/tests/INVARIANTS.md `mh-a-whole-account-kill-is-refused`, as amended
2026-11-04 (a later -s/-n re-reads the signal, literal brace and blank-led targets, -n/-o
beside host-wide filters, signal 0 read by BOTH kills).

The sentence: hooks/block-unsafe-kill.sh refuses a kill whose target set is the whole
account or the caller's process group -- a `kill` whose literal target is PID -1 or PID 0
in any grammar bash's kill or `/bin/kill` reads a target in, with the signal that kill
actually sends (a later `-s`/`-n`, glued or separate, or `/bin/kill`'s `-s`/`--signal`
anywhere before `--`, re-sets the signal an earlier word named), after bash's brace
expansion of a literal word and past a blank before the number, [... ps listings, owner
filters ...] -- as it refuses `pkill -u "$USER"`; and it refuses pkill, or pgrep into a
kill, whose only criteria are `-n`/`-o` and host-wide filters (`--ns`, `--nslist`, `-t`,
`--cgroup`, `-r`, `-O`, any spelling), which selects the newest or oldest process on the
whole host whoever owns it. A kill that both bash's kill and `/bin/kill` read as sending
signal 0, or as listing signals, is never refused by this rule.

Written from the hooks/tests/INVARIANTS.md clause alone. The unamended clauses are pinned by
test-block-unsafe-kill-whole-account-cert.py; this check pins the amendment's directions:

  A. bash's kill: an earlier signal word (-0, -s 0, -n 0) re-set by a LATER -s / -n,
     separate and glued (-sKILL, -n9), on PID -1 and PID 0.
  B. /bin/kill: an earlier -0 / -s 0 re-set by a later -s / --signal / --signal=,
     glued, and AFTER the target word (getopt permutes; "anywhere before --").
  C. brace expansion of a literal word yielding -1 or 0 as a target: {-1,}, {,0},
     -{1..1}, {0..1}, a brace that yields the signal word and the `--` before -1.
  D. a blank (space, tab) before the number in a quoted target: " -1", "	0", -- " -1".
  E. pkill / pgrep-into-kill whose only criteria are -n/-o and host-wide filters, each
     filter in its spellings (short separate, short glued, long, long=, an abbreviation
     procps-ng reads unambiguously: --term, --ru, --cg, --nsl), --newest/--oldest.
  F. the exemption, silent: the reverse order (a later -s 0 re-sets an earlier signal to 0),
     which BOTH kills measured as sending signal 0; signal 0 on a brace / blank-led -1/0.
  G. over-reach, silent: a re-set signal on a literal ordinary pid, brace / blank-led
     ordinary pids, a host-wide filter with a pattern, a host-wide listing that reaches no kill.

Grammar measured with bash and procps-ng /bin/kill against a decoy
process, never against -1 or 0: `kill -0 -s TERM P`, `kill -0 -n15 P`, `kill -s 0 -sTERM P`,
`/bin/kill -0 --signal=TERM P`, `/bin/kill -s 0 P -s TERM` all deliver TERM; `kill -9 -s 0 -- P`,
`kill -s TERM -s 0 -- P`, `/bin/kill -9 -s 0 -- P`, `/bin/kill -s TERM -s 0 -- P`,
`/bin/kill --signal TERM -s 0 P` deliver nothing (signal 0); `kill -TERM " P"`,
`/bin/kill -TERM -- " P"`, `kill -TERM {P,}` deliver TERM to P.

Not pinned silent: any re-set that only ONE kill reads as 0 (e.g. `kill -s TERM -n 0 P`, which
bash reads as 0 and /bin/kill rejects -n) -- the exemption asks both.
"""
import json, os, subprocess, sys

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))


def verdict(cmd):
    """(fired, stderr) -- fired is True iff the hook exited non-zero."""
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True, timeout=60)
    return p.returncode != 0, p.stderr


MUST_BLOCK = [
    # --- anchor ------------------------------------------------------------------------
    ("anchor pkill -u $USER",              'pkill -u "$USER"'),
    # --- A: bash's kill, a later -s/-n re-sets the signal ------------------------------
    ("kill -0 -s KILL -1",                 "kill -0 -s KILL -1"),
    ("kill -0 -s 9 -- -1",                 "kill -0 -s 9 -- -1"),
    ("kill -0 -sKILL -1 glued",            "kill -0 -sKILL -1"),
    ("kill -0 -n 9 -1",                    "kill -0 -n 9 -1"),
    ("kill -0 -n9 -- -1 glued",            "kill -0 -n9 -- -1"),
    ("kill -s 0 -s TERM -1",               "kill -s 0 -s TERM -1"),
    ("kill -s 0 -n 15 -- -1",              "kill -s 0 -n 15 -- -1"),
    ("kill -n 0 -s KILL -1",               "kill -n 0 -s KILL -1"),
    ("kill -0 -s TERM 0",                  "kill -0 -s TERM 0"),
    ("kill -s 0 -sHUP 0 glued",            "kill -s 0 -sHUP 0"),
    ("kill -0 -n 9 -- 0",                  "kill -0 -n 9 -- 0"),
    ("builtin kill -0 -s KILL -1",         "builtin kill -0 -s KILL -1"),
    # --- B: /bin/kill, -s/--signal anywhere before -- re-sets ---------------------------
    ("/bin/kill -0 -s KILL -- -1",         "/bin/kill -0 -s KILL -- -1"),
    ("/bin/kill -s 0 -s 9 -- -1",          "/bin/kill -s 0 -s 9 -- -1"),
    ("/bin/kill -0 --signal KILL -- -1",   "/bin/kill -0 --signal KILL -- -1"),
    ("/bin/kill -0 --signal=KILL -- -1",   "/bin/kill -0 --signal=KILL -- -1"),
    ("/bin/kill -0 -sKILL -- -1 glued",    "/bin/kill -0 -sKILL -- -1"),
    ("/bin/kill --signal 0 --signal TERM 0", "/bin/kill --signal 0 --signal TERM 0"),
    ("/bin/kill -s 0 0 -s KILL (after)",   "/bin/kill -s 0 0 -s KILL"),
    ("/bin/kill -0 0 --signal TERM (after)", "/bin/kill -0 0 --signal TERM"),
    ("/usr/bin/kill -0 -s TERM -- -1",     "/usr/bin/kill -0 -s TERM -- -1"),
    ("env kill -0 -s KILL -- -1",          "env kill -0 -s KILL -- -1"),
    # --- C: brace expansion of a literal word --------------------------------------------
    ("kill -9 {-1,}",                      "kill -9 {-1,}"),
    ("kill -9 {,-1}",                      "kill -9 {,-1}"),
    ("kill -9 -- {-1,}",                   "kill -9 -- {-1,}"),
    ("kill -9 -{1..1}",                    "kill -9 -{1..1}"),
    ("kill -TERM {0,}",                    "kill -TERM {0,}"),
    ("kill {,0}",                          "kill {,0}"),
    ("kill -9 {0..1}",                     "kill -9 {0..1}"),
    ("kill -9 {12345,-1}",                 "kill -9 {12345,-1}"),
    ("kill {-9,-1} (signal+target)",       "kill {-9,-1}"),
    ("kill -{9,-} -1 (signal+--)",         "kill -{9,-} -1"),
    ("/bin/kill -9 -- {-1,}",              "/bin/kill -9 -- {-1,}"),
    ("/bin/kill {0,}",                     "/bin/kill {0,}"),
    # --- D: a blank before the number -----------------------------------------------------
    ("kill -9 ' -1'",                      "kill -9 ' -1'"),
    ("kill -9 \" -1\"",                    'kill -9 " -1"'),
    ("kill -- ' -1'",                      "kill -- ' -1'"),
    ("kill ' 0'",                          "kill ' 0'"),
    ("kill -9 '\\t0' tab",                 "kill -9 '\t0'"),
    ("kill -9 '  -1' two blanks",          "kill -9 '  -1'"),
    ("/bin/kill -9 -- ' -1'",              "/bin/kill -9 -- ' -1'"),
    ("/bin/kill ' 0'",                     "/bin/kill ' 0'"),
    # --- E: -n/-o beside host-wide filters only ------------------------------------------
    ("pkill -n --ns 1",                    "pkill -n --ns 1"),
    ("pkill -o --ns=1",                    "pkill -o --ns=1"),
    ("pkill -n --nslist net --ns 1",       "pkill -n --nslist net --ns 1"),
    ("pkill -o --nslist=pid --ns 1",       "pkill -o --nslist=pid --ns 1"),
    ("pkill -n --nsl net --ns 1 abbrev",   "pkill -n --nsl net --ns 1"),
    ("pkill -n -t pts/0",                  "pkill -n -t pts/0"),
    ("pkill -o -tpts/0 glued",             "pkill -o -tpts/0"),
    ("pkill -n --terminal pts/0",          "pkill -n --terminal pts/0"),
    ("pkill -n --terminal=pts/0",          "pkill -n --terminal=pts/0"),
    ("pkill -o --term pts/0 abbrev",       "pkill -o --term pts/0"),
    ("pkill -n --cgroup /user.slice",      "pkill -n --cgroup /user.slice"),
    ("pkill -o --cgroup=/system.slice",    "pkill -o --cgroup=/system.slice"),
    ("pkill -n --cg /user.slice abbrev",   "pkill -n --cg /user.slice"),
    ("pkill -n -r S",                      "pkill -n -r S"),
    ("pkill -o -rR glued",                 "pkill -o -rR"),
    ("pkill -n --runstates S",             "pkill -n --runstates S"),
    ("pkill -n --runstates=S",             "pkill -n --runstates=S"),
    ("pkill -o --ru S abbrev",             "pkill -o --ru S"),
    ("pkill -n -O 10",                     "pkill -n -O 10"),
    ("pkill -o -O10 glued",                "pkill -o -O10"),
    ("pkill -n --older 10",                "pkill -n --older 10"),
    ("pkill -o --older=10",                "pkill -o --older=10"),
    ("pkill --newest -t pts/0",            "pkill --newest -t pts/0"),
    ("pkill --oldest --ns 1",              "pkill --oldest --ns 1"),
    ("pkill -9 -n -r R -O 5 (two filters)", "pkill -9 -n -r R -O 5"),
    ("pkill -KILL -o --cgroup / -t pts/1", "pkill -KILL -o --cgroup / -t pts/1"),
    ("pgrep -n -t pts/0 | xargs kill",     "pgrep -n -t pts/0 | xargs kill"),
    ("kill $(pgrep -o --ns 1)",            "kill $(pgrep -o --ns 1)"),
    ("kill -9 $(pgrep -n -r R)",           "kill -9 $(pgrep -n -r R)"),
    ("pgrep -o -O 60 | xargs kill -9",     "pgrep -o -O 60 | xargs kill -9"),
    ("kill $(pgrep --newest --cgroup /)",  "kill $(pgrep --newest --cgroup /)"),
]

MUST_BE_SILENT = [
    # --- F: signal 0 read by both kills is never refused by this rule ---------------------
    ("kill -9 -s 0 -- -1",                 "kill -9 -s 0 -- -1"),
    ("kill -TERM -s 0 0",                  "kill -TERM -s 0 0"),
    ("kill -s KILL -s 0 -- -1",            "kill -s KILL -s 0 -- -1"),
    ("/bin/kill -9 -s 0 -- -1",            "/bin/kill -9 -s 0 -- -1"),
    ("/bin/kill -s TERM -s 0 -- 0",        "/bin/kill -s TERM -s 0 -- 0"),
    ("/bin/kill --signal TERM -s 0 -- -1", "/bin/kill --signal TERM -s 0 -- -1"),
    ("kill -0 {-1,}",                      "kill -0 {-1,}"),
    ("kill -0 ' -1'",                      "kill -0 ' -1'"),
    ("kill -s 0 -- ' 0'",                  "kill -s 0 -- ' 0'"),
    ("kill -0 -- -1 (baseline)",           "kill -0 -- -1"),
    # --- G: over-reach -----------------------------------------------------------------
    ("kill -0 -s KILL a pid",              "kill -0 -s KILL 12345"),
    ("/bin/kill -s 0 12345 -s KILL",       "/bin/kill -s 0 12345 -s KILL"),
    ("kill -9 {12345,12346}",              "kill -9 {12345,12346}"),
    ("kill -9 ' 12345'",                   "kill -9 ' 12345'"),
    ("kill -9 {10..12}",                   "kill -9 {10..12}"),
    ("pgrep -n -t pts/0 (no kill)",        "pgrep -n -t pts/0"),
    ("pgrep -o --ns 1 (no kill)",          "pgrep -o --ns 1"),
]


def main():
    failures = []
    for label, cmd in MUST_BLOCK:
        fired, err = verdict(cmd)
        if not fired:
            failures.append("NOT BLOCKED [%s]: %s" % (label, cmd))
        elif "BLOCKED" not in err:
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
    print("OK: %d block + %d silent cases of the amended whole-account kill" %
          (len(MUST_BLOCK), len(MUST_BE_SILENT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
