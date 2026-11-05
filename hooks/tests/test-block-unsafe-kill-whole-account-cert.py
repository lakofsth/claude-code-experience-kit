"""Check of hooks/tests/INVARIANTS.md `mh-a-whole-account-kill-is-refused`.

The sentence: hooks/block-unsafe-kill.sh refuses a kill whose target set is the whole
account or the caller's process group -- a `kill` whose target is PID -1 or PID 0 in any
grammar bash's kill or `/bin/kill` reads a target in, a `ps` listing that selects by owner,
every process or nothing whose pids reach a kill, or a pkill/pgrep owner filter in any
spelling procps accepts, abbreviated long options included -- as it refuses
`pkill -u "$USER"`; and it refuses pkill, or pgrep into a kill, whose only criterion is
`-n`/`-o`, which selects the newest or oldest process on the whole host whoever owns it.
A kill that sends signal 0, or lists signals, is never refused by this rule.

Written from the hooks/tests/INVARIANTS.md clause alone. Directions, each derived from the sentence:

  1. PID -1 as a target, in every grammar a target is read in: after a signal given as
     -N / -NAME / -SIGNAME / -s / -n / --signal, after `--`, quoted, beside another pid,
     for the builtin (bare, `builtin`, `command`) and for /bin/kill (absolute, env).
  2. PID 0 as a target, the same grammars.
  3. A `ps` listing whose pids reach a kill, selecting by owner (-u, -U, --user, BSD x),
     every process (-e, -A, ax, aux) or nothing (bare `ps -o pid=`), reaching the kill
     through a pipe to xargs, a command substitution, and a while-read loop.
  4. A pkill / pgrep-into-kill owner filter in each spelling procps accepts: -u, -U,
     attached value, --euid / --uid with space and with `=`, and abbreviated long options
     (--eu, --eui, --ui).
  5. pkill, or pgrep into a kill, whose only criterion is -n / -o / --newest / --oldest
     (and abbreviations procps accepts -- `--new`, `--oldes`; `--old` and `--olde` are
     ambiguous with `--older` in procps-ng's option table and are refused by pgrep itself), with and
     without a signal.
  6. The exemption, silent: the same targets and listings under signal 0 (every way the
     grammar spells it), and `kill -l` / `-L` (signal listing), for builtin and /bin/kill.
  7. Over-reach, silent: an ordinary pid kill, an owner listing that reaches no kill.

Not pinned on the silent side: `ps ... | xargs kill -0`. The guard's separate ps-listing
rule (a kill of pids read off a ps listing) refuses it already, and the
sentence exempts signal 0 from THIS rule only; a refusal by another rule is not this
sentence's to judge.
"""
import json, os, pwd, subprocess, sys

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))
U = pwd.getpwuid(os.getuid()).pw_name   # the account running the suite


def verdict(cmd):
    """(fired, stderr) -- fired is True iff the hook exited non-zero."""
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True, timeout=60)
    return p.returncode != 0, p.stderr


MUST_BLOCK = [
    # --- anchor the sentence names ------------------------------------------------------
    ("anchor pkill -u $USER",            'pkill -u "$USER"'),
    # --- direction 1: PID -1 -----------------------------------------------------------
    ("kill -9 -1",                       "kill -9 -1"),
    ("kill -- -1",                       "kill -- -1"),
    ("kill -KILL -1",                    "kill -KILL -1"),
    ("kill -SIGKILL -1",                 "kill -SIGKILL -1"),
    ("kill -s KILL -1",                  "kill -s KILL -1"),
    ("kill -s 9 -- -1",                  "kill -s 9 -- -1"),
    ("kill -n 9 -1",                     "kill -n 9 -1"),
    ("kill -TERM -- -1",                 "kill -TERM -- -1"),
    ("kill -9 '-1' quoted",              "kill -9 '-1'"),
    ("kill -- \"-1\" quoted",            'kill -- "-1"'),
    ("kill -9 1234 -1 mixed",            "kill -9 1234 -1"),
    ("builtin kill -9 -1",               "builtin kill -9 -1"),
    ("command kill -9 -1",               "command kill -9 -1"),
    ("/bin/kill -9 -1",                  "/bin/kill -9 -1"),
    ("/bin/kill -- -1",                  "/bin/kill -- -1"),
    ("/bin/kill --signal KILL -1",       "/bin/kill --signal KILL -1"),
    ("/bin/kill -s TERM -- -1",          "/bin/kill -s TERM -- -1"),
    ("/usr/bin/kill -9 -- -1",           "/usr/bin/kill -9 -- -1"),
    ("env kill -9 -1",                   "env kill -9 -1"),
    # --- direction 2: PID 0 ------------------------------------------------------------
    ("kill 0",                           "kill 0"),
    ("kill -9 0",                        "kill -9 0"),
    ("kill -- 0",                        "kill -- 0"),
    ("kill -HUP 0",                      "kill -HUP 0"),
    ("kill -s TERM 0",                   "kill -s TERM 0"),
    ("kill -n 15 0",                     "kill -n 15 0"),
    ("kill '0' quoted",                  "kill '0'"),
    ("/bin/kill 0",                      "/bin/kill 0"),
    ("/bin/kill -9 0",                   "/bin/kill -9 0"),
    ("/bin/kill --signal TERM -- 0",     "/bin/kill --signal TERM -- 0"),
    # --- direction 3: a ps listing whose pids reach a kill ------------------------------
    ("ps -u $USER | xargs kill",         'ps -u "$USER" -o pid= | xargs kill'),
    ("ps -U user | xargs kill -9",       "ps -U %s -o pid= | xargs kill -9" % U),
    ("ps --user user | xargs kill",      "ps --user %s -o pid= | xargs kill" % U),
    ("ps x | xargs kill (BSD owner)",    "ps x -o pid= | xargs kill"),
    ("kill $(ps -u user)",               "kill $(ps -u %s -o pid=)" % U),
    ("kill -9 $(ps -U $USER)",           'kill -9 $(ps -U "$USER" -o pid=)'),
    ("ps -e | xargs kill",               "ps -e -o pid= | xargs kill"),
    ("ps -eo pid= | xargs kill",         "ps -eo pid= | xargs kill"),
    ("ps -A | xargs kill",               "ps -A -o pid= | xargs kill"),
    ("ps ax | xargs kill",               "ps ax -o pid= | xargs kill"),
    ("ps aux | awk | xargs kill",        "ps aux | awk '{print $2}' | xargs kill"),
    ("kill $(ps -e)",                    "kill $(ps -e -o pid=)"),
    ("ps (no selection) | xargs kill",   "ps -o pid= | xargs kill"),
    ("kill $(ps -o pid=) no selection",  "kill $(ps -o pid=)"),
    ("ps -u | while read; kill",         "ps -u %s -o pid= | while read p; do kill \"$p\"; done" % U),
    # --- direction 4: owner filter in every spelling ------------------------------------
    ("pkill -u user",                    "pkill -u %s" % U),
    ("pkill -U user",                    "pkill -U %s" % U),
    ("pkill -u$USER attached",           "pkill -u$USER"),
    ("pkill -9 -u user",                 "pkill -9 -u %s" % U),
    ("pkill -u uid",                     "pkill -u 1000"),
    ("pkill --euid user",                "pkill --euid %s" % U),
    ("pkill --euid=user",                "pkill --euid=%s" % U),
    ("pkill --uid user",                 "pkill --uid %s" % U),
    ("pkill --uid=user",                 "pkill --uid=%s" % U),
    ("pkill --eu user (abbrev)",         "pkill --eu %s" % U),
    ("pkill --eui=user (abbrev)",        "pkill --eui=%s" % U),
    ("pkill --ui user (abbrev)",         "pkill --ui %s" % U),
    ("pgrep -u | xargs kill",            "pgrep -u %s | xargs kill" % U),
    ("kill $(pgrep -U user)",            "kill $(pgrep -U %s)" % U),
    ("pgrep --euid | xargs kill",        "pgrep --euid %s | xargs kill" % U),
    ("kill $(pgrep --ui user) abbrev",   "kill $(pgrep --ui %s)" % U),
    ("pgrep --eu=user | xargs kill",     "pgrep --eu=%s | xargs kill -9" % U),
    # --- direction 5: -n / -o as the only criterion -------------------------------------
    ("pkill -n",                         "pkill -n"),
    ("pkill -o",                         "pkill -o"),
    ("pkill -9 -n",                      "pkill -9 -n"),
    ("pkill -SIGKILL -o",                "pkill -SIGKILL -o"),
    ("pkill --newest",                   "pkill --newest"),
    ("pkill --oldest",                   "pkill --oldest"),
    ("pkill --new (abbrev)",             "pkill --new"),
    ("pkill --oldes (abbrev)",           "pkill --oldes"),
    ("pgrep --oldes | xargs kill",       "pgrep --oldes | xargs kill"),
    ("kill $(pgrep -n)",                 "kill $(pgrep -n)"),
    ("pgrep -o | xargs kill",            "pgrep -o | xargs kill"),
    ("kill -9 $(pgrep --newest)",        "kill -9 $(pgrep --newest)"),
]

MUST_BE_SILENT = [
    # --- direction 6: signal 0 and signal listing are never refused by this rule ---------
    ("kill -0 -1",                       "kill -0 -1"),
    ("kill -0 -- -1",                    "kill -0 -- -1"),
    ("kill -s 0 -- -1",                  "kill -s 0 -- -1"),
    ("kill -n 0 -1",                     "kill -n 0 -1"),
    ("kill -0 0",                        "kill -0 0"),
    ("kill -s 0 0",                      "kill -s 0 0"),
    ("/bin/kill -0 -1",                  "/bin/kill -0 -1"),
    ("/bin/kill -s 0 -- -1",             "/bin/kill -s 0 -- -1"),
    ("/bin/kill --signal 0 -1",          "/bin/kill --signal 0 -1"),
    ("/bin/kill -0 0",                   "/bin/kill -0 0"),
    ("kill -0 $(ps -u user)",            "kill -0 $(ps -u %s -o pid=)" % U),
    ("pgrep -u | xargs kill -0",         "pgrep -u %s | xargs kill -0" % U),
    ("pgrep -n | xargs kill -0",         "pgrep -n | xargs kill -0"),
    ("kill -l",                          "kill -l"),
    ("kill -l 9",                        "kill -l 9"),
    ("kill -L",                          "kill -L"),
    ("/bin/kill -l",                     "/bin/kill -l"),
    ("/bin/kill -L",                     "/bin/kill -L"),
    # --- direction 7: over-reach -------------------------------------------------------
    ("kill a plain pid",                 "kill 12345"),
    ("kill -9 a captured pid",           'SRV=$!; kill -9 "$SRV"'),
    ("kill -- a pid 10",                 "kill -- 10"),
    ("owner listing, no kill",           "pgrep -u %s" % U),
    ("ps by owner, no kill",             "ps -u %s -o pid=,comm=" % U),
    ("newest pid listed, no kill",       "pgrep -n"),
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
    print("OK: %d block + %d silent cases of a whole-account kill" % (len(MUST_BLOCK),
                                                                     len(MUST_BE_SILENT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
