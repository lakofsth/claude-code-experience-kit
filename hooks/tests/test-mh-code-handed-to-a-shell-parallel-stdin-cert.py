"""Check of the GNU parallel stdin clause of `mh-code-handed-to-a-shell-is-code` (amended 2026-10-28).

The sentence (hooks/tests/INVARIANTS.md):

    With a command and no :::/:::: source and no -a FILE (or with one of them -), what parallel
    reads on stdin is put where its command template holds a replacement string, appended when it
    holds none, and given to each job's stdin under --pipe; hooks/bash_parse.py parallel_stdin()
    reads that and hooks/block-unsafe-kill.sh parallel_feeds() writes a lister there, so a pgrep
    listing piped into a parallel template that kills its replacement string is refused as a
    pattern-keyed kill. Read wide: any blank-free {...} in the template is a replacement string.
    Stated as not read: options from a --profile/-J file, ~/.parallel/config or $PARALLEL.

Written from the hooks/tests/INVARIANTS.md clause alone. Its directions:

  P  PLACED     -- the template holds `{}` and kills it, in every spelling of the template: one
                   quoted string, several words, double quotes, the replacement string quoted
                   inside the string, the kill after another command, behind parallel's options.
  W  READ WIDE  -- any blank-free {...} is a replacement string: {.} {/} {//} {1} {=perl=}.
  A  APPENDED   -- a template that holds no replacement string gets the line appended, so a
                   template that is a bare kill (with or without a signal) kills the listing --
                   and so does `kill 1234`, which kills 1234 AND the appended listing.
  S  STDIN AS SOURCE -- `-a -`, `--arg-file -`, `--arg-file=-` and `:::: -` read stdin too.
  J  --pipe     -- each job's stdin is the listing, so a job that reads its stdin into a kill
                   (`xargs kill`, `cat | xargs kill`) kills it.
  R  ROUTES     -- the listing reaches parallel's stdin by more than a bare pipe: through a
                   filter, from a variable echoed in, behind a wrapper (`nice`), and inside a
                   handed `sh -c` string (the same rules inside handed code). `sem` is not
                   asked: it runs its command once and reads no arguments on stdin.
  N  NOT FED    -- neighbours where stdin does not reach the kill must stay silent: a template
                   that only echoes, a `:::` source given, an `-a FILE` source given.

Every must-refuse case must also be refused AS a pattern-keyed kill: its message names `pgrep
-f` or a pattern. The variants the sentence states as not read (--profile, ~/.parallel/config,
$PARALLEL) are not asked. Nothing here runs a kill; the hook only reads.
"""
import json, os, subprocess, sys

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))
L = "pgrep -f mhparcert-no-such-pattern"

MUST_REFUSE = [
    # P  PLACED
    ("P quoted template",               "%s | parallel 'kill {}'" % L),
    ("P double-quoted, signal",         "%s | parallel \"kill -9 {}\"" % L),
    ("P {} quoted inside the string",   "%s | parallel 'kill -9 \"{}\"'" % L),
    ("P words, unquoted",               "%s | parallel kill {}" % L),
    ("P words, -j4",                    "%s | parallel -j4 kill {}" % L),
    ("P quoted, --jobs 2 -k",           "%s | parallel --jobs 2 -k 'kill -TERM {}'" % L),
    ("P after another command",         "%s | parallel 'echo {}; kill {}'" % L),
    ("P in a substitution kill expands", "%s | parallel 'kill $(echo {})'" % L),
    ("P quoted, trailing ||",           "%s | parallel 'kill {} || true'" % L),
    # W  READ WIDE
    ("W {.}",                           "%s | parallel 'kill {.}'" % L),
    ("W {/}",                           "%s | parallel 'kill {/}'" % L),
    ("W {//}",                          "%s | parallel 'kill -9 {//}'" % L),
    ("W {1}",                           "%s | parallel 'kill {1}'" % L),
    ("W {=perl=}",                      "%s | parallel 'kill {=s/x//=}'" % L),
    # A  APPENDED
    ("A bare kill, words",              "%s | parallel kill" % L),
    ("A kill -9, words",                "%s | parallel kill -9" % L),
    ("A quoted 'kill'",                 "%s | parallel 'kill'" % L),
    ("A quoted 'kill -9'",              "%s | parallel 'kill -9'" % L),
    ("A quoted, -j2",                   "%s | parallel -j2 'kill -TERM'" % L),
    ("A literal pid, listing appended", "%s | parallel 'kill 1234'" % L),
    # S  STDIN AS SOURCE
    ("S -a - quoted",                   "%s | parallel -a - 'kill {}'" % L),
    ("S --arg-file - words",            "%s | parallel --arg-file - kill {}" % L),
    ("S --arg-file=- quoted",           "%s | parallel --arg-file=- 'kill {}'" % L),
    ("S :::: - quoted",                 "%s | parallel 'kill {}' :::: -" % L),
    ("S :::: - words",                  "%s | parallel kill {} :::: -" % L),
    # J  --pipe
    ("J --pipe 'xargs kill'",           "%s | parallel --pipe 'xargs kill'" % L),
    ("J --pipe xargs -r kill -9",       "%s | parallel --pipe xargs -r kill -9" % L),
    ("J --pipe 'cat | xargs kill'",     "%s | parallel --pipe 'cat | xargs kill'" % L),
    # R  ROUTES
    ("R through head",                  "%s | head -n 3 | parallel 'kill {}'" % L),
    ("R variable echoed in",            "P=$(%s); echo \"$P\" | parallel 'kill {}'" % L),
    ("R behind nice",                   "%s | nice parallel 'kill {}'" % L),
    ("R inside sh -c",                  "sh -c \"%s | parallel 'kill {}'\"" % L),
]

MUST_STAY_SILENT = [
    ("N template only echoes",          "%s | parallel 'echo {}'" % L),
    ("N template only echoes, words",   "%s | parallel echo {}" % L),
    ("N ::: source given",              "%s | parallel 'kill {}' ::: 1234" % L),
    ("N -a FILE source given",          "%s | parallel -a pids.txt 'kill {}'" % L),
]


def verdict(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


def pattern_keyed(err):
    return "pgrep -f" in err or "pattern" in err


bad, n = [], 0
for label, cmd in MUST_REFUSE:
    n += 1
    fired, err = verdict(cmd)
    if not fired:
        bad.append("NOT REFUSED   %-34s %s" % (label, cmd))
    elif not pattern_keyed(err):
        bad.append("NOT AS PATTERN %-33s %s :: %s" % (label, cmd, err.strip()[:120]))
    else:
        print("ok refused     %-34s %s" % (label, cmd))
for label, cmd in MUST_STAY_SILENT:
    n += 1
    fired, err = verdict(cmd)
    if fired:
        bad.append("REFUSED       %-34s %s :: %s" % (label, cmd, err.strip()[:120]))
    else:
        print("ok silent      %-34s %s" % (label, cmd))

for b in bad:
    print(b)
print("%d of %d cases red" % (len(bad), n))
sys.exit(1 if bad else 0)
