"""Check: a lister in a substitution is followed by its structure.

The sentence (hooks/tests/INVARIANTS.md, mh-a-lister-in-a-substitution-is-followed-by-its-structure):

    hooks/block-unsafe-kill.sh finds the substitution a pgrep or pidof sits in, and the command
    that substitution is a word of, from the shared scanner's substitution spans
    (hooks/quote_mask.py, substitutions()) -- so a newline or space after the opening, another
    command before the lister inside the substitution, another substitution earlier in the same
    command, an array literal v=( ... ) and a herestring into read each carry the lister's pids
    to the kill exactly as the one-line kill $(pgrep ...) does -- and a lister whose
    substitution sits in no command it can read is counted, never passed in silence.

Written from the hooks/tests/INVARIANTS.md clause alone. Its directions, each
run for the three listers pgrep -f (a pattern: refused by structure), pgrep -x and pidof (a NAME
held by two live processes of this test's own: refused by count):

  0. BASELINE   -- the one-line `kill $(LISTER)` is refused; every case below is held to it.
  1. OPENING    -- a newline, a space, a tab or a newline plus indent after `$(` or a backtick,
                   and a newline before the close, carry the pids to the kill.
  2. BEFORE     -- another command before the lister inside the substitution (`;`, `&&`, a
                   newline, a pipeline, a redirection) carries the pids.
  3. EARLIER    -- another substitution earlier in the same command ($(...), backticks, inside
                   "...", nested) does not lose the lister's substitution or its host.
  4. ARRAY      -- an array literal v=( ... ), v+=( ... ), with other elements, spaces and
                   newlines, through declare/local, binds v, and a kill expanding v is reached.
  5. HERESTRING -- `<<< "$(LISTER)"` into read binds what the read takes, and a kill expanding
                   it is reached (loop and plain read, quoted and bare, with spaces).
  6. NO HOST    -- a lister whose substitution sits in no command the hook can read (the
                   substitution IS the command word, or its host is nothing but redirections),
                   in a command that holds a kill, is counted -- refused, never silent.
  7. EXACTLY AS -- the same structures where the kill does NOT expand what the lister bound stay
                   silent, as `P=$(pgrep ...); kill $SRV` does: "exactly as" is both verdicts.

Fixture: two copies of a uniquely named program of this test's own, stopped by PID afterwards.
Nothing here runs a kill; the hook only reads.
"""
import json, os, shutil, signal, subprocess, sys, tempfile, time
from _proc_names import proc_name, sleeper  # noqa: E402  (per-run comm names: host-wide pgrep must see only this run)

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

A = proc_name("mhstr")     # comm is truncated to 15 characters; per-run, unique to this test
PAT = "mhsubstcrt-no-such-pattern"
LISTERS = [("pgrep -f", "pgrep -f " + PAT), ("pgrep -x", "pgrep -x " + A), ("pidof", "pidof " + A)]


def verdict(cmd):
    """(fired, stderr) -- fired is True iff the hook exited non-zero."""
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


def count(name):
    r = subprocess.run(["pgrep", "-x", name], capture_output=True, text=True)
    return len([x for x in r.stdout.split() if x.isdigit()])


# Each template has one {L}, replaced by every lister in turn.
MUST_REFUSE = [
    ("0 baseline: kill $(L)",                      "kill $({L})"),
    # 1. OPENING
    ("1 newline after $(",                         "kill $(\n{L}\n)"),
    ("1 space after $(",                           "kill $( {L} )"),
    ("1 tab after $(",                             "kill $(\t{L})"),
    ("1 newline + indent after $(",                "kill -9 $(\n    {L}\n)"),
    ("1 newline after $( inside \"...\"",          "kill \"$(\n{L})\""),
    ("1 space after a backtick",                   "kill ` {L}`"),
    ("1 newline after a backtick",                 "kill `\n{L}\n`"),
    ("1 newline after $( in a for",                "for p in $(\n{L}\n); do kill $p; done"),
    ("1 newline after $( in an assignment",        "P=$(\n  {L}\n)\nkill $P"),
    # 2. BEFORE
    ("2 ; before the lister",                      "kill $(sleep 0; {L})"),
    ("2 && before the lister",                     "kill $(true && {L})"),
    ("2 newline-separated command before",         "kill $(cd /\n{L})"),
    ("2 a pipeline before, ; then lister",         "kill $(echo x | cat >/dev/null; {L})"),
    ("2 a redirection before",                     "kill $(exec 2>/dev/null; {L})"),
    ("2 ; before, in an assignment",               "P=$(sleep 0; {L}); kill $P"),
    ("2 ; before, in a for",                       "for p in $(true; {L}); do kill \"$p\"; done"),
    ("2 ; before, in backticks",                   "kill `sleep 0; {L}`"),
    # 3. EARLIER
    ("3 $(cat f) earlier",                         "kill $(cat f) $({L})"),
    ("3 \"$(cat f)\" earlier",                     "kill \"$(cat f)\" $({L})"),
    ("3 backtick earlier",                         "kill `cat f` $({L})"),
    ("3 signal from a substitution",               "kill -$(echo 9) $({L})"),
    ("3 nested substitution earlier",              "kill $(echo $(cat f)) $({L})"),
    ("3 earlier, both in one \"...\"",             "kill \"$(cat f) $({L})\""),
    ("3 earlier, in an assignment",                "P=\"$(date) $({L})\"; kill $P"),
    ("3 earlier with a space, in an assignment",   "P=\"$(cat f) $({L})\"; kill $P"),
    ("3 earlier, adjacent, in an assignment",      "P=$(cat f)$({L}); kill $P"),
    ("3 earlier backtick, in an assignment",       "P=\"`cat f` $({L})\"; kill $P"),
    ("3 earlier, in an array element",             "pids=(\"$(cat f) $({L})\"); kill ${pids[@]}"),
    ("3 earlier, in a herestring to read",         "read p <<< \"$(cat f) $({L})\"; kill $p"),
    ("3 earlier, adjacent, bare herestring",       "read p <<< $(cat f)$({L}); kill $p"),
    ("3 earlier, herestring into a while read",    "while read p; do kill $p; done <<< \"$(cat f) $({L})\""),
    ("3 earlier, herestring into read -a",         "read -a p <<< \"$(cat f) $({L})\"; kill ${p[@]}"),
    ("3 earlier, in a for list",                   "for p in $(cat f) $({L}); do kill $p; done"),
    ("3 earlier, in the same simple command",      "echo $(date) >/dev/null; kill $(cat f) `{L}`"),
    # 4. ARRAY
    ("4 v=($(L)); kill ${v[@]}",                   "pids=($({L})); kill ${pids[@]}"),
    ("4 v=( $(L) ); kill \"${v[@]}\"",             "pids=( $({L}) ); kill \"${pids[@]}\""),
    ("4 v+=($(L)); kill ${v[*]}",                  "pids=(); pids+=($({L})); kill ${pids[*]}"),
    ("4 another element first",                    "pids=(1 $({L})); kill ${pids[@]}"),
    ("4 an earlier substitution element",          "pids=($(cat f) $({L})); kill ${pids[@]}"),
    ("4 newline inside the literal",               "pids=(\n  $({L})\n)\nkill ${pids[@]}"),
    ("4 declare -a v=(...)",                       "declare -a pids=($({L})); kill ${pids[@]}"),
    ("4 local v=(...) in a function",              "f() { local pids=($({L})); kill ${pids[@]}; }; f"),
    ("4 kill ${v[0]}",                             "pids=($({L})); kill ${pids[0]}"),
    ("4 array then for over it",                   "pids=($({L})); for p in \"${pids[@]}\"; do kill $p; done"),
    # 5. HERESTRING
    ("5 while read; done <<< \"$(L)\"",            "while read p; do kill $p; done <<< \"$({L})\""),
    ("5 read p <<< \"$(L)\"; kill $p",             "read p <<< \"$({L})\"; kill $p"),
    ("5 read -a <<< $(L) bare",                    "read -a pids <<< $({L}); kill ${pids[@]}"),
    ("5 read -r <<<\"$( L )\" no space",           "read -r p <<<\"$( {L} )\"; kill \"$p\""),
    ("5 herestring with newline after $(",         "while read -r p; do kill -9 \"$p\"; done <<< \"$(\n{L}\n)\""),
    ("5 herestring with ; before the lister",      "read p <<< \"$(sleep 0; {L})\"; kill $p"),
    # 6. NO HOST -- counted, never silent
    ("6 the substitution is the command word",     "$({L}); kill $SRV"),
    ("6 command-word substitution after kill",     "kill \"$SRV\"; $({L})"),
    ("6 host is only a redirection",               "kill $SRV; >$({L})"),
    ("6 backtick as the command word",             "kill $SRV && `{L}`"),
]

# 7. EXACTLY AS -- the one-line `P=$(L); kill $SRV` is silent, and so are these.
MUST_BE_SILENT = [
    ("7 baseline: P=$(L); kill $SRV",              "P=$({L}); kill \"$SRV\""),
    ("7 newline after $(, kill $SRV",              "P=$(\n{L}\n); kill \"$SRV\""),
    ("7 ; before lister, echoed; kill $SRV",       "echo $(sleep 0; {L}); kill \"$SRV\""),
    ("7 earlier substitution, echoed; kill $SRV",  "echo $(cat f) $({L}); kill \"$SRV\""),
    ("7 array not expanded by the kill",           "pids=($({L})); echo ${#pids[@]}; kill \"$SRV\""),
    ("7 array literal, kill an other array",       "pids=($({L})); mine=($SRV); kill ${mine[@]}"),
]


def main():
    d = tempfile.mkdtemp(prefix="mh-subst-struct-")
    exe = os.path.join(d, A)
    shutil.copy2("/bin/sleep", exe)
    procs = [sleeper(exe) for _ in range(2)]
    failures, total = [], 0
    try:
        for _ in range(50):
            if count(A) >= 2:
                break
            time.sleep(0.05)
        if count(A) != 2:
            print("SETUP FAILED: want 2 x %s, have %d" % (A, count(A)))
            return 2
        for lname, lister in LISTERS:
            for label, tmpl in MUST_REFUSE:
                cmd = tmpl.replace("{L}", lister)
                total += 1
                fired, err = verdict(cmd)
                if not fired:
                    failures.append("NOT REFUSED [%s | %s]: %r" % (label, lname, cmd))
                elif "BLOCKED:" not in err:
                    failures.append("REFUSED, said nothing useful [%s | %s]: %r"
                                    % (label, lname, err[:160]))
            for label, tmpl in MUST_BE_SILENT:
                cmd = tmpl.replace("{L}", lister)
                total += 1
                fired, err = verdict(cmd)
                if fired:
                    failures.append("FALSE REFUSAL [%s | %s]: %r\n      said: %s"
                                    % (label, lname, cmd, err.splitlines()[0] if err else ""))
    finally:
        for p in procs:             # by PID
            try:
                p.send_signal(signal.SIGTERM)
                p.wait(timeout=5)
            except Exception:
                pass
        shutil.rmtree(d, ignore_errors=True)

    if failures:
        print("FAIL (%d of %d cases)" % (len(failures), total))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d cases (%d must-refuse + %d must-stay-silent, x %d listers)"
          % (total, len(MUST_REFUSE), len(MUST_BE_SILENT), len(LISTERS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
