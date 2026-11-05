"""Check (amended 2026-10-27): a lister in a substitution is followed by its structure --
herestring host, process substitution, arithmetic, exactly when.

The sentence (hooks/tests/INVARIANTS.md, mh-a-lister-in-a-substitution-is-followed-by-its-structure):

    hooks/block-unsafe-kill.sh finds the substitution a pgrep or pidof sits in, and the command
    that substitution is a word of, from the shared scanner's substitution spans
    (hooks/quote_mask.py, substitutions()) -- so a newline or space after the opening, another
    command before the lister inside the substitution, another substitution earlier in the same
    command, an array literal v=( ... ) wherever in it the substitution sits, a herestring or
    process substitution read by its host (a kill, a read, or a command passing it on), and an
    arithmetic $((...)) or ((...)) each carry the lister's pids to the kill exactly as the
    one-line form (a kill whose operand is the lister's command substitution) does -- and the
    pids are refused exactly when they reach a kill: a read of another variable beside it, or
    an arithmetic count that is only a status or a value no kill expands, refuses nothing; and a
    lister whose substitution sits in no command it can read is counted, never passed in silence.

Written from the hooks/tests/INVARIANTS.md clause alone. The directions the
amendment added are the weight of this check; the earlier ones (opening, before, earlier) are
kept as a baseline row each, since test-lister-substitution-structure-cert.py pins them in full.
Each case is run for the three listers pgrep -f (a pattern: refused by structure), pgrep -x and
pidof (a NAME held by two live processes of this test's own: refused by count).

  0. BASELINE   -- `kill $(L)` refused; one row each for opening / before / earlier.
  A. ARRAY      -- the lister's substitution anywhere in v=( ... ): first, middle, last, after
                   a newline, as an indexed element [i]=..., quoted, beside other substitutions.
  H. HERESTRING -- `<<< "$(L)"` read by its host: a kill (`xargs kill <<<`), a read, or a
                   command passing it on (`cat <<<` inside the kill's substitution or pipeline).
  P. PROCSUB    -- `<(L)` read by its host: a kill (`xargs kill < <(L)`), a read/mapfile whose
                   variable the kill expands, or a command passing it on into the kill.
  R. ARITH      -- a lister inside $(( ... )) or (( ... )) whose value the kill expands.
  N. NO HOST    -- a substitution in no command the hook can read: counted, never silent.
  X. EXACTLY WHEN (must stay silent) -- a read of ANOTHER variable beside the lister's read,
                   an arithmetic status or a count no kill expands, a herestring / process
                   substitution whose host passes the pids nowhere near a kill.

Fixture: two copies of a uniquely named program of this test's own, stopped by PID afterwards.
Nothing here runs a kill; the hook only reads.
"""
import json, os, shutil, signal, subprocess, sys, tempfile, time
from _proc_names import proc_name, sleeper  # noqa: E402  (per-run comm names: host-wide pgrep must see only this run)

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

A = proc_name("mhhst")     # comm is truncated to 15 characters; per-run, unique to this test
PAT = "mhhostcert-no-such-pattern"
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
    ("0 newline after $(",                         "kill $(\n{L}\n)"),
    ("0 a command before the lister",              "kill $(sleep 0; {L})"),
    ("0 an earlier substitution",                  "kill $(cat f) $({L})"),
    # A. ARRAY -- wherever in the literal the substitution sits
    ("A first element",                            "pids=($({L}) 1 2); kill ${pids[@]}"),
    ("A middle element",                           "pids=(1 $({L}) 2); kill ${pids[@]}"),
    ("A last of several",                          "pids=(a b c $({L})); kill ${pids[@]}"),
    ("A after a newline in the literal",           "pids=(1\n  $({L})\n  2\n); kill ${pids[@]}"),
    ("A quoted element in the middle",             "pids=(1 \"$({L})\" 2); kill \"${pids[@]}\""),
    ("A indexed element [1]=$(L)",                 "pids=([0]=1 [1]=$({L})); kill ${pids[1]}"),
    ("A after another substitution element",       "pids=($(cat f) 1 $({L}) 2); kill ${pids[@]}"),
    ("A += with others before",                    "pids=(1); pids+=(2 3 $({L})); kill ${pids[@]}"),
    ("A local, middle element",                    "f() { local pids=(1 $({L}) 2); kill ${pids[@]}; }; f"),
    ("A backtick element in the middle",           "pids=(1 `{L}` 2); kill ${pids[@]}"),
    # H. HERESTRING -- read by its host
    ("H host a kill: xargs kill <<<",              "xargs kill <<< \"$({L})\""),
    ("H host a kill: xargs -r kill -9 <<<",        "xargs -r kill -9 <<< \"$({L})\""),
    ("H host a read",                              "read -a p <<< \"$({L})\"; kill ${p[@]}"),
    ("H host passes it on, in kill's subst",       "kill $(cat <<< \"$({L})\")"),
    ("H host passes it on, tr in kill's subst",    "kill $(tr ' ' '\\n' <<< \"$({L})\")"),
    ("H host passes it on, into kill's pipe",      "cat <<< \"$({L})\" | xargs kill"),
    ("H host passes it on, assigned",              "P=$(cat <<< \"$({L})\"); kill $P"),
    ("H host passes it on, into a for",            "for p in $(cat <<< \"$({L})\"); do kill $p; done"),
    # P. PROCESS SUBSTITUTION -- read by its host
    ("P host a kill: xargs kill < <(L)",           "xargs kill < <({L})"),
    ("P host a kill: xargs kill <(L) file arg",    "xargs -a <({L}) kill"),
    ("P host a read",                              "read -r p < <({L}); kill \"$p\""),
    ("P host a while read",                        "while read p; do kill $p; done < <({L})"),
    ("P host mapfile",                             "mapfile -t p < <({L}); kill ${p[@]}"),
    ("P host passes it on, in kill's subst",       "kill $(cat <({L}))"),
    ("P host passes it on, into kill's pipe",      "cat <({L}) | xargs kill"),
    ("P host passes it on, assigned",              "P=$(cat <({L})); kill $P"),
    ("P host passes it on, sort | into kill",      "sort -u <({L}) | xargs kill"),
    # R. ARITHMETIC -- carried to the kill
    ("R kill $(( $(L) ))",                         "kill $(( $({L}) ))"),
    ("R kill $(( $(L) + 0 ))",                     "kill $(( $({L}) + 0 ))"),
    ("R p=$(( $(L) )); kill $p",                   "p=$(( $({L}) )); kill $p"),
    ("R (( p = $(L) )); kill $p",                  "(( p = $({L}) )); kill $p"),
    ("R ((p=$(L))); kill \"$p\"",                  "((p=$({L}))); kill \"$p\""),
    # N. NO HOST -- counted, never silent
    ("N the substitution is the command word",     "$({L}); kill $SRV"),
    ("N host is only a redirection",               "kill $SRV; >$({L})"),
]

# X. EXACTLY WHEN -- the pids reach no kill, so nothing is refused.
MUST_BE_SILENT = [
    ("X baseline: P=$(L); kill $SRV",              "P=$({L}); kill \"$SRV\""),
    # a read of another variable beside it
    ("X herestring read q; read p from a file",    "read q <<< \"$({L})\"; read p < pidfile; kill $p"),
    ("X procsub read q; read p from a file",       "read q < <({L}); read p < pidfile; kill \"$p\""),
    ("X mapfile q; read -r p from a file",         "mapfile -t q < <({L}); read -r p < pidfile; kill $p"),
    ("X herestring read q; kill $SRV",             "read q <<< \"$({L})\"; kill \"$SRV\""),
    ("X read q from L; while read p < f",          "read -a q <<< \"$({L})\"; while read p; do kill $p; done < pidfile"),
    # an arithmetic count that is only a status, or a value no kill expands
    ("X (( count > 0 )) status && kill $SRV",      "(( $({L} | wc -l) > 0 )) && kill \"$SRV\""),
    ("X if (( count )); then kill $SRV",           "if (( $({L} | wc -l) )); then kill \"$SRV\"; fi"),
    ("X n=$(( count )); kill $SRV",                "n=$(( $({L} | wc -l) )); kill \"$SRV\""),
    ("X (( n = count )); echo $n; kill $SRV",      "(( n = $({L} | wc -l) )); echo $n; kill \"$SRV\""),
    ("X [ $(( count )) -gt 1 ] && kill $SRV",      "[ $(( $({L} | wc -l) )) -gt 1 ] && kill \"$SRV\""),
    # a herestring / process substitution whose host takes the pids nowhere near a kill
    ("X wc -l <<< L; kill $SRV",                   "wc -l <<< \"$({L})\"; kill \"$SRV\""),
    ("X cat <(L) > file; kill $SRV",               "cat <({L}) > /dev/null; kill \"$SRV\""),
    ("X diff <(L) f; kill $SRV",                   "diff <({L}) before.txt; kill \"$SRV\""),
    # an array the kill does not expand
    ("X array middle element, kill another",       "pids=(1 $({L}) 2); kill \"$SRV\""),
]


def main():
    d = tempfile.mkdtemp(prefix="mh-subst-host-")
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
