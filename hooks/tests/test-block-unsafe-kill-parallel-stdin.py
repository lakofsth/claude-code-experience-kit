"""A lister's pids fed to GNU parallel on stdin reach the kill in its command template
(mh-code-handed-to-a-shell-is-code, mh-a-lister-reaches-a-kill-through-every-binding-site;
amended 2026-10-28).

Reading only GNU parallel's `:::` operands and moreutils' `--` form misses a QUOTED command
template fed on stdin -- `pgrep -f X | parallel 'kill {}'`: the template analysed as code on its
own is `kill {}`, a kill of no lister. GNU parallel (parallel(1), "INPUT
SOURCES" and "REPLACEMENT STRINGS") reads its arguments from stdin when it is given no `:::` /
`::::` source and no `-a FILE` (or when one of them is `-`), puts each argument where the template
holds a replacement string -- `{}`, `{.}`, `{/}`, `{//}`, `{/.}`, `{n}` and their positional forms,
`{= perl =}`, the strings `-I`, `-i`, `--replace`, `--er`, `--bnr`, `--dnr`, `--bner` and `--rpl`
define -- and APPENDS it when the template holds none; with `--pipe` the input goes to each job's
stdin instead. Debian's default `parallel` is moreutils' (no stdin grammar), so these rows are
GNU's semantics BY ITS DOCUMENTATION, not run: there is no bash oracle for them, unlike the
binding-site check this file sits beside.

Each template runs for `pgrep -f` (refused by structure) and for `pgrep -x` and `pidof` of a name
two live processes answer to (refused by count). REACH rows must be refused; every SILENT row is
the same template made harmless -- a non-kill template, a kill of the pid this command started
(from `$!`), parallel's arguments taken from a file or `:::` rather than from the lister's stdin.
Run serially: the live-count rows read the process table.
"""
import json, os, shutil, signal, subprocess, sys, tempfile, time
from _proc_names import proc_name, sleeper  # noqa: E402  (per-run comm names: host-wide pgrep must see only this run)

HOOK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "block-unsafe-kill.sh")
PROC_NAME = proc_name("mhpar")    # comm is 15 characters at most; pgrep -x matches comm

LISTER_FORMS = [("pgrep -f", "pgrep -f mh-no-such-pattern"), ("pgrep -x", "pgrep -x " + PROC_NAME),
                ("pidof", "pidof " + PROC_NAME)]

# (label, template). {L} is the lister. A template whose kill is LAST would be refused even if its
# replacement string were missed, because the lister is then appended after the kill; so every
# row for a replacement-string spelling (and --pipe) ends `; echo done`, where an append misses.
REACH = [
    ("{} in a quoted template",                 "{L} | parallel 'kill {}'"),
    ("{} after a signal",                       "{L} | parallel -j4 'kill -TERM {}'"),
    ("{} double-quoted template",               "{L} | parallel \"kill -9 {}\""),
    ("{1} positional",                          "{L} | parallel 'kill {1}; echo done'"),
    ("{.} no extension",                        "{L} | parallel 'kill {.}; echo done'"),
    ("{/} basename",                            "{L} | parallel 'kill {/}; echo done'"),
    ("{/.} basename, no extension",             "{L} | parallel 'kill {/.}; echo done'"),
    ("{1/.} positional basename",               "{L} | parallel 'kill {1/.}; echo done'"),
    ("{= perl =} dynamic replacement",          "{L} | parallel 'kill {= s/x// =}; echo done'"),
    ("-I STR",                                  "{L} | parallel -I PID 'kill PID; echo done'"),
    ("-ISTR glued",                             "{L} | parallel -IPID 'kill PID; echo done'"),
    ("--replace=STR",                           "{L} | parallel --replace=PID 'kill PID; echo done'"),
    ("--replace alone means {}",                "{L} | parallel --replace 'kill {}'"),
    ("-i alone means {}",                       "{L} | parallel -i 'kill {}'"),
    ("--er STR",                                "{L} | parallel --er PID 'kill PID; echo done'"),
    ("--extensionreplace STR",                  "{L} | parallel --extensionreplace PID 'kill PID; echo done'"),
    ("--bnr STR",                               "{L} | parallel --bnr PID 'kill PID; echo done'"),
    ("--basenameextensionreplace STR",          "{L} | parallel --basenameextensionreplace PID 'kill PID; echo done'"),
    ("--rpl TAG",                               "{L} | parallel --rpl '{p} s/x//' 'kill {p}; echo done'"),
    ("no replacement string: appended",         "{L} | parallel 'kill -9'"),
    ("-I STR absent from the template: appended", "{L} | parallel -I PID 'kill -TERM'"),
    ("{} inside the template's own '...'",      "{L} | parallel \"kill '{}'\""),
    ("the kill after another command",          "{L} | parallel 'echo stopping {}; kill {}'"),
    ("the kill in sh -c inside the template",   "{L} | parallel 'sh -c \"kill {}\"'"),
    ("-n1 and -X",                              "{L} | parallel -n1 -X 'kill {}'"),
    ("-a - names stdin",                        "{L} | parallel -a - 'kill {}'"),
    (":::: - names stdin",                      "{L} | parallel 'kill {}' :::: -"),
    ("::: then :::: -",                         "{L} | parallel 'kill -{1} {2}' ::: TERM :::: -"),
    ("--pipe: the jobs' stdin",                 "{L} | parallel --pipe 'xargs kill; echo done'"),
    ("behind nice",                             "{L} | nice parallel -j2 'kill {}'"),
    ("by path",                                 "{L} | /usr/bin/parallel 'kill {}'"),
    ("a herestring",                            "parallel 'kill {}' <<< \"$({L})\""),
    ("an input process substitution",           "parallel -j2 'kill {}' < <({L})"),
    ("a bound name echoed in",                  "P=$({L}); echo \"$P\" | parallel 'kill {}'"),
    ("a bound name in a herestring",            "P=$({L}); parallel 'kill {}' <<< \"$P\""),
    # The three rows above were refused at 37a87fc only because resolve() joins the redirection
    # into the GNU code string, where it becomes the LAST command's input; these are not.
    ("a herestring, the kill not last",         "parallel 'kill {}; echo done' <<< \"$({L})\""),
    ("a process substitution, the kill not last", "parallel 'kill {}; echo done' < <({L})"),
    ("a bound name in a herestring, kill not last", "P=$({L}); parallel 'kill {}; echo done' <<< \"$P\""),
    # xargs -I's replace string as the SECOND use in sh -c code: the first planted lister reaches
    # only the echo, so every planted place is asked (synthetic_feeds()).
    ("xargs -I{} sh -c, echo then kill",        "{L} | xargs -I{} sh -c 'echo {}; kill {}'"),
    ("xargs -I {} sh -c, echo then kill",       "{L} | xargs -I {} sh -c 'echo {}; kill {}'"),
    ("xargs -I STR sh -c, echo then kill",      "{L} | xargs -I PID sh -c 'echo PID; kill PID'"),
    ("xargs -ISTR glued sh -c, echo then kill", "{L} | xargs -IPID sh -c 'echo PID; kill PID'"),
    ("xargs -i sh -c, echo then kill",          "{L} | xargs -i sh -c 'echo {}; kill {}'"),
]

SILENT = [
    ("a template that only echoes",             "{L} | parallel 'echo {}'; kill \"$SRV\""),
    ("-I STR, a template that only echoes",     "{L} | parallel -I PID 'echo PID'; kill \"$SRV\""),
    ("appended to an echo",                     "{L} | parallel 'echo pid'; kill \"$SRV\""),
    ("a template that kills only $SRV",         "{L} | parallel 'echo {}; kill '\"$SRV\""),
    ("a template's kill of $SRV, {} to a file", "{L} | parallel 'echo {} >> seen.txt; kill \"$SRV\"'"),
    ("the pids from a pidfile you wrote",       "echo \"$SRV\" > srv.pid; {L} | wc -l; parallel 'kill {}' < srv.pid"),
    ("-a FILE: stdin is not read",              "echo \"$SRV\" > srv.pid; {L} | parallel -a srv.pid 'kill {}'"),
    ("::: source: stdin is not read",           "{L} | parallel 'kill {}' ::: \"$SRV\""),
    ("--pipe into a count",                     "{L} | parallel --pipe wc -l; kill \"$SRV\""),
    ("a herestring into an echo",               "parallel 'echo {}' <<< \"$({L})\"; kill \"$SRV\""),
    # bash, not sh: a kill in sh code beside a lister is refused whatever it
    # kills (mh-a-kill-the-runtime-guard-cannot-see-is-refused); in bash it is the neighbour it was.
    ("xargs -I{} bash -c: echo, kill of $SRV", "{L} | xargs -I{} bash -c 'echo {}; kill '\"$SRV\""),
    ("xargs -I STR sh -c: only echoes",         "{L} | xargs -I PID sh -c 'echo PID; echo PID'; kill \"$SRV\""),
    ("xargs -i sh -c: only echoes",             "{L} | xargs -i sh -c 'echo {}; echo {}'; kill \"$SRV\""),
    ("parallel spelled as data",                "echo \"{L} | parallel 'kill {}'\"; kill \"$SRV\""),
]
PRELUDE = "sleep 0.2 & SRV=$!; "     # every row: a pid this command started, read from $!


def verdict(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


def start_shared_name(n=2):
    d = tempfile.mkdtemp(prefix="mh-para-live-")
    exe = os.path.join(d, PROC_NAME)
    shutil.copy2("/bin/sleep", exe)
    procs = [sleeper(exe) for _ in range(n)]
    for _ in range(50):
        r = subprocess.run(["pgrep", "-x", PROC_NAME], capture_output=True, text=True)
        if len([x for x in r.stdout.split() if x.isdigit()]) >= n:
            break
        time.sleep(0.05)
    return d, procs


def main():
    failures, n = [], 0
    live, procs = start_shared_name()
    try:
        for want, rows in ((True, REACH), (False, SILENT)):
            for label, tmpl in rows:
                for lname, lister in LISTER_FORMS:
                    cmd = PRELUDE + tmpl.replace("{L}", lister)
                    fired, err = verdict(cmd)
                    n += 1
                    if fired != want:
                        failures.append("%s [%s | %s]: %s%s" % (
                            "NOT REFUSED" if want else "FALSE REFUSAL", label, lname, cmd,
                            "" if want else "\n    said: " + err[:200]))
                    elif fired and "BLOCKED:" not in err:
                        failures.append("REFUSED SAYING NOTHING [%s | %s]" % (label, lname))
    finally:
        for p in procs:                # by PID, the construct this guard recommends
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=5)
        shutil.rmtree(live, ignore_errors=True)
    if failures:
        print("FAIL (%d of %d)" % (len(failures), n))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d cases (%d reach + %d silent templates x %d listers): GNU parallel's stdin "
          "reaches its template's kill" % (n, len(REACH), len(SILENT), len(LISTER_FORMS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
