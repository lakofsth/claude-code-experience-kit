"""Check mh-code-handed-to-a-shell-is-code (amended 2026-10-30): a wrapper's long options are read
as the wrapper's own getopt_long reads them, so the command it runs is found.

GNU getopt_long takes any unambiguous prefix of a long option, `--opt ARG` as well as `--opt=ARG`,
and an OPTIONAL argument only after `=`. Read in full only, `timeout --sig KILL 5 pkill -f X`
would read KILL as the duration and 5 as the command, and `xargs --replace pkill -f X` would have
its pkill eaten as a replace string (--replace, --max-lines and --eof take an optional argument):
either way the wrong command would be judged and the pattern kill let through.

FOUR PARTS, each failing on its own:

  G  GRAMMAR, MEASURED FROM THE PROGRAM. Every installed wrapper bash_parse.WRAPPERS names is
     asked, inside hooks/tests/bash_oracle.py's namespace, what its long options are: the names its
     --help prints, each one's kind by its own getopt diagnostics (`--NAME=x` -> "doesn't allow an
     argument": none; `--NAME` -> "requires an argument": one; else optional), the names its help
     leaves out (`--c` for every letter: "ambiguous; possibilities" lists them, "requires"/"doesn't
     allow" names the one), and its alias groups (a shared prefix it accepts without "ambiguous").
     That must equal bash_parse.LONG_OPTS. sudo, run0, systemd-run and systemd-inhibit are --help
     rows, read from `W --help` and never run (they ask for authentication or start units). A
     wrapper with no getopt_long grammar must be stated in NO_LONG with its reason.
  O  ORACLE, END TO END. The wrappers above, and their neighbours, run a stand-in that
     writes its argv to a file: each row must run the stand-in with exactly the argv `marker`, so
     the wrapper itself says which word is its command. The ambiguous control must run nothing.
  P  THE PARSER. hooks/bash_parse.py's parse() must find the command the wrapper runs in every
     oracle row and every derived row below (H): it is shared with the original's
     block-live-script-edit.sh (original only), which has no backstop, and in hooks/block-unsafe-kill.sh a misread is caught only where a
     kill word happens to survive among the words read past (CARRIED) -- `timeout --sig KILL 5
     pkill -f X` was refused at af8fdc6 by that backstop, `xargs --replace pkill -f X` was not.
  H  THE GUARD. Each oracle row with a pattern kill in the stand-in's place must be refused and
     with `sleep 1` must stay silent. Then, from the grammar part G MEASURED (not from bash_parse's
     table), every option taking an argument is written at its shortest unique prefix with its
     argument as the next word, and every optional one bare (at that prefix and in full), ahead
     of a pattern kill: each must be
     refused, its `sleep 1` twin silent. Controls that read as they did before: a full spelling
     (refused), an ambiguous prefix (refused, as a flag word, as before), a non-wrapper word
     (`echo --sig KILL 5 pkill ...`, silent), systemd-run's --host in any spelling (another host's
     processes, silent).

Stated out (and in hooks/tests/INVARIANTS.md): GNU parallel's Getopt::Long abbreviations (GNU parallel is
not run). The long options of programs that hand a string to a shell (su/runuser/script/sg
`--comm`, watch, git) are asserted by test-handed-code-long-option-prefixes.py;
their verdicts are printed here.
"""
import json, os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)
import bash_parse  # noqa: E402

HOOK = os.path.join(HERE, "..", "block-unsafe-kill.sh")
D_PAT = "pkill -f myserver"
D_ALL = "killall python3"
TWIN = "sleep 1"
LC = dict(os.environ, LC_ALL="C", LANG="C")

HELP_ROWS = ("sudo", "run0", "systemd-run", "systemd-inhibit")
NO_LONG = {   # WRAPPERS members read with no getopt_long grammar, and why
    "builtin": "a bash builtin: no long option", "command": "a bash builtin: no long option",
    "exec": "a bash builtin: no long option", "doas": "getopt(3), no long option (not installed)",
    "screen": "screen's own parser: no long option", "unbuffer": "expect script: no long option",
    "chronic": "moreutils, getopt(3): no long option", "nocache": "no long option",
    "sshpass": "getopt(3): no long option", "trickle": "getopt(3): no long option",
    "fstab-decode": "takes no option", "busybox": "an applet name first; --list/--install run nothing",
    "dbus-run-session": "its own parser: --config-file/--dbus-daemon in full only (checked below)",
}
# The words a wrapper needs around an option to run its command: (before the options, after them).
# The word a derived row runs w by: `time` first in a command is bash's keyword, which runs its
# first word, so the program is named by its path.
WORD = {"time": "/usr/bin/time"}
# Options a derived row leaves out: a flag consumes nothing; systemd-run's --host sends the command
# to another host (MUST_SILENT); env's --split-string's argument is the command itself (ORACLE).
SKIP = {"systemd-run": ("--host",), "env": ("--split-string",)}
FRAME = {"timeout": ("", "5"), "flock": ("", "lk"), "chroot": ("", "/"), "chrt": ("", "0"),
         "taskset": ("", "1"), "setarch": ("x86_64", "")}

PROBE = r'''
import json, os, re, string, subprocess, sys
ENV = dict(os.environ, LC_ALL="C", LANG="C")
ENV.pop("POSIXLY_CORRECT", None)
UNREC = r"unrecognized option|unknown option|invalid option"


def ask(argv):
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           timeout=5, env=ENV)
        return p.stdout + p.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except OSError as e:
        return "OSERROR %s" % e


def kind(w, n):
    if "doesn't allow an argument" in ask([w, "%s=x" % n]):
        return ""
    return "=" if "requires an argument" in ask([w, n]) else "?"


def measure(w):
    out = {}
    for n in sorted(set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9.-]*[a-z0-9])", ask([w, "--help"])))):
        a = ask([w, "%s=x" % n])
        if re.search(UNREC, a) and n in a:
            continue                         # a name its help prints that it does not take
        out[n] = kind(w, n)
    named = lambda a: set(re.findall(r"option '(--[a-z][a-z0-9.-]*)(?:=x)?' (?:requires|doesn't allow)", a))
    for c in string.ascii_lowercase:
        a = ask([w, "--" + c])
        mine = {k for k in out if k.startswith("--" + c)}
        m = re.search(r"is ambiguous; possibilities:(.*)", a)
        if m:
            seen = set(re.findall(r"'(--[a-z0-9.-]+)'", m.group(1)))
        elif re.search(UNREC, a):
            seen = set()
        else:
            seen = (named(a) | named(ask([w, "--%s=x" % c]))) or mine
        for h in seen - set(out):
            out[h] = kind(w, h)
    groups = []
    for a in sorted(out):
        for b in sorted(out):
            if a >= b or out[a] != out[b]:
                continue
            p = os.path.commonprefix([a, b])
            while p in out:                  # an exact name wins over its prefixes
                p = p[:-1]
            reach = {k for k in out if k.startswith(p)}
            if len(p) < 3 or len({out[k] for k in reach}) != 1:
                continue
            if "is ambiguous" in ask([w, p + ("=x" if out[a] == "" else "")]) + ask([w, p]):
                continue
            for g in groups:
                if g & reach:
                    g |= reach; break
            else:
                groups.append(set(reach))
    return {"kinds": out, "aliases": [sorted(g) for g in groups]}


print(json.dumps({w: measure(w) for w in sys.argv[1:]}))
'''

ORACLE_RUN = r'''
set -u
W=$(mktemp -d); cd "$W"
printf '#!/bin/sh\nprintf "%%s\\n" "$*" > "$(dirname "$0")/m"\n' > sa; chmod +x sa
: > lk
while IFS= read -r T; do
  rm -f m; eval "$T" >/dev/null 2>&1 </dev/null
  if [ -e m ]; then echo "RAN $(cat m) :: $T"; else echo "NOT :: $T"; fi
done
rm -rf "$W"
'''
SA = "./sa marker"

# (label, template with {C} for the command, the wrapper's verdict: True runs {C} with the argv
# `marker`, a string runs it with that argv (xargs appends its input), False runs nothing)
ORACLE = [
    ("timeout --sig KILL", "timeout --sig KILL 5 {C}", True),
    ("timeout --s KILL", "timeout --s KILL 5 {C}", True),
    ("timeout --sig=KILL", "timeout --sig=KILL 5 {C}", True),
    ("timeout --kill-a 1", "timeout --kill-a 1 5 {C}", True),
    ("timeout --k 1 --si TERM", "timeout --k 1 --si TERM 5 {C}", True),
    ("timeout --signal KILL (full spelling)", "timeout --signal KILL 5 {C}", True),
    ("nice --adj 5", "nice --adj 5 {C}", True),
    ("nice --a 5", "nice --a 5 {C}", True),
    ("stdbuf --out L", "stdbuf --out L {C}", True),
    ("stdbuf --o L --e 0", "stdbuf --o L --e 0 {C}", True),
    ("setsid --w (a flag)", "setsid --w {C}", True),
    ("nohup", "nohup {C}", True),
    ("flock --time 1", "flock --time 1 lk {C}", True),
    ("flock --wa 1 (hidden --wait)", "flock --wa 1 lk {C}", True),
    ("flock --conf 9", "flock --conf 9 lk {C}", True),
    ("flock --wa 1 FILE -c CODE (flock's own -c)", "flock --wa 1 lk -c '{C}'", True),
    ("flock --time=1 --sh FILE -c CODE", "flock --time=1 --sh lk -c '{C}'", True),
    ("xargs --replace (optional argument, bare)", "echo a | xargs --replace {C}", True),
    ("xargs --rep", "echo a | xargs --rep {C}", True),
    ("xargs --repl=R", "echo a | xargs --repl=R {C}", True),
    ("xargs --max-l (optional argument, bare)", "echo a | xargs --max-l {C}", "marker a"),
    ("xargs --max-lines (in full: optional, bare)", "echo a | xargs --max-lines {C}", "marker a"),
    ("xargs --max-a 1", "echo a | xargs --max-a 1 {C}", "marker a"),
    ("xargs --max-p 1", "echo a | xargs --max-p 1 {C}", "marker a"),
    ("xargs --eo (optional --eof, bare)", "echo a | xargs --eo {C}", "marker a"),
    ("ionice --classd 4 --class 2", "ionice --classd 4 --class 2 {C}", True),
    ("time --f %e", "/usr/bin/time --f %e {C}", True),
    ("time --outp f (alias group --output|--output-file)", "/usr/bin/time --outp f {C}", True),
    ("env --s STR", "env --s '{C}'", True),
    ("env --un X", "env --un X {C}", True),
    # a list wider than any host's: CPU 0 alone is refused where this run's affinity excludes it
    ("taskset --cpu-l 0-4095", "taskset --cpu-l 0-4095 {C}", True),
    ("prlimit --nof=1024 (optional argument, `=`)", "prlimit --nof=1024 {C}", True),
    ("setpriv --n (alias group --nnp|--no-new-privs)", "setpriv --n {C}", True),
    ("systemd-cat --ident x", "systemd-cat --ident x {C}", True),
    # the ambiguous control: --c is --class and --classdata, which ionice refuses
    ("ionice --c 3 (ambiguous: the wrapper refuses it)", "ionice --c 3 {C}", False),
    ("timeout --ver 5 (ambiguous: the wrapper refuses it)", "timeout --ver 5 {C}", False),
    ("xargs --e (ambiguous: --eof, --exit)", "echo a | xargs --e {C}", False),
]
GUARD_EXTRA_REFUSE = [   # read by the guard; their wrapper is not run here
    ("sudo --us root", "sudo --us root {C}"),
    ("sudo --chd /tmp", "sudo --chd /tmp {C}"),
    ("systemd-run --scope --uni u", "systemd-run --scope --uni u {C}"),
    ("run0 --us root", "run0 --us root {C}"),
]
MUST_SILENT = [
    ("a non-wrapper word", "echo --sig KILL 5 %s" % D_PAT),
    ("systemd-run --ho H (another host)", "systemd-run --ho h %s" % D_PAT),
    ("systemd-run --host=H (another host)", "systemd-run --host=h %s" % D_PAT),
    ("timeout --sig KILL 5 sleep 1 (the allow twin)", "timeout --sig KILL 5 sleep 1"),
]


def verdict(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0


def reads(cmd, argv=D_PAT):
    """Whether hooks/bash_parse.py's parse() finds argv as a command of cmd: a command whose words
    are argv's, or a string it hands on as code that is argv (env -S)."""
    want = argv.split()
    return any(c.kw is None and ([v for _, v in c.words] == want or argv in c.codes)
               for c in bash_parse.parse(cmd))


def help_grammar(text):
    g = {}
    for m in re.finditer(r"(?<![\w-])(--[a-z][a-z0-9.-]*[a-z0-9])(\[=|=)?", text):
        n, k = m.group(1), {"[=": "?", "=": "=", None: ""}[m.group(2)]
        g[n] = "?" if n in g and g[n] != k else k     # `--x` beside `--x=ARG`: optional
    return {"kinds": g, "aliases": []}


def table_of(w):
    """bash_parse's reading of w as {"kinds": {name: kind}, "aliases": [[names]]}."""
    t = getattr(bash_parse, "LONG_OPTS", {}).get(w)
    if t is None:
        return None
    groups = {}
    for n, (k, canon) in t.items():
        groups.setdefault(canon, []).append(n)
    return {"kinds": {n: k for n, (k, _) in t.items()},
            "aliases": sorted(sorted(g) for g in groups.values() if len(g) > 1)}


def shortest(name, kinds, aliases):
    """The shortest prefix of name that is no other option's (alias group aside) and no exact
    name, or None when only the full spelling is."""
    mates = next((set(g) for g in aliases if name in g), {name})
    for n in range(3, len(name)):
        p = name[:n]
        if p not in kinds and all(o in mates for o in kinds if o.startswith(p)):
            return p
    return None


def main():
    fails = []
    installed = {w for w in bash_parse.WRAPPERS if shutil.which(w)}
    # --- G: the grammar, measured -------------------------------------------------------
    probed = sorted(w for w in installed if w not in NO_LONG and w not in HELP_ROWS)
    p = bash_oracle.run([sys.executable, "-I", "-c", PROBE] + probed, capture_output=True,
                        text=True, timeout=600)
    measured = json.loads(p.stdout) if p.returncode == 0 else {}
    if p.returncode:
        fails.append("G probe failed: %s" % p.stderr[-400:])
    for w in HELP_ROWS:
        if w in installed:
            h = subprocess.run([w, "--help"], capture_output=True, text=True, env=LC,
                               stdin=subprocess.DEVNULL, timeout=20)
            measured[w] = help_grammar(h.stdout + h.stderr)
    for w in sorted(bash_parse.WRAPPERS):
        if w not in measured and w not in NO_LONG:
            fails.append("G %s: a wrapper neither measured (not installed?) nor in NO_LONG" % w)
    for w, g in sorted(measured.items()):
        t = table_of(w)
        if t is None:
            fails.append("G %s: no LONG_OPTS row; the program reads %d long options" % (w, len(g["kinds"])))
            continue
        for n in sorted(set(g["kinds"]) | set(t["kinds"])):
            if g["kinds"].get(n) != t["kinds"].get(n):
                fails.append("G %s %s: the program reads %r, LONG_OPTS %r"
                             % (w, n, g["kinds"].get(n), t["kinds"].get(n)))
        if sorted(g["aliases"]) != t["aliases"] and w not in HELP_ROWS:
            fails.append("G %s aliases: the program %s, LONG_OPTS %s" % (w, g["aliases"], t["aliases"]))
    if "dbus-run-session" in installed:     # its own parser: a prefix is no option of it
        q = bash_oracle.run(["dbus-run-session", "--conf=/nonexistent", "true"], capture_output=True,
                            text=True, timeout=30, env=LC, stdin=subprocess.DEVNULL)
        if "is unknown" not in q.stderr:
            fails.append("G dbus-run-session took --conf=: %r" % q.stderr[-200:])
    # --- O: the wrapper says which word it runs -----------------------------------------
    lines = [t.replace("{C}", SA) for _, t, _ in ORACLE]
    p = bash_oracle.run(["bash", "-c", ORACLE_RUN], input="\n".join(lines) + "\n",
                        capture_output=True, text=True, timeout=300)
    got = {}
    for ln in p.stdout.splitlines():
        st, _, t = ln.partition(" :: ")
        got[t] = st
    for (label, _, runs), line in zip(ORACLE, lines):
        want = "RAN " + (runs if isinstance(runs, str) else "marker") if runs else "NOT"
        if got.get(line) != want:
            fails.append("O %s: the wrapper %r, want %r (%s)" % (label, got.get(line), want, line))
    # --- P: the parser finds the command the wrapper runs (another guard of the original reads
    # it too, with no backstop) -------------------------------------------------------------
    n = 0
    for label, tpl in [(l, t) for l, t, runs in ORACLE if runs] + GUARD_EXTRA_REFUSE[:4]:
        n += 1
        if not reads(tpl.replace("{C}", D_PAT)):
            fails.append("P %s: parse() does not find `%s` in %s" % (label, D_PAT, tpl))
    # --- H: the guard reads the same command ---------------------------------------------
    for label, tpl, runs in ORACLE:
        for d in (D_PAT, D_ALL):
            n += 1
            cmd = tpl.replace("{C}", d)
            if not verdict(cmd):            # an ambiguous control is refused, as it read before
                fails.append("H NOT REFUSED %s: %s" % (label, cmd))
        n += 1
        if runs and verdict(tpl.replace("{C}", TWIN)):
            fails.append("H REFUSED, allow twin %s: %s" % (label, tpl.replace("{C}", TWIN)))
    for label, tpl in GUARD_EXTRA_REFUSE:
        n += 1
        cmd = tpl.replace("{C}", D_PAT)
        if not verdict(cmd):
            fails.append("H NOT REFUSED %s: %s" % (label, cmd))
    for label, cmd in MUST_SILENT:
        n += 1
        if verdict(cmd):
            fails.append("H REFUSED %s: %s" % (label, cmd))
    derived, done = 0, set()
    for w, g in sorted(measured.items()):
        lead, ops = FRAME.get(w, ("", ""))
        for name, k in sorted(g["kinds"].items()):
            if k == "" or name in SKIP.get(w, ()):
                continue
            p = shortest(name, g["kinds"], g["aliases"])
            spell = [x for x in (p, name if k == "?" else None) if x]   # an optional one in full too
            for p in spell:
                opt = "%s 1" % p if k == "=" else p
                pre = " ".join(x for x in (WORD.get(w, w), lead, opt, ops) if x)
                if pre in done:              # an alias group's members share a prefix
                    continue
                done.add(pre)
                n += 1
                derived += 1
                if not reads("%s %s" % (pre, D_PAT)):
                    fails.append("P derived: parse() does not find `%s` in %s" % (D_PAT, pre))
                for c, want in ((D_PAT, True), (TWIN, False)):
                    n += 1
                    derived += 1
                    if verdict("%s %s" % (pre, c)) != want:
                        fails.append("H %s: %s %s" % ("NOT REFUSED" if want else "REFUSED, twin", pre, c))
    # --- stated out ----------------------------------------------------------------------
    for cmd in ("su --comm '%s'" % D_PAT, "script --comm '%s'" % D_PAT, "sg adm --comm '%s'" % D_PAT,
                "watch --int 1 %s" % D_PAT):
        print("handed code (asserted by test-handed-code-long-option-prefixes.py): %s -> %s"
              % (cmd, "refused" if verdict(cmd) else "allowed"))
    for f in fails:
        print("FAIL", f)
    print("%d wrappers measured, %d oracle rows, %d hook cases (%d derived), %d failures"
          % (len(measured), len(ORACLE), n, derived, len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
