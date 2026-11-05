"""Check mh-code-handed-to-a-shell-is-code (amended 2026-10-30): the strings a program hands to a
shell are read from every spelling of its code-taking option that the program's own option parser
accepts -- the full long name, every unambiguous prefix of it, `=ARG` and the next word -- so
hooks/block-unsafe-kill.sh gives the abbreviated spelling the verdict of the full one.

Matched in full only, `su --comm 'pkill -f X'`, `script --comm '...'`, `sg adm --comm '...'` and
`git rebase --exe '...'` would run their code while the guard read none.

FIVE PARTS, each failing on its own:

  S  THE SITES, DERIVED. An AST walk of handed_code() and _shell_read() in hooks/bash_parse.py
     collects every string literal `--NAME` the code compares an option word with. Each must be read
     through long_code()/long_option() (a literal handed to them, or compared with what long_option
     returns), or be in IN_FULL with the reason its program reads it in full -- a reason part O
     checks against the program where it is installed.
  G  THE GRAMMAR, MEASURED. script, sg, newgrp, watch and runuser are asked, inside
     hooks/tests/bash_oracle.py's namespace, by the PROBE of test-wrapper-long-option-abbreviations.py
     (their own getopt diagnostics), what long options they read; that must equal
     bash_parse.LONG_OPTS. runuser's diagnostics come before its root check. su is the same
     util-linux binary (one su-common.c table) and setuid: its row must equal runuser's, and is
     not run. git-rebase is `git rebase --git-completion-helper-all`. where fish is not installed
     its row is DOCUMENTED below from fish's own getopt_long table, and is measured if fish appears.
  O  THE ORACLE. Where the program runs unprivileged here (script, sg, newgrp, git rebase), each
     template runs it with `/bin/echo RAN` in place of the code: RAN must appear, and must not for
     an ambiguous control (the program refuses it). Also: `flock F --comm CODE` executes `--comm`
     (flock reads FILE -c|--command by strcmp), and `bash --rcf` is an invalid option. su, runuser
     and fish rows are NOT run (privilege; not installed).
  P  THE PARSER. handed_code()/shell_code(), through parse(), hand on the code in every template
     and do not in an ambiguous one (`su --s`, `fish --i`, `git rebase --e`).
  H  THE GUARD. Every template with `pkill -f myserver` or `killall python3` as its code is
     refused, and its `sleep 1` twin stays silent.

The templates are derived from the measured (or documented) grammar, not from bash_parse's table:
every unambiguous prefix of each code-taking option, from the shortest to the full name, each as
`PREFIX CODE` and `PREFIX=CODE`.
"""
import ast, importlib.util, inspect, json, os, re, shutil, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)
import bash_parse  # noqa: E402

HOOK = os.path.join(HERE, "..", "block-unsafe-kill.sh")
KILLS = ("pkill -f myserver", "killall python3")
TWIN = "sleep 1"
LC = dict(os.environ, LC_ALL="C", LANG="C")

# fish's own getopt_long table (fish-shell src/bin/fish.rs LONG_OPTS; its wgetopt is a port of GNU
# getopt_long, unambiguous prefixes included). DOCUMENTED, measured only where fish is installed.
FISH_DOC = {"--command": "=", "--init-command": "=", "--features": "=", "--debug": "=",
            "--debug-output": "=", "--debug-stack-frames": "=", "--interactive": "", "--login": "",
            "--no-config": "", "--no-execute": "", "--print-rusage-self": "",
            "--print-debug-categories": "", "--profile": "=", "--profile-startup": "=",
            "--private": "", "--help": "", "--version": ""}
MEASURED = ("script", "sg", "newgrp", "watch", "runuser")
# Literals the two functions still compare in full, and why their program reads them so.
IN_FULL = {
    "--command": "_shell_read(), a shell not in LONG_OPTS: bash and the rest have no --command;"
                 " handed_code(), nix-shell: as --run below",
    "--command=": "_shell_read(), the same, `=` spelling; handed_code(), nix-shell: as --run=",
    "--run": "handed_code(), nix-shell: nix-build.cc compares --run and --command with ==, no"
             " getopt_long and no prefix (nix-shell, where installed)",
    "--run=": "handed_code(), nix-shell: the `=` spelling, read too; reading it refuses more, never less",
    "--rcfile": "_shell_read(): bash's own long options take no prefix (`bash --rcf`: invalid)",
    "--init-file": "_shell_read(): the same",
    "--git-dir": "git's global options are matched in full by git.c, not parse-options",
    "--work-tree": "the same", "--namespace": "the same", "--super-prefix": "the same",
    "--config-env": "the same",
    "--quiet": "git submodule [foreach]: git-submodule.sh matches its options with shell `case`",
    "--cached": "the same", "--recursive": "the same",
}

# program -> (frame with {O} for the option spelling, the code-taking options)
FRAMES = {
    "su": ("su {O} root", ("--command", "--session-command")),
    "runuser": ("runuser {O} root", ("--command", "--session-command")),
    "script": ("script -q {O} /dev/null", ("--command",)),
    "sg": ("sg {G} {O}", ("--command",)),
    "newgrp": ("newgrp {G} {O}", ("--command",)),
    "git-rebase": ("git rebase {O} HEAD~1", ("--exec",)),
    "fish": ("fish {O}", ("--command", "--init-command")),
}
RUNS_HERE = ("script", "sg", "newgrp", "git-rebase")
# Ambiguous prefixes: the program refuses them, so nothing of theirs is code.
AMBIGUOUS = [("su", "su --s {C}"), ("runuser", "runuser --s {C} root"),
             ("fish", "fish --i {C}"), ("git-rebase", "git rebase --e {C} HEAD~1")]
# Long options that take an argument ahead of the code (a misread eats the code word, or reads the
# argument as it): every one must be read so.
AHEAD = [("su", "su --sh /bin/sh --comm {C}"), ("su", "su --supp adm -c {C}"),
         ("script", "script --log-o /dev/null --comm {C} /dev/null"),
         ("fish", "fish --profile-s /dev/null -c {C}"), ("fish", "fish --debug-o /dev/null --init {C}"),
         ("watch", "watch --int 1 {K}"), ("watch", "watch --equ 1 {K}"),
         ("watch", "watch --ex {K}"), ("runuser", "runuser --us root -- {K}"),
         ("runuser", "runuser --gr adm --us root {K}")]

ORACLE_RUN = r'''
set -u
W=$(mktemp -d); cd "$W"
export GIT_AUTHOR_NAME=n GIT_AUTHOR_EMAIL=e@x GIT_COMMITTER_NAME=n GIT_COMMITTER_EMAIL=e@x
: > lk
while IFS= read -r T; do
  rm -rf r; mkdir r; ( cd r && git init -q && echo a > f && git add f && git commit -qm a &&
    echo b > f && git commit -qam b ) >/dev/null 2>&1
  o=$(cd r && eval "$T" 2>&1 </dev/null)
  case $o in *RAN*) echo "RAN :: $T";; *) echo "NOT :: $T";; esac
done
cd /; rm -rf "$W"
'''


def load_probe():
    spec = importlib.util.spec_from_file_location(
        "wlo", os.path.join(HERE, "test-wrapper-long-option-abbreviations.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.PROBE


def sites():
    """(literal, function) for every `--NAME` literal handed_code()/_shell_read() compare in full."""
    out = []
    for fn in ("handed_code", "_shell_read"):
        tree = ast.parse(inspect.getsource(getattr(bash_parse, fn)))
        read = set()                          # literals handed to long_code / long_option's result
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "long_code":
                read |= {id(c) for a in node.args for c in ast.walk(a)}
            if isinstance(node, ast.Compare) and any(
                    isinstance(c, ast.Call) and getattr(c.func, "id", "") == "long_option"
                    for c in ast.walk(node.left)):
                read |= {id(c) for c in ast.walk(node)}
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and re.match(r"^--[a-z]", node.value) and id(node) not in read):
                out.append((node.value, fn))
    return out


def unique_prefixes(name, kinds):
    """Every spelling of name getopt_long resolves to it: the prefixes no other option shares, and
    the full name (an exact name wins)."""
    return [name[:n] for n in range(3, len(name) + 1)
            if name[:n] == name or (name[:n] not in kinds
                                    and all(o == name for o in kinds if o.startswith(name[:n])))]


def verdict(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0


def codes_of(cmd):
    return [c for cm in bash_parse.parse(cmd) for c in cm.codes]


def main():
    fails = []
    # --- S: the sites ----------------------------------------------------------------------
    for lit, fn in sites():
        if lit not in IN_FULL:
            fails.append("S %s(): `%s` is compared in full and is not in IN_FULL" % (fn, lit))
    # --- G: the grammar -------------------------------------------------------------------
    grammar = {}
    have = [w for w in MEASURED if shutil.which(w)]
    probe_cwd = tempfile.TemporaryDirectory()   # script's options write files where they run
    p = bash_oracle.run([sys.executable, "-I", "-c", load_probe()] + have, capture_output=True,
                        text=True, timeout=600, cwd=probe_cwd.name)
    if p.returncode:
        fails.append("G probe failed: %s" % p.stderr[-400:])
    else:
        grammar.update({w: g["kinds"] for w, g in json.loads(p.stdout).items()})
    for w in MEASURED:
        if w not in grammar:
            fails.append("G %s: not measured (not installed?)" % w)
    if "runuser" in grammar:
        grammar["su"] = grammar["runuser"]   # the same binary and table; su is setuid, not run
    with tempfile.TemporaryDirectory() as d:  # the helper answers only inside a repository
        subprocess.run(["git", "init", "-q", d], check=True)
        h = subprocess.run(["git", "rebase", "--git-completion-helper-all"], capture_output=True,
                           text=True, env=LC, stdin=subprocess.DEVNULL, cwd=d)
    grammar["git-rebase"] = {n.rstrip("="): "=" if n.endswith("=") else ""
                             for n in h.stdout.split() if n.startswith("--") and len(n) > 2}
    if "--exec" not in grammar["git-rebase"]:
        fails.append("G git rebase: the helper named no --exec (%r)" % (h.stdout + h.stderr)[-200:])
    if shutil.which("fish"):
        q = bash_oracle.run([sys.executable, "-I", "-c", load_probe(), "fish"], capture_output=True,
                            text=True, timeout=120, cwd=probe_cwd.name)
        grammar["fish"] = json.loads(q.stdout)["fish"]["kinds"]
    else:
        print("fish: not installed, its row is FISH_DOC (fish's documented table), not measured")
        grammar["fish"] = FISH_DOC
    probe_cwd.cleanup()
    for w, kinds in sorted(grammar.items()):
        t = {n: k for n, (k, _) in bash_parse.LONG_OPTS.get(w, {}).items()}
        if w == "git-rebase":                # the helper writes no kind for an optional argument
            t = {n: ("=" if k == "=" else "") for n, k in t.items()}
        for n in sorted(set(kinds) | set(t)):
            if kinds.get(n) != t.get(n):
                fails.append("G %s %s: the program reads %r, LONG_OPTS %r" % (w, n, kinds.get(n), t.get(n)))
    # --- the templates, from the grammar ----------------------------------------------------
    group = subprocess.run(["id", "-gn"], capture_output=True, text=True).stdout.strip()
    rows = []                                 # (program, template with {C})
    for w, (frame, names) in FRAMES.items():
        kinds = grammar.get(w, {})
        for name in names:
            for pre in unique_prefixes(name, kinds):
                for opt in ("%s {C}" % pre, "%s={C}" % pre):
                    rows.append((w, frame.replace("{G}", group).replace("{O}", opt)))
    print("%d templates from the grammar" % len(rows))
    # --- O: the program says what it runs ---------------------------------------------------
    oracle = [(w, t) for w, t in rows if w in RUNS_HERE]
    controls = [(w, t) for w, t in AMBIGUOUS if w in RUNS_HERE]
    flock_bash = ["flock lk --comm {C}", "bash --rcf /dev/null -c {C}"]
    lines = [t.replace("{C}", "'/bin/echo RAN'") for _, t in oracle + controls] + \
            [t.replace("{C}", "'/bin/echo RAN'") for t in flock_bash]
    q = bash_oracle.run(["bash", "-c", ORACLE_RUN], input="\n".join(lines) + "\n",
                        capture_output=True, text=True, timeout=600)
    got = dict(reversed(ln.split(" :: ", 1)) for ln in q.stdout.splitlines() if " :: " in ln)
    for k, line in enumerate(lines):
        want = "RAN" if k < len(oracle) else "NOT"
        if got.get(line) != want:
            fails.append("O %s, want %s: %s" % (got.get(line), want, line))
    print("oracle: %d rows run (%s), %d controls; su, runuser, fish rows not run"
          % (len(oracle), ", ".join(RUNS_HERE), len(controls) + len(flock_bash)))
    # --- P and H ----------------------------------------------------------------------------
    cases = []
    for w, t in rows + [(w, t) for w, t in AHEAD if "{C}" in t]:
        for k in KILLS:
            cmd = t.replace("{C}", "'%s'" % k)
            if k not in codes_of(cmd):
                fails.append("P parse() hands on no `%s` in %s" % (k, cmd))
            cases.append((cmd, True))
        cases.append((t.replace("{C}", "'%s'" % TWIN), False))
    for w, t in AHEAD:
        if "{K}" in t:
            for k in KILLS:
                if k not in codes_of(t.replace("{K}", k)):   # the argv it runs, as the code
                    fails.append("P parse() hands on no `%s` in %s" % (k, t.replace("{K}", k)))
                cases.append((t.replace("{K}", k), True))
            cases.append((t.replace("{K}", TWIN), False))
    for w, t in AMBIGUOUS:
        cmd = t.replace("{C}", "'%s'" % KILLS[0])
        if KILLS[0] in codes_of(cmd):
            fails.append("P ambiguous read as code: %s" % cmd)
    with ThreadPoolExecutor(8) as ex:
        for (cmd, want), v in zip(cases, ex.map(lambda c: verdict(c[0]), cases)):
            if v != want:
                fails.append("H %s: %s" % ("NOT REFUSED" if want else "REFUSED, twin", cmd))
    print("taskset -p (measured, not changed): with -p taskset runs no command, so a kill after it "
          "is not run and the guard's silence is its verdict")
    for f in fails:
        print("FAIL", f)
    print("%d templates, %d hook cases, %d failures" % (len(rows), len(cases), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
