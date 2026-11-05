"""Pin a clause of mh-every-pattern-keyed-kill-is-refused: code behind an unlisted wrapper.

The class: a pattern-keyed kill inside CODE that a program runs, where the program is reached
through a wrapper the guard does not name. Such a wrapper is read past to any word from which the
rest runs code, so `valgrind -q sh -c 'pkill -f X'`, `kubectl exec POD -- bash -c '...'` and
`time -p bash -c '...'` are refused, and so are the string runners `sudo -s 'STRING'` and
`nix-shell --run 'STRING'`.

The sites are DERIVED, not listed: every program bash_parse.py reads code from or reads past --
the string constants resolve(), command_codes() and handed_code() compare a command's name with
(an AST walk), every member of SHELLS, and every member of WRAPPERS (followed by `sh -c`). Each
derived program must have a template below that runs CODE through it; a derived name with none is
a failure, so a program added to bash_parse.py without one turns this red.

  R  each template, with CODE a pkill -f and a kill $(pgrep -f), bare and behind each unlisted
     prefix in PREFIXES, is refused;
     The same for ARGV_FORMS, a second reading of watch, sudo -s and tmux.
  S  the same templates with CODE `echo hi` or `kill 12345` stay silent, as does a command sent
     to another host behind an unlisted prefix.
"""
import ast
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
HOOKS = os.path.join(HERE, "..")
HOOK = os.environ.get("HOOK", os.path.join(HOOKS, "block-unsafe-kill.sh"))
sys.path.insert(0, HOOKS)
import bash_parse  # noqa: E402

CODES = ["pkill -f myserver", "kill $(pgrep -f myserver)"]
CONTROLS = ["echo hi", "kill 12345"]
PREFIXES = ["", "valgrind -q ", "xvfb-run -a ", "kubectl exec pod -- ", "time -p ",
            "zz-unlisted-runner --opt ", "coproc "]

# How each code-reading program runs CODE (single-quoted, with no quote of its own inside).
TEMPLATES = {
    "docker": "docker exec c1 sh -c '%s'", "podman": "podman exec c1 sh -c '%s'",
    "env": "env -S '%s'", "eval": "eval '%s'", "find": "find . -exec sh -c '%s' \\;",
    "flock": "flock /tmp/l -c '%s'", "git": "git rebase -x '%s'",
    "newgrp": "newgrp grp -c '%s'", "sg": "sg grp -c '%s'",
    "nix-shell": "nix-shell --run '%s'", "parallel": "parallel ::: '%s'",
    "sem": "sem -- '%s'", "runuser": "runuser -c '%s' u", "script": "script -qc '%s' /dev/null",
    "ssh": "ssh localhost '%s'", "su": "su -c '%s'", "sudo": "sudo -s '%s'",
    "tmux": "tmux new-session -d '%s'", "trap": "trap '%s' EXIT", "watch": "watch -n1 '%s'",
    "setarch": "setarch x86_64 sh -c '%s'", "runcon": "runcon ctx sh -c '%s'",
}

# A second reading where a program's own grammar gives one: watch and sudo -s join their argv for
# `sh -c` (the words as written are read beside the joined values), tmux runs a shell-command given
# as several arguments directly.
ARGV_FORMS = ["watch -n1 sh -c '%s'", "sudo -s sh -c '%s'", "sudo -i bash -c '%s'",
              "tmux new-session -d sh -c '%s'", "tmux split-window bash -c '%s'"]


def derived():
    """Every program name bash_parse.py reads code from or reads past (module docstring)."""
    tree = ast.parse(open(bash_parse.__file__).read())
    names = set()
    for f in tree.body:
        if isinstance(f, ast.FunctionDef) and f.name in ("resolve", "command_codes", "handed_code"):
            for n in ast.walk(f):
                if isinstance(n, ast.Compare) and isinstance(n.left, ast.Name) \
                        and n.left.id in ("name", "base"):
                    names |= {x.value for c in n.comparators for x in ast.walk(c)
                              if isinstance(x, ast.Constant) and isinstance(x.value, str)}
    return names, set(bash_parse.SHELLS), set(bash_parse.WRAPPERS)


def template(name, shells, wrappers):
    if name in TEMPLATES:
        return TEMPLATES[name]
    if name in shells:
        return name + " -c '%s'"
    if name in wrappers:
        return " ".join([name] + ["x"] * bash_parse.WRAPPERS[name][1] + ["sh -c '%s'"])
    return None


def fired(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0 and "BLOCKED:" in p.stderr


def main():
    named, shells, wrappers = derived()
    bad, cases = [], []
    for name in sorted(named | shells | wrappers):
        t = template(name, shells, wrappers)
        if t is None:
            bad.append("NO TEMPLATE for derived program %r" % name)
            continue
        for pre in PREFIXES:
            cases += [(True, pre + t % code) for code in CODES]
            cases += [(False, pre + t % code) for code in CONTROLS]
    for t in ARGV_FORMS:
        for pre in PREFIXES:
            cases += [(True, pre + t % code) for code in CODES]
            cases += [(False, pre + t % code) for code in CONTROLS]
    cases += [(False, pre + "ssh build-host 'pkill -f myserver'") for pre in PREFIXES[1:]]
    with ThreadPoolExecutor(8) as ex:
        got = list(ex.map(lambda c: fired(c[1]), cases))
    for (want, cmd), hit in zip(cases, got):
        if hit != want:
            bad.append(("NOT BLOCKED: %s" if want else "FALSE POSITIVE: %s") % cmd)
    n = sum(w for w, _ in cases)
    if bad:
        print("FAIL (%d wrong of %d must-refuse, %d must-stay-silent)" % (len(bad), n, len(cases) - n))
        for b in bad:
            print("  " + b)
        return 1
    print("OK: %d must-refuse, %d must-stay-silent, over %d derived programs"
          % (n, len(cases) - n, len(named | shells | wrappers)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
