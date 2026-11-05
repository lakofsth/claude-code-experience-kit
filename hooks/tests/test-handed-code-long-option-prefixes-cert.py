"""Check: a handed-code option in every spelling its program's parser accepts.

The sentence (hooks/tests/INVARIANTS.md `mh-code-handed-to-a-shell-is-code`, amendment of 2026-10-30): the
strings a program hands to a shell are read from every spelling of its code-taking option that the
program's own option parser accepts -- the full long name, every unambiguous prefix of it, `=ARG`
and the next word -- so hooks/block-unsafe-kill.sh gives the abbreviated spelling the verdict of
the full one (`su --comm 'pkill -f X'`, `script --comm '...'`, `sg GROUP --comm '...'` are refused
as their `--command` spellings are, while their `sleep 1` twins stay silent).

Directions, each derived from the sentence and not from any fix:

  P. THE PREMISE, MEASURED. Each program's long-option set is the one its own --help prints here
     (su, runuser, script), and where the program can run a harmless string without root or a
     password (script, sg, git rebase --exec) every abbreviated spelling below is first RUN with
     `echo RAN >marker` and must write the marker: a spelling the program refuses is not one the
     sentence asks about, and a spelling it runs is.
  1. Every unambiguous prefix, from the shortest the option set leaves unambiguous to the full name
     (`--c` ... `--command` for su, runuser, script, sg; `--se` ... `--session-command` for su
     and runuser; `--ex` ... `--exec` for git rebase).
  2. Both argument forms of each prefix: `--opt=ARG` and `--opt ARG` (the next word).
  3. Each program in the positions its parser takes the option: su/runuser with the user before
     or after it and after `-`, sg with the group before and after it, script with its trailing
     file, git with the revision after it.
  4. "The verdict of the full one", both ways: each abbreviation is refused wherever its full
     spelling is (two dangers: a pattern kill and killall), and its `sleep 1` twin is silent
     wherever the full spelling's twin is. The full spelling is run as the anchor; a case is
     only counted against the abbreviation when its anchor gave the expected verdict, so a red
     here is the abbreviation disagreeing with the full name, and an anchor red is reported as
     such.
  5. An AMBIGUOUS prefix (`su --s`: session-command, shell, supp-group) is refused by su itself
     and runs nothing; it is not a spelling the parser accepts, so nothing is asserted on it.

Not pinned here: fish -c/--command and --init-command (fish may not be installed, so its parser's
prefixes are not measured), and flock, whose `FILE -c|--command CODE` form is matched
by flock literally (measured: `flock F --comm X` runs `--comm` as a program).
"""
import json, os, re, shutil, subprocess, sys, tempfile

HOOK = os.environ.get("HOOK", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                           "..", "block-unsafe-kill.sh"))

DANGERS = ["pkill -f myserver", "killall python3"]
HARMLESS = "sleep 1"

# Long-option sets as measured from each program's --help. The probe below
# re-reads --help where the program is installed and fails on a difference.
LONG = {
    "su": "command session-command fast login group supp-group preserve-environment pty no-pty"
          " shell whitelist-environment help version",
    "runuser": "command session-command fast login group supp-group preserve-environment pty"
               " no-pty shell whitelist-environment user help version",
    "script": "append command echo return flush force log-io log-in log-out log-timing"
              " logging-format output-limit quiet timing help version",
    "sg": "command help version",
}


def prefixes(name, opts):
    """Every prefix of `name` that names it alone among opts (exact match wins)."""
    out = []
    for k in range(1, len(name) + 1):
        p = name[:k]
        if p == name or [o for o in opts if o.startswith(p)] == [name]:
            out.append(p)
    return out


# program -> (option, [templates]); {o} is the spelled option word(s), {c} the quoted code.
TEMPLATES = {
    "su": [("command", ["su {o}", "su root {o}", "su - root {o}", "su {o} root"]),
           ("session-command", ["su {o}", "su root {o}", "su {o} root"])],
    "runuser": [("command", ["runuser root {o}", "runuser {o} root", "runuser -l root {o}"]),
                ("session-command", ["runuser root {o}", "runuser {o} root"])],
    "script": [("command", ["script -q {o} /dev/null", "script {o}", "script -qe {o} /dev/null"])],
    "sg": [("command", ["sg wheel {o}", "sg {o} wheel"])],
    "git": [("exec", ["git rebase {o} HEAD~1", "git rebase -i {o} main"])],
}
GIT_EXEC_PREFIXES = ["ex", "exe", "exec"]   # measured: `git rebase --ex=CMD` runs CMD; --e is
                                            # ambiguous (--edit-todo, --empty, --exec)


def spellings(prog, opt):
    if prog == "git":
        ps = GIT_EXEC_PREFIXES
    else:
        ps = prefixes(opt, LONG[prog].split())
    return ps


def word_forms(p, code):
    q = "'" + code + "'"
    return [("next word", "--%s %s" % (p, q)), ("=ARG", "--%s=%s" % (p, q))]


def verdict(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode != 0, p.stderr


def probe():
    """Direction P: the spellings are ones the programs themselves accept. [] when all hold."""
    bad, notes = [], []
    for prog in ("su", "runuser", "script"):
        exe = shutil.which(prog)
        if not exe:
            notes.append("%s not installed: its option set is taken as written" % prog)
            continue
        h = subprocess.run([exe, "--help"], capture_output=True, text=True)
        seen = set(re.findall(r"--([a-z][a-z-]*)", h.stdout + h.stderr))
        if seen != set(LONG[prog].split()):
            bad.append("PROBE %s --help long options differ: help %s, table %s"
                       % (prog, sorted(seen), sorted(LONG[prog].split())))
    d = tempfile.mkdtemp(prefix="mh-prefix-probe-")
    try:
        mk = os.path.join(d, "marker")
        run = []
        if shutil.which("script"):
            for p in spellings("script", "command"):
                code = "echo RAN >" + mk
                for w in (["--%s=%s" % (p, code)], ["--" + p, code]):
                    run.append((["script", "-q"] + w + ["/dev/null"], "script " + w[0][:12]))
        if shutil.which("sg"):
            g = subprocess.run(["id", "-gn"], capture_output=True, text=True).stdout.strip()
            for p in spellings("sg", "command"):
                run.append((["sg", g, "--%s=echo RAN >%s" % (p, mk)], "sg --%s=" % p))
                run.append((["sg", g, "--" + p, "echo RAN >" + mk], "sg --%s" % p))
        for argv, label in run:
            if os.path.exists(mk):
                os.unlink(mk)
            subprocess.run(argv, capture_output=True, text=True, timeout=30,
                           stdin=subprocess.DEVNULL)
            if not os.path.exists(mk):
                bad.append("PROBE %s did not run its string: %r" % (label, argv))
        if shutil.which("git"):
            r = os.path.join(d, "repo")
            env = dict(os.environ, GIT_AUTHOR_NAME="a", GIT_AUTHOR_EMAIL="a@b",
                       GIT_COMMITTER_NAME="a", GIT_COMMITTER_EMAIL="a@b",
                       GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
            g = lambda *a: subprocess.run(["git", "-C", r] + list(a), capture_output=True,
                                          text=True, env=env)
            subprocess.run(["git", "init", "-q", r], capture_output=True, env=env)
            g("commit", "-q", "--allow-empty", "-m", "a")
            g("commit", "-q", "--allow-empty", "-m", "b")
            for p in GIT_EXEC_PREFIXES:
                if os.path.exists(mk):
                    os.unlink(mk)
                g("rebase", "--%s=echo RAN >%s" % (p, mk), "HEAD~1")
                if not os.path.exists(mk):
                    bad.append("PROBE git rebase --%s= did not run its string" % p)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return bad, notes


def main():
    failures, anchors_bad = [], []
    bad, notes = probe()
    failures += bad
    n = 0
    for prog, rows in TEMPLATES.items():
        for opt, templates in rows:
            for t in templates:
                for code, want in [(c, True) for c in DANGERS] + [(HARMLESS, False)]:
                    for form, full_word in word_forms(opt, code):
                        anchor = t.format(o=full_word)
                        fired, _ = verdict(anchor)
                        if fired != want:
                            anchors_bad.append("ANCHOR %s [%s]: %s"
                                               % ("NOT BLOCKED" if want else "FALSE POSITIVE",
                                                  form, anchor))
                            continue
                        for p in spellings(prog, opt):
                            if p == opt:
                                continue
                            cmd = t.format(o=dict(word_forms(p, code))[form])
                            n += 1
                            fired, err = verdict(cmd)
                            if want and not fired:
                                failures.append("NOT BLOCKED (its --%s spelling is) [%s]: %s"
                                                % (opt, form, cmd))
                            elif not want and fired:
                                failures.append("FALSE POSITIVE (its --%s twin is silent) [%s]: "
                                                "%s\n    said: %s" % (opt, form, cmd, err[:200]))
    for line in notes:
        print("note: " + line)
    if anchors_bad:
        print("ANCHORS (full spelling) not as expected -- %d; their abbreviations not counted:"
              % len(anchors_bad))
        for a in anchors_bad:
            print("  " + a)
    if failures or anchors_bad:
        print("FAIL (%d of %d abbreviated cases)" % (len(failures), n))
        for f in failures:
            print("  " + f)
        return 1
    print("OK: %d abbreviated spellings, each with the verdict of its full one" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
