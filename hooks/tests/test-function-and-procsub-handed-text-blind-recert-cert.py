"""Check of one clause of `mh-code-handed-to-a-shell-is-code`
(hooks/tests/INVARIANTS.md), written from the hooks/tests/INVARIANTS.md clause alone:

  hooks/block-unsafe-kill.sh reads text that reaches a shell reading code on its stdin through a
  function body at the place it is called, or through stdout redirected into a `>(...)` that runs
  such a shell, as that shell's code, as bash runs it; and it refuses none of these when bash
  hands the shell no such text.

THE ORACLE IS BASH. Every row is a template with {P} in the place of the handed text. The hook is
given the row with {P} = `pkill -f myserver` (refused on its own: the anchor row). bash itself
is given the row with {P} = `touch HANDED_RAN`, through hooks/tests/bash_oracle.py, in an empty
directory; whether bash handed the text to a shell that ran it is whether the file exists after.
  - the file exists       => the hook must REFUSE the row
  - the file does not      => the hook must stay SILENT on the row
Each row also carries its written expectation; a row where bash disagrees with it is red
too (the row does not test what it says), so the oracle cannot quietly turn a refuse row into a
silent one.

DIRECTIONS (derived from the sentence; each must-refuse block has silent siblings one change away):
  F1  a function whose body writes the text, called where its stdout is piped into a bare shell —
      every definition spelling (`f()`, `function f`, `function f()`, a `( )` body, over lines),
      every writer (echo, printf, heredoc, herestring, cat of a heredoc), called through another
      function, in a compound, and the LAST definition before the call being the one that runs
  F2  a function whose body IS the shell reading its stdin, with the text piped into the call
  F3  silent: defined and never called, called where its stdout goes elsewhere (cat, a file, a
      later stage, after the pipe, before the definition), redefined away, its own stdout
      redirected, a body shell that reads a script file, and text that is data to the shell
  P1  stdout redirected into `>(shell)` — every redirection spelling (`>`, `1>`, `>>`, `>|`, `&>`),
      every writer, on a simple command, a group, a subshell, an if/for, a function call, a
      function DEFINITION (bash applies it at every call), a pipeline inside the `>(...)` that
      ends in the shell, a function that is the shell
  P2  held by `exec` with no command for every later command of its shell
  P3  silent: `>(cat)`, `>(grep x)`, `>(bash FILE)`, stderr only (`2>`), a later stdout
      redirection overriding it, the exec in a subshell, `exec 2>`, text that is data to the shell
Not asked, because they are other routes than the sentence's two: a function body whose writer
is a nested `bash -c` (silent without a function too), and a call inside an INPUT `<(...)` read
by `bash <` (silent without a function too).
Controls: the counts of rows bash ran and did not run are printed, and either being 0 is red.
"""
import json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HOOK = os.path.join(HERE, "..", "block-unsafe-kill.sh")
DANGER = "pkill -f myserver"
MARK = "touch HANDED_RAN"

R, S = "refuse", "silent"
ROWS = [
    # ---- F1: a function body writes the text; the call's stdout is a shell's stdin -----------
    ("F1", R, "f() { echo '{P}'; }; f | bash"),
    ("F1", R, "f() { echo '{P}'; }; f | sh"),
    ("F1", R, "f() { printf '%s\\n' '{P}'; }; f | bash"),
    ("F1", R, "function f { echo '{P}'; }; f | bash"),
    ("F1", R, "function f() { echo '{P}'; }; f | bash"),
    ("F1", R, "f() ( echo '{P}' ); f | bash"),
    ("F1", R, "f() { cat <<EOF\n{P}\nEOF\n}; f | bash"),
    ("F1", R, "f() { cat <<'EOF'\n{P}\nEOF\n}\nf | bash"),
    ("F1", R, "f()\n{\n  echo '{P}'\n}\nf | bash"),
    ("F1", R, "f() { cat <<< '{P}'; }; f | bash"),
    ("F1", R, "function f { echo '{P}'; }; g() { f; }; g | bash"),
    ("F1", R, "f() { echo '{P}'; }; g() { f | cat; }; g | bash"),
    ("F1", R, "f() { echo '{P}'; }; { f; } | bash"),
    ("F1", R, "f() { echo '{P}'; }; (f) | bash"),
    ("F1", R, "f() { echo '{P}'; }; if true; then f; fi | bash"),
    ("F1", R, "f() { echo '{P}'; }; f | cat | bash"),
    ("F1", R, "f() { echo '{P}'; }; f x y | bash"),
    ("F1", R, "f() { echo '{P}'; }; true && f | bash"),
    ("F1", R, "f() { echo hi; }; f() { echo '{P}'; }; f | bash"),
    ("F1", R, "f() { echo '{P}'; }; f | bash -s"),
    # ---- F2: the function body is the shell reading its stdin ---------------------------------
    ("F2", R, "f() { bash; }; echo '{P}' | f"),
    ("F2", R, "f() { sh; }; echo '{P}' | f"),
    ("F2", R, "f() { bash -s; }; printf '%s\\n' '{P}' | f"),
    ("F2", R, "function f { cat | bash; }; echo '{P}' | f"),
    ("F2", R, "f() { bash; }; f <<EOF\n{P}\nEOF"),
    ("F2", R, "f() { bash; }; f <<< '{P}'"),
    ("F2", R, "g() { bash; }; f() { g; }; echo '{P}' | f"),
    ("F2", R, "f() { bash; }; echo '{P}' | { f; }"),
    # ---- F3: silent — bash hands no shell the text --------------------------------------------
    ("F3", S, "f() { echo '{P}'; }; echo hi | bash"),
    ("F3", S, "f() { echo '{P}'; }; f | cat"),
    ("F3", S, "f() { echo '{P}'; }; f | wc -l"),
    ("F3", S, "f() { echo '{P}'; }; f > /dev/null | bash"),
    ("F3", S, "f() { echo '{P}' > /dev/null; }; f | bash"),
    ("F3", S, "f() { echo '{P}'; } > /dev/null; f | bash"),
    ("F3", S, "f() { echo '{P}'; }; f && true | bash"),
    ("F3", S, "f() { echo '{P}'; }; true | bash; f"),
    ("F3", S, "f | bash; f() { echo '{P}'; }"),
    ("F3", S, "f() { echo '{P}'; }; f() { echo hi; }; f | bash"),
    ("F3", S, "f() { echo \"echo '{P}'\"; }; f | bash"),
    ("F3", S, "f() { cat <<EOF\necho '{P}'\nEOF\n}; f | bash"),
    ("F3", S, "f() { bash script.txt; }; echo '{P}' | f"),
    ("F3", S, "f() { wc -l; }; echo '{P}' | f"),
    ("F3", S, "f() { bash; }; echo '{P}' | cat"),
    ("F3", S, "f() { bash; }; echo hi | f; echo '{P}'"),
    ("F3", S, "f() { grep x | bash; }; echo '{P}' | f"),
    # ---- P1: stdout redirected into >(shell) --------------------------------------------------
    ("P1", R, "echo '{P}' > >(bash)"),
    ("P1", R, "echo '{P}' > >(sh)"),
    ("P1", R, "echo '{P}' > >( bash )"),
    ("P1", R, "echo '{P}' 1> >(bash)"),
    ("P1", R, "echo '{P}' >> >(bash)"),
    ("P1", R, "echo '{P}' >| >(bash)"),
    ("P1", R, "echo '{P}' &> >(bash)"),
    ("P1", R, "echo '{P}' > >(bash -s)"),
    ("P1", R, "echo '{P}' > >(bash -)"),
    ("P1", R, "printf '%s\\n' '{P}' > >(bash)"),
    ("P1", R, "cat <<EOF > >(bash)\n{P}\nEOF"),
    ("P1", R, "cat > >(bash) <<'EOF'\n{P}\nEOF"),
    ("P1", R, "cat <<< '{P}' > >(bash)"),
    ("P1", R, "{ echo '{P}'; } > >(sh)"),
    ("P1", R, "( echo '{P}' ) > >(bash)"),
    ("P1", R, "if true; then echo '{P}'; fi > >(bash)"),
    ("P1", R, "for i in 1; do echo '{P}'; done > >(bash)"),
    ("P1", R, "echo '{P}' > >(cat | bash)"),
    ("P1", R, "echo '{P}' > >(timeout 5 bash)"),
    ("P1", R, "echo '{P}' > >(bash) 2>/dev/null"),
    ("P1", R, "> >(bash) echo '{P}'"),
    ("P1", R, "f() { echo '{P}'; }; f > >(bash)"),
    ("P1", R, "f() { echo '{P}'; } > >(bash); f"),
    ("P1", R, "f() { bash; }; echo '{P}' > >(f)"),
    ("P1", R, "echo '{P}' | cat > >(bash)"),
    # ---- P2: an exec with no command holds the redirection for later commands -----------------
    ("P2", R, "exec > >(bash); echo '{P}'"),
    ("P2", R, "exec 1> >(bash)\necho '{P}'"),
    ("P2", R, "exec > >(sh); echo hi; printf '%s\\n' '{P}'"),
    ("P2", R, "exec > >(bash); cat <<EOF\n{P}\nEOF"),
    ("P2", R, "exec > >(bash); { echo '{P}'; }"),
    ("P2", R, "f() { echo '{P}'; }; exec > >(bash); f"),
    # ---- P3: silent — no shell is handed the text ---------------------------------------------
    ("P3", S, "echo '{P}' > >(cat)"),
    ("P3", S, "echo '{P}' > >(grep x)"),
    ("P3", S, "echo '{P}' > >(wc -l)"),
    ("P3", S, "echo '{P}' > >(bash script.txt)"),
    ("P3", S, "echo '{P}' 2> >(bash)"),
    ("P3", S, "echo '{P}' > >(bash) > /dev/null"),
    ("P3", S, "echo \"echo '{P}'\" > >(bash)"),
    ("P3", S, "cat <<EOF > >(bash)\necho '{P}'\nEOF"),
    ("P3", S, "(exec > >(bash)); echo '{P}'"),
    ("P3", S, "exec 2> >(bash); echo '{P}'"),
    ("P3", S, "exec > >(cat); echo '{P}'"),
    ("P3", S, "echo '{P}'; exec > >(bash)"),
    ("P3", S, "exec > >(bash); exec > /dev/null; echo '{P}'"),
    ("P3", S, "f() { echo '{P}'; }; f > >(cat)"),
    ("P3", S, "f() { echo '{P}'; } > >(cat); f"),
    ("P3", S, "f() { echo '{P}'; } > >(bash)"),
    ("P3", S, "echo '{P}' > >(grep x | bash)"),
]


def hook_refuses(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True, timeout=120)
    return p.returncode != 0, p.stderr


def bash_hands_it(T, row):
    d = tempfile.mkdtemp(dir=T)
    line = row.replace("{P}", MARK)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": d, "LC_ALL": "C"}
    bash_oracle.run(["bash", "-c", line], stdin=subprocess.DEVNULL, capture_output=True,
                    cwd=d, env=env, timeout=30)
    return os.path.exists(os.path.join(d, "HANDED_RAN"))


def main():
    fails = []
    anchor, _ = hook_refuses(DANGER)
    print("anchor: hook %s `%s` on its own" % ("refuses" if anchor else "DOES NOT refuse", DANGER))
    if not anchor:
        fails.append("anchor: the hook does not refuse `%s` at all, so no row below means anything"
                     % DANGER)
    T = tempfile.mkdtemp(prefix="fn-procsub-cert-")
    ran = notran = 0
    try:
        for direction, expect, row in ROWS:
            handed = bash_hands_it(T, row)
            ran += handed
            notran += not handed
            truth = R if handed else S
            refused, err = hook_refuses(row.replace("{P}", DANGER))
            said = R if refused else S
            shown = row.replace("{P}", DANGER).replace("\n", "\\n")
            bad = []
            if truth != expect:
                bad.append("bash says %s but the row expects %s (the row is mis-built)"
                           % ("the shell ran the text" if handed else "no shell ran the text", expect))
            if said != truth:
                bad.append("bash %s the text, but the hook is %s"
                           % ("RUNS" if handed else "does NOT run",
                              "REFUSING" if refused else "SILENT"))
            if bad:
                msg = "[%s] %s  —  %s" % (direction, shown, "; ".join(bad))
                fails.append(msg)
                print("  FAIL " + msg)
            else:
                print("  ok   [%s] %-6s %s" % (direction, truth, shown))
    finally:
        shutil.rmtree(T, ignore_errors=True)
    print("asked %d rows: bash handed a shell the text in %d, in %d it did not" % (len(ROWS), ran, notran))
    if not ran or not notran:
        fails.append("vacuous: bash ran the text in %d rows and not in %d" % (ran, notran))
    if fails:
        print("FAILED %d:" % len(fails))
        for f in fails:
            print("  - " + f)
        sys.exit(1)
    print("all held")


if __name__ == "__main__":
    main()
