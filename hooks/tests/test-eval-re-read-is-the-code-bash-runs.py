"""Check for hooks/tests/INVARIANTS.md `mh-an-eval-is-read-as-the-code-bash-runs`.

bash's eval joins its argument words with single spaces and runs that string as code in this
shell; a redirection written on the eval is the eval command's own, never one of those words.
Two halves, bash the oracle of both, each line run in bash_oracle.py's namespace.

Half C (the code): eval is shadowed by a function printing "$*" to fd 9, which no row redirects,
and `hooks/bash_parse.py` parse() must hand on exactly that string for the eval.

Half K (the verdict): pgrep prints a marker pid and kill echoes its operands. The hook must
refuse a line where bash carries the marker to the kill, and must keep allowing the twins where
it does not (an assignment before a command word is temporary, a leading `#` comments the code
out, an unterminated quote is a syntax error, a trailing backslash is a literal word). The re-read
of the call with the eval spelled as its code is the site these rows reach: a `#` in the code
must not comment out the commands after the eval, nor a redirection's target open a quote.

Shapes that would pass a weaker reading: `eval 'P=$(pgrep -f X) #'; kill $P` and `eval
'P=$(pgrep -f X)' >"it's"; kill $P`.
"""
import json, os, shutil, subprocess, sys, tempfile
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "hooks"))
import bash_parse  # noqa: E402

CODE_ROWS = [
    "eval 'a' 'b'",
    "eval a\\ b c",
    "eval 'P=$(pgrep' '-f X)'",
    "eval 'a' >\"it's\"",
    "eval a 2>'#' b",
    "eval a > f b",
    "eval \"x y\" z <<< w",
    "eval a 3>&1 '#'",
    "eval a #b",
]

KILL_ROWS = [
    # a `#` in the code ends at the code's end, not at the call's
    "eval 'P=$(pgrep -f X) #'; kill $P",
    "eval 'P=$(pgrep -f X) # pids'; kill $P",
    "eval 'P=$(pgrep -f X)' '#'; kill $P",
    "eval 'P=$(pgrep -f X)' '#x'; kill $P",
    "eval 'P=$(pgrep -f X) #' && kill $P",
    # a redirection is not one of eval's words
    "eval 'P=$(pgrep -f X)' >\"it's\"; kill $P",
    "eval 'P=$(pgrep -f X)' > \"it's\"; kill $P",
    "eval 'P=$(pgrep -f X)' 2>\"a'b\"; kill $P",
    "eval 'P=$(pgrep -f X)' 2>'#'; kill $P",
    "eval 'P=$(pgrep -f X)' 2>'x #'; kill $P",
    # the words joined: already refused at 94ab4fc, pinned
    "eval 'P=$(pgrep -f X);' 'kill $P'",
    "eval 'P=$(pgrep -f X);' x; kill $P",
    "eval \"P=\\$(pgrep\" \"-f X)\"; kill $P",
    "eval 'P=$(pgrep' '-f X)'; kill $P",
    "eval P=\\$\\(pgrep -f X\\); kill $P",
    "eval ${y:-:}\\; 'P=$(pgrep -f X)'; kill $P",
    "eval -- 'P=$(pgrep -f X)'; kill $P",
    "eval 'P=$(pgrep -f X)' <<< 'x'; kill $P",
    "eval 'P=$(pgrep -f X)' ';' 'kill $P'",
    # a string bash cannot parse whole runs its lines up to the error, and nothing it leaves open
    # reaches the call after the eval
    "eval $'P=$(pgrep -f X)\\n\\''; kill $P",
    "eval $'P=$(pgrep -f X)\\n\"'; kill $P",
    "eval $'P=$(pgrep -f X)\\necho \\''; kill $P",
    "eval $'P=$(pgrep -f X)\\nif true'; kill $P",
    "eval $'P=$(pgrep -f X)\\necho $('; kill $P",
    "eval $'P=$(pgrep -f X)\\n{ echo'; kill $P",
    "eval $'P=$(pgrep -f X)\\n( echo'; kill $P",
    "eval $'P=$(pgrep -f X)\\n)'; kill $P",
    "eval $'echo \"a\\nb\"\\nP=$(pgrep -f X)\\n\\''; kill $P",
    "X=$'P=$(pgrep -f X)\\n\\''; eval \"$X\"; kill $P",
    # allow-twins: bash carries no pid to the kill
    "eval $'P=$(pgrep -f X) \\''; kill $P",
    "eval $')\\nP=$(pgrep -f X)'; kill $P",
    "eval $'echo \\'\\nP=$(pgrep -f X)'; kill $P",
    "eval $'P=$(pgrep -f X); )\\necho'; kill $P",
    "eval 'P=$(pgrep -f X)' x; kill $P",
    "eval 'P=$(echo 4242)' x; kill $P",
    "eval '#' 'P=$(pgrep -f X)'; kill $P",
    "eval ${y:-x} '#' 'P=$(pgrep -f X)'; kill $P",
    "eval ${y:-;#} 'P=$(pgrep -f X)'; kill $P",
    "eval 'P=$(pgrep -f X)' \"'\"; kill $P",
    "eval 'P=$(pgrep -f X)' '\\'; kill $P",
    "eval 'echo #'; kill 123",
    "eval 'echo hi # x' >\"it's\"; kill 123",
    # a here-document the code leaves open ends where the string ends, and takes nothing after the
    # eval for its body
    "eval 'P=$(pgrep -f X) <<E'; kill $P",
    "eval 'P=$(pgrep -f X) <<\"E F\"'; kill $P",
    "eval $'P=$(pgrep -f X) <<E <<F\\nx\\nE'; kill $P",
    "eval $'P=$(pgrep -f X) <<E\\nbody'; kill $P",
    "eval $'cat <<E\\nE\\nP=$(pgrep -f X) <<F'; kill $P",
    "eval 'P=$(pgrep -f X)' '<<E'\nkill $P",
    "eval $'P=$(pgrep -f X) <<E\\nE'; kill $P",
    "eval 'P=$(pgrep -f X) x <<E'; kill $P",
    "eval 'echo <<E'; kill 123",
    # an eval in a pipeline runs in a subshell, binding nothing after it (unless lastpipe)
    "eval 'P=$(pgrep -f X)' | cat; kill $P",
    "eval 'P=$(pgrep -f X) <<E' | cat; kill $P",
    "eval 'P=$(pgrep -f X)' |& cat; kill $P",
    "echo | eval 'P=$(pgrep -f X)'; kill $P",
    "shopt -s lastpipe; echo | eval 'P=$(pgrep -f X)'; kill $P",
    "eval 'P=$(pgrep -f X); kill $P' | cat",
]

SCRATCH = tempfile.mkdtemp(prefix="eval-re-read-")


def bash(line, prelude):
    p = bash_oracle.run(["bash", "-c", prelude + line], capture_output=True, text=True,
                        timeout=20, cwd=SCRATCH, stdin=subprocess.DEVNULL)
    return p.stdout


def hook_exit(line):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": line}})
    p = subprocess.run(["bash", os.path.join(ROOT, "hooks", "block-unsafe-kill.sh")],
                       input=payload, capture_output=True, text=True, timeout=60)
    return p.returncode


red = []
print("half C: the code parse hands on for an eval is the string bash's eval runs")
SHOW = "exec 9>&1; eval(){ printf 'CODE<%s>\\n' \"$*\" >&9; }\n"
for line in CODE_ROWS:
    out = [l for l in bash(line, SHOW).splitlines() if l.startswith("CODE<")]
    want = out[0][5:-1] if len(out) == 1 else None
    got = [c.codes for c in bash_parse.parse(line) if c.kw is None and c.name == "eval"]
    ok = want is not None and len(got) == 1 and want in got[0]
    print("  %s %-34r bash runs %-14r parse hands on %r" % ("ok " if ok else "RED", line, want, got))
    if not ok:
        red.append(line)

print("half K: refused exactly where bash carries the lister's pid to the kill")
SHADOW = ("pgrep(){ echo 4242; }; kill(){ echo \"KILL:$*\"; }; pkill(){ :; }; "
          "killall(){ :; }; x(){ :; }\n")
carried = 0
for line in KILL_ROWS:
    want = "4242" in "".join(l for l in bash(line, SHADOW).splitlines() if l.startswith("KILL:"))
    carried += want
    rc = hook_exit(line)
    ok = rc == (2 if want else 0)
    print("  %s %-52r bash carries the pid: %-5s hook exit %d" % ("ok " if ok else "RED", line, want, rc))
    if not ok:
        red.append(line)

# Controls: the oracle must have said yes and no, or the comparison proves nothing.
if carried in (0, len(KILL_ROWS)):
    red.append("oracle gave one answer for every row (%d of %d carried)" % (carried, len(KILL_ROWS)))
shutil.rmtree(SCRATCH, ignore_errors=True)
print("%d of %d red" % (len(red), len(CODE_ROWS) + len(KILL_ROWS)))
sys.exit(1 if red else 0)
