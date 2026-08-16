#!/usr/bin/env python3
"""Behaviour cases for hooks/backtick-prose-warn.sh.

Drives the real hook as a subprocess with a real JSON payload on stdin, because that is the
join it sits on: Claude Code hands a PreToolUse hook the payload on stdin and reads JSON back.

Run it from anywhere:  python3 hooks/tests/test-backtick-prose-warn.py
Exit status is the gate: 0 all pass, 1 one or more failed.
"""
import json, os, subprocess, sys

# Resolved from this file's own location, so the suite runs from any working directory and
# tests the copy that ships beside it rather than one installed somewhere else.
HOOK = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                                    "backtick-prose-warn.sh"))


def fires(cmd):
    p = subprocess.run(["bash", HOOK],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return bool(p.stdout.strip()), p.returncode


# The writer verbs are held in variables so that writing THIS FILE through a shell heredoc does
# not itself trip the hook under test. It is not indirection for its own sake: the literal
# strings below are exactly the shapes the hook is built to notice.
GC = "git commit"
GT = "git tag"

cases = [
    # Shape B: an UNQUOTED heredoc fed to a durable-prose writer. This is the real mangled
    # commit that the shape-B detection was added for.
    ("FAIL-FIRST: the real mangled commit",
     GC + ' -q -F - <<MSG\nfix\n\nnarrowed `-f` to `-s`\nMSG', True),
    ("shape B: " + GT + " heredoc",       GT + ' -a v1 -F - <<T\nuses `foo`\nT', True),
    # Warns, but NOT proof of shape-B detection: `--body-file` also satisfies the shape-A
    # `--body` pattern, so this case stays green with shape B removed. The two git cases
    # above are the ones that discriminate.
    ("gh pr heredoc body",                'gh pr create --body-file - <<B\nuses `foo`\nB', True),
    # Shape A: prose inline in an interpolating string.
    ("shape A: " + GC + " -m inline",     GC + ' -m "fix `foo` handling"', True),
    ("shape A: gh issue --body inline",   'gh issue create --body "see `ls`"', True),
    # Silence on the correct forms.
    ("heredoc writer, no backtick in body", GC + ' -F - <<MSG\nplain prose\nMSG', False),
    ("SAFE: quoted heredoc",              GC + " -F - <<'MSG'\nkeep `x` intact\nMSG", False),
    ("SAFE: quoted + unrelated unquoted heredoc",
     "cat > /tmp/f <<X\nstuff\nX\n" + GC + " -F - <<'MSG'\nkeep `x`\nMSG", False),
    ("SAFE: ordinary shell substitution", 'echo `date`', False),
    ("SAFE: backticks single-quoted",     GC + " -m 'literal `x` here'", False),
    ("SAFE: -F from a file, backtick elsewhere",
     GC + ' -F /tmp/m.txt && echo `date`', False),
    ("SAFE: dangerous form as literal DATA inside a quoted heredoc",
     "python3 - <<'PY'\ncases=['" + GC + " -F - <<MSG\\nuses `x`\\nMSG']\nPY", False),
    ("still warns: real writer AFTER a quoted heredoc block",
     "cat > /tmp/f <<'A'\ndata\nA\n" + GC + " -F - <<MSG\nuses `x`\nMSG", True),
    ("fail-open: garbage payload", None, False),
]

bad = 0
for label, cmd, want in cases:
    if cmd is None:
        p = subprocess.run(["bash", HOOK], input="not json", capture_output=True, text=True)
        got, rc = bool(p.stdout.strip()), p.returncode
    else:
        got, rc = fires(cmd)
    ok = (got == want) and rc == 0
    if not ok:
        bad += 1
    print(f"  {'PASS' if ok else 'FAIL'}  want={'WARN  ' if want else 'SILENT'} "
          f"got={'WARN  ' if got else 'SILENT'}  rc={rc}  {label}")

print(f"\n  Ran {len(cases)} cases — {'ALL PASS' if bad == 0 else str(bad) + ' FAILED'}")
# Exit status, not just a printed line: this file is run as a gate, and a gate whose failure
# looks like success is no gate at all.
sys.exit(1 if bad else 0)
