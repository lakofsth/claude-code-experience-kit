"""Check `mh-a-substitution-ends-where-bash-ends-it`.

The sentence: every span hooks/quote_mask.py substitutions() records for a `$(...)`, `<(...)` or
`>(...)` ends where bash ends that substitution, a `case ... esac` in its body included -- the
patterns' `)` (`x)`, `(x)`, `a|x)`, an extglob `@(a|b))`) are patterns, not the closing paren.

The oracle is bash itself: the closing paren of the substitution opening at `open` is the first
`)` after it at which the text up to and including it is a complete command for `bash -n` (with
the row's own closer appended, for a row inside "..."). Every row is first checked to be valid
bash as a whole.

Its directions:
  S   a case ... esac in the body (every pattern form, several arms, arms on lines, a last arm
      with no `;;`, `;&` and `;;&`, a nested case, a case in a subshell or behind `&&`, `then`
      or `do`, `in` on its own line, a heredoc in an arm holding a `)`, inside "...", a process
      substitution): the span substitutions() records ends at bash's paren, and the mask keeps
      its input's length.
  N   negatives: a `)` that does close the substitution still closes it -- the word
      `case` as an argument, `mycase`, a quoted `"case"`, a case already closed by `esac`, a
      plain `$(echo x) y`. M shows these rows can fail: a scanner that reads `case` as a
      keyword wherever it is a word reads them long.
  P   the readers of the spans: hooks/bash_parse.py parse() keeps the substitution one word
      of its host and the words after it top-level; block-unsafe-kill.sh denies a pattern
      lister inside a case arm in a kill's substitution, and stays silent on a harmless one.
  M   the negatives are live: with the command-position test removed from a copy of the
      scanner, at least one N row is red.


Run: python3 hooks/tests/test-quote-mask-case-in-substitution.py   (exit 0 all pass, 1 otherwise)
"""
import json, os, shutil, subprocess, sys, tempfile
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HERE = os.path.dirname(os.path.abspath(__file__))
HOOKS = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, HOOKS)
import quote_mask  # noqa: E402
from quote_mask import mask_quoted, substitutions  # noqa: E402

FAILS = []
K = "ki" + "ll"                     # spelled apart so the kit's own kill guard does not read this file's text
PG = "pg" + "rep"


def check(ok, label):
    print(("  ok: " if ok else "  FAIL: ") + label)
    if not ok:
        FAILS.append(label)


def bash_ok(code):
    return bash_oracle.run(["bash", "-O", "extglob", "-n", "-c", code], capture_output=True).returncode == 0


def bash_end(t, open_, closer):
    """The offset of the paren bash closes the substitution at t[open_] with, or None."""
    for e in range(open_ + 2, len(t)):
        if t[e] == ")" and bash_ok(t[:e + 1] + closer):
            return e
    return None


def opening(t):
    for tok in ("$(", "<(", ">("):
        k = t.find(tok)
        if k >= 0:
            return k
    raise ValueError(t)


# (text, closer): the substitution under test is the first `$(`, `<(` or `>(` of the text.
S = [
    ("echo $(case a in a) echo hi;; esac) y", ""),
    ("echo $(case a in (a) echo hi;; esac) y", ""),
    ("echo $(case a in x|a) echo hi;; esac) y", ""),
    ("echo $(case a in @(a|b)) echo hi;; esac) y", ""),
    ("echo $(case a in x) echo 1;; a) echo 2;; esac) y", ""),
    ("echo $(case a in\n  x) echo 1\n  ;;\n  a) echo 2\n  ;;\nesac) y", ""),
    ("echo $(case a in a) echo last\nesac) y", ""),
    ("echo $(case a in a) echo 1;& b) echo 2;;& *) echo 3;; esac) y", ""),
    ("echo $(case a in a) case b in b) echo in;; esac;; esac) y", ""),
    ("echo $( (case a in a) echo hi;; esac) ) y", ""),
    ("echo $(true && case a in a) echo hi;; esac) y", ""),
    ("echo $(if true; then case a in a) echo hi;; esac; fi) y", ""),
    ("echo $(for v in 1; do case $v in 1) echo hi;; esac; done) y", ""),
    ("echo $(case a\nin a) echo hi;; esac) y", ""),
    ("echo $(case $(echo a) in a) echo hi;; esac) y", ""),
    ("echo $(case \"a\" in 'a') echo hi;; \"b\") echo no;; esac) y", ""),
    ("echo $(case a in a) cat <<E\nx)\nE\n;; esac) y", ""),
    ("echo $(case a in # c)\na) echo hi;; esac) y", ""),
    ("echo $(case a in esac) y", ""),
    ("echo $(case in in in) echo hi;; esac) y", ""),
    ("echo $(case a in a) echo hi;; esac; echo z) y", ""),
    ("echo \"$(case a in a) echo hi;; esac) y", "\""),
    ("cat <(case a in a) echo hi;; esac) y", ""),
]

N = [
    ("echo $(echo x) y", ""),
    ("echo $(echo case a in a) y", ""),
    ("echo $(: case a in a) y", ""),
    ("echo $(mycase a in a) y", ""),
    ("echo $(echo \"case\" a in a) y", ""),
    ("echo $(case a in a) :;; esac; echo b) y", ""),
    ("echo $(echo esac) y", ""),
    ("echo $( (echo a) ) y", ""),
]


def span_rows(rows, tag, qm=quote_mask):
    bad = []
    for t, closer in rows:
        if not bash_ok(t + closer):
            check(False, "%s oracle: the row is valid bash: %r" % (tag, t)); continue
        o = opening(t)
        want = bash_end(t, o, closer)
        got = [s["body"][1] for s in qm.substitutions(t) if s["open"] == o and s["kind"] != "arith"]
        lens = all(len(qm.mask_quoted(t, **cfg)) == len(t) for cfg in
                   ({}, {"fill": "\x01", "live": True}, {"fill": "x"}, {"quotes": "'", "keep": "`"}))
        ok = got == [want] and lens
        if not ok:
            bad.append(t)
        yield ok, "%s: span of %r ends at %s (bash), recorded %s; length holds %s" % (tag, t, want, got, lens)


for ok, label in span_rows(S, "S"):
    check(ok, label)
for ok, label in span_rows(N, "N"):
    check(ok, label)

# P: the readers.
from bash_parse import parse  # noqa: E402
t = "echo $(case a in a) echo hi;; esac) y"
top = [c for c in parse(t) if c.kw is None and c.pos == 0]
check(len(top) == 1 and [w[0] for w in top[0].words] == ["echo", "$(case a in a) echo hi;; esac)", "y"],
      "P parse: the substitution is one word of echo and y is its argument: %r"
      % ([[w[0] for w in c.words] for c in top],))
names = [c.name for c in parse(t) if c.kw is None]
check(names == ["echo", "echo"], "P parse: no command named y or esac is read: %r" % (names,))


def guard(cmd):
    p = subprocess.run(["bash", os.path.join(HOOKS, "block-unsafe-kill.sh")],
                       input=json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}}),
                       capture_output=True, text=True)
    return p.returncode


for cmd in [K + " $(case a in a) " + PG + " -f myserver;; esac)",
            K + " $(case a in a) true;; esac; " + PG + " -f myserver)",
            K + " $(case a in\n a) " + PG + " -f myserver\n ;;\nesac)",
            "P=$(case a in (a) " + PG + " -f myserver;; esac); " + K + " $P"]:
    check(guard(cmd) == 2, "P block-unsafe-kill denies %r" % cmd)
for cmd in ["echo $(case a in a) echo hi;; esac) y",
            K + " $(case a in a) echo 12345;; esac) 2>/dev/null || true"]:
    check(guard(cmd) == 0, "P block-unsafe-kill stays silent on %r" % cmd)

# M: the negatives can fail. A copy of the scanner that takes `case` for the keyword wherever it
# is a word must read at least one N row long.
src = open(os.path.join(HOOKS, "quote_mask.py")).read()
MARK = "cmdpos and w == \"case\""
if MARK in src:
    d = tempfile.mkdtemp(prefix="qm-case-mut-")
    with open(os.path.join(d, "quote_mask_mut.py"), "w") as f:
        f.write(src.replace(MARK, "w == \"case\""))
    sys.path.insert(0, d)
    import quote_mask_mut  # noqa: E402
    red = [label for ok, label in span_rows(N, "M", quote_mask_mut) if not ok]
    check(len(red) >= 1, "M a scanner that ignores command position reads %d N row(s) long" % len(red))
    shutil.rmtree(d, ignore_errors=True)
else:
    check(False, "M the command-position test (%s) is in quote_mask.py to mutate" % MARK)

print("%d failed" % len(FAILS))
sys.exit(1 if FAILS else 0)
