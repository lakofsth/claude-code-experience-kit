"""mh-a-words-value-is-bash-quote-removal, checked from the hooks/tests/INVARIANTS.md clause alone.

The sentence: hooks/bash_parse.py gives every word the value bash's quote removal gives it --
'...' literal, an unquoted backslash escaping any character, a backslash inside "..." or $"..."
escaping only $ ` " \\ and a newline, $'...' with its escapes decoded, and a command or process
substitution kept as the code it is -- so a string handed to eval, bash -c or any program that
runs it as code is read as the code bash runs.

THE ORACLE IS BASH. For every word W with no expansion in it, the value bash gives W is what
`printf '%s\\0' W` prints, run by bash itself (set -f, set +B, LC_ALL=C.UTF-8, an empty cwd), and
it is compared BYTE FOR BYTE with the value parse() gives the word in `printf X W`, with the
code parse() reads off `eval W`, and with the code it reads off `bash -c W`. Bash holds a value as
a C string, so a $'...' escape decoding to NUL ends the value there; a value carrying a NUL is not
the value bash gives the word. A word holding a substitution has no printf oracle (bash would
run it), so its value is stated: the word's quotes removed and the substitution's text kept
verbatim, through its closing `)` or backtick, as ONE word.

Directions, one per clause of the sentence:
  D1 '...' is literal                    D2 an unquoted backslash escapes any character
  D3 in "..." / $"..." a backslash escapes only $ ` " \\ newline
  D4 $'...' escapes decoded (named, octal, \\x, \\u, \\U, \\c, unknown, NUL, bytes)
  D5 the clauses mixed in one word       D6 a substitution kept as the code it is, one word
  D7 the code handed to eval and bash -c is the value bash hands them
Every case is printed on failure; the counts per direction are printed always (the controls).
"""
import os, random, re, subprocess, sys, tempfile
import bash_oracle  # noqa: E402  (a shell line runs where no host process is)

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from bash_parse import parse  # noqa: E402

ENV = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8")
CWD = tempfile.mkdtemp()
PRINTABLE = [chr(c) for c in range(0x20, 0x7f)]


def bash_value(word):
    p = bash_oracle.run(["bash", "--norc", "--noprofile", "-c", "set -f +B\nprintf '%s\\0' " + word],
                       cwd=CWD, env=ENV, capture_output=True)
    parts = p.stdout.split(b"\0")
    if p.returncode != 0 or len(parts) != 2 or parts[1] != b"":
        return None                    # not one word to bash: no oracle, case not used
    return parts[0]


def b(s):
    if s is None:
        return None
    try:
        return s.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return s.encode("utf-8", "surrogatepass")


def find(cmds, name):
    for c in cmds:
        if c.kw is None and c.pos == 0 and c.name == name:
            return c
    return None


def parsed(word):
    """{route: value} for the three readings of word."""
    out = {}
    try:
        c = find(parse("printf X " + word), "printf")
        out["word"] = b(c.words[2][1]) if c and len(c.words) == 3 else ("WORDS", c and c.words)
    except Exception as e:  # noqa: BLE001
        out["word"] = ("RAISED", repr(e))
    for route, text in (("eval", "eval " + word), ("bash -c", "bash -c " + word)):
        try:
            c = find(parse(text), "eval" if route == "eval" else "bash")
            out[route] = b(c.codes[0]) if c and len(c.codes) == 1 else ("CODES", c and c.codes)
        except Exception as e:  # noqa: BLE001
            out[route] = ("RAISED", repr(e))
    return out


cases = []  # (direction, word, expected bytes or None for the oracle)

# D1 -- every printable character but the quote, and the controls bash keeps literal, in '...'.
for ch in PRINTABLE + ["\t", "\n"]:
    if ch != "'":
        cases.append(("D1", "'a" + ch + "b'", None))
cases.append(("D1", "'" + "".join(c for c in PRINTABLE if c != "'") + "'", None))
cases.append(("D1", "''", None))

# D2 -- an unquoted backslash before every printable character, a tab, a newline, and at the end.
for ch in PRINTABLE + ["\t"]:
    cases.append(("D2", "a\\" + ch + "b", None))
cases.append(("D2", "a\\\nb", None))          # a line continuation inside a word
cases.append(("D2", "a\\", None))             # nothing to escape at the end of the text
cases.append(("D2", "\\\\\\\\x", None))

# D3 -- a backslash before every printable character, a tab and a newline, in "..." and $"...".
for open_ in ('"', '$"'):
    for ch in PRINTABLE + ["\t", "\n"]:
        cases.append(("D3", open_ + "a\\" + ch + "b\"", None))
    cases.append(("D3", open_ + "\\\\\\\"\\$\\`\"", None))
    cases.append(("D3", open_ + "it's $'x\\n'\"", None))

# D4 -- every escape $'...' decodes, and the ones it does not.
esc = [c for c in "abeEfnrtv\\'\"?"]
esc += ["0", "7", "07", "077", "101", "1011", "377", "400", "777", "8", "08", "18"]
esc += ["x", "x4", "x41", "x414", "xg", "xff", "xc3\\xa9", "xc3", "xe2\\x82\\xac", "x7f"]
esc += ["u", "u4", "u41", "u00e9", "u20ac", "u20ac0", "ud800", "ufffe", "U", "U41", "U0001F600",
        "U00110000", "UFFFFFFFF", "U000000e9e9"]
esc += ["c" + ch for ch in PRINTABLE if ch not in "'\\"] + ["c\\\\", "c\\\\x41"]
esc += [ch for ch in "dgijklmopqswyzABCDFGHIJKLMNOPQRSTVWXYZ%&()*+,-./:;<=>@[]^_{|}~ "]
esc += ["0", "00", "000", "x0", "x00", "u0", "u0000", "U00000000", "c@", "c`", "0a", "x0041"]
for e in esc:
    cases.append(("D4", "$'a\\" + e + "z'", None))
for e in ["0", "x00", "u0000", "c@"]:
    cases.append(("D4", "$'a\\" + e + "z'tail", None))   # the NUL ends the $'...' part only?
    cases.append(("D4", "pre$'\\" + e + "'\"q\"", None))

# D5 -- the clauses mixed in one word (fixed seed, so a red is reproducible).
parts = ["'s p'", "'\\'", '"d \\" q"', '"\\a\\$"', "$'\\x41\\t'", "$'\\''", '$"t\\`"', "\\ ",
         "\\'", '\\"', "x", "\\\\", "'\"'", '"\'"', "$'\\c?'", "$'\\101'"]
rnd = random.Random(20261029)
for _ in range(120):
    cases.append(("D5", "".join(rnd.choice(parts) for _ in range(rnd.randint(2, 5))), None))

# D6 -- a substitution kept as written, inside the one word it sits in (stated values).
D6 = [
    ("x$(echo a b)y", "x$(echo a b)y"),
    ('"x$(echo "a b")y"', 'x$(echo "a b")y'),
    ('"$(echo ")")"', '$(echo ")")'),
    ("\"$(echo 'a\"b')\"", "$(echo 'a\"b')"),
    ('"a\\$(echo b)c"', "a$(echo b)c"),          # escaped: no substitution, quote removal
    ('"a`echo b`c"', "a`echo b`c"),
    ("a`echo 'b c'`d", "a`echo 'b c'`d"),
    ('"a\\`echo b\\`c"', "a`echo b`c"),          # escaped backticks: literal
    ("<(cat 'f')", "<(cat 'f')"),
    (">(tee 'f g')", ">(tee 'f g')"),
    ("'$(echo a)'", "$(echo a)"),                # single-quoted: literal
    ("$'\\x24(echo a)'", "$(echo a)"),           # decoded from $'...': literal
    ('"$(printf %s \\"x\\")"', '$(printf %s \\"x\\")'),  # the body is code: its backslashes kept
    ("$(echo a)'b c'\"d\"", "$(echo a)b cd"),
    ('"k \\$(pgrep -f X)"', "k $(pgrep -f X)"),
]
for w, v in D6:
    cases.append(("D6", w, v.encode()))

# A stated value is only as good as its word: each D6 word must be bash syntax as the one argument
# of a command (`\$(echo a)` unquoted is not -- bash refuses the `(` -- and was struck for that).
bad_stated = []
for w, _ in D6:
    p = bash_oracle.run(["bash", "-n", "-c", "printf X " + w], cwd=CWD, env=ENV, capture_output=True)
    if p.returncode != 0:
        bad_stated.append("D6 word %r is not bash syntax: %s" % (w, p.stderr.decode().strip()))

# D7 -- every case above is also read through eval and bash -c (parsed() asks all three).

# D8 -- where a word ends is the other half of its value (`wp 'a'>b` is not the one word `a>b`,
# and `wp $((1+2)) z` is not cut at the `$`). A
# line `f TEXT` (or `TEXT f z`) glues words to redirection operators and expansions; bash's arguments to f are
# the oracle, and parse() must give f the same arguments (its words without the redirections) and
# read no other command. Where TEXT holds a `$`, bash's values are expansions, so only their count
# is compared.
REDIR_WORD = re.compile(r"^(?:(?:\d+|\{[A-Za-z_][A-Za-z0-9_]*\})(?!&))?"
                        r"(?:&>>|&>|<<<|<<-|<<|<>|<&|>&|>>|>\||<|>)(?!\()(.*)$", re.S)
open(os.path.join(CWD, "in"), "w").close()


def bash_argv(text):
    r, w = os.pipe()
    try:
        p = bash_oracle.run(["bash", "--norc", "--noprofile", "-c",
                             "exec 3>&%d >/dev/null\nset -f +B\nf() { printf '%%s\\0' \"$#\" \"$@\" >&3; }"
                             "\n%s" % (w, text)],
                            cwd=CWD, env=ENV, capture_output=True, pass_fds=(w,))
        os.close(w); w = -1
        out = os.read(r, 1 << 20)
    finally:
        os.close(r)
        if w >= 0:
            os.close(w)
    vals = out.split(b"\0")[:-1]
    if p.returncode != 0 or not vals or not vals[0].isdigit() or len(vals) != int(vals[0]) + 1:
        return None
    return vals[1:]


def parse_argv(text):
    # `echo` is the one command D8 writes inside a substitution, listed beside its host by design
    cmds = [c for c in parse(text) if c.kw is None and not (c.pos > 0 and c.name == "echo")]
    if len(cmds) != 1 or cmds[0].name != "f":
        return ("COMMANDS", [(c.name, [v for _, v in c.words]) for c in cmds])
    out, ws, k = [], cmds[0].words[1:], 0
    while k < len(ws):
        m = REDIR_WORD.match(ws[k][0])
        if m:
            k += 1 if m.group(1) else 2
            continue
        out.append(b(ws[k][1]))
        k += 1
    return out


D8 = []
for w in ["a", "'a'", '"a b"', "a\\ b", "$'a'", '$"a"', "12", "a2", '"2"', "\\2", "{fd}", "x{fd}",
          "a\\>b", "'a>b'"]:
    for op in [">o", ">>o", ">|o", "<in", "<>o", "<<<h", ">&2", "<&0", "&>o", "&>>o", ">o<in",
               "<<E\nbody\nE", " >o", "2>o"]:
        D8.append("f " + w + op + " z")
        D8.append(w + op + " f z")      # a leading redirection: f must still be the command
D8 += ["f " + t for t in ["$((1+2)) z", "a$((1>2))b z", "$(( 1 + 2 )) z", "$((1)) pkill -f X", "$(( $(echo 1) + 2 ))z y",
       "$((1|2)) z", "$((1&&2)) z", "$[1>2] z", "a$[1+2]b z", "${x:-a;b} z",
       "${x:-a>b} z", "${x:-a|b}c z", "x$((1))$((2))y z", "$$ z"]]

fails, counts, used, skipped = list(bad_stated), {}, 0, []
for d, w, want in cases:
    if want is None:
        want = bash_value(w)
        if want is None:
            skipped.append((d, w))
            continue
    used += 1
    got = parsed(w)
    for route, val in got.items():
        key = d if route == "word" else "D7"
        counts.setdefault(key, [0, 0])
        counts[key][0] += 1
        if val != want:
            counts[key][1] += 1
            fails.append("%s via %-7s word %r: bash gives %r, parse gives %r" % (d, route, w, want, val))

d8_checked = d8_red = 0
for text in D8:
    want = bash_argv(text)
    if want is None:
        skipped.append(("D8", text))
        continue
    used += 1
    got = parse_argv(text)
    d8_checked += 1
    ok = (got == want) if "$" not in text else (isinstance(got, list) and len(got) == len(want))
    if not ok:
        d8_red += 1
        fails.append("D8 f %r: bash gives %r, parse gives %r" % (text, want, got))

print("cases: %d built, %d with a value, %d with no oracle (not one word to bash)"
      % (len(cases), used, len(skipped)))
for d, w in skipped:
    print("  no oracle: %s %r" % (d, w))
for k in sorted(counts):
    print("  %s: %d checked, %d red" % (k, counts[k][0], counts[k][1]))
print("  D8: %d checked, %d red" % (d8_checked, d8_red))
if used == 0:
    print("FAIL: no case had a value -- the oracle ran nothing")
    sys.exit(1)
if fails:
    print("\nFAIL (%d)" % len(fails))
    for f in fails:
        print("  " + f)
    sys.exit(1)
print("\nOK: every word's value is bash's, as a word, through eval and through bash -c")
