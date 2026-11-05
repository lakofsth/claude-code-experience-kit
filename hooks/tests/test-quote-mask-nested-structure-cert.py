"""Check of `mh-the-mask-reads-code-in-double-quotes-whatever-it-shows`, written from the sentence.

The sentence: hooks/quote_mask.py reads the same structure -- every quote span, comment,
heredoc and substitution -- inside a $(...) or backtick within "...", and inside an unquoted
heredoc body, whatever its live, quotes and fill arguments, so heredocs() (from which
hooks/bash_parse.py code_heredocs() names the bodies fed to a shell) finds every heredoc parse()
reads, and a quote inside such a heredoc body never closes the enclosing "..." at any site of
the mask.

Its directions, each a row below:
  1. the STRUCTURE read inside "$(...)" / "`...`" / an unquoted heredoc body's substitution does
     not depend on (live, quotes, fill): a quote, a comment or a heredoc there is read as bash
     reads it at EVERY combination, so the code after the construct (`pkill -f SENTINEL`, outside
     every quote) shows in the mask at every combination;
  2. heredocs() finds a heredoc nested in "$(...)", in "`...`", and in a substitution inside an
     unquoted heredoc body -- every heredoc parse() reads -- and so code_heredocs() names the one
     fed to a shell, and parse() reads its body as code;
  3. a quote inside a heredoc body nested in "$(...)" never closes the enclosing "...": not in
     mask_quoted at any combination, not in heredocs(), not in continuations() (every site).
Every probe is valid bash and runs as described (the SENTINEL line runs after the construct).
"""
import itertools, os, sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "hooks"))
import quote_mask  # noqa: E402
import bash_parse  # noqa: E402

LIVE = (False, True)
QUOTES = ("'\"", "'", '"', "")
FILLS = (" ", "\x01")
COMBOS = list(itertools.product(LIVE, QUOTES, FILLS))
TAIL = " ; pkill -f SENTINEL\n"

# (name, text before TAIL). Each construct holds a quote that, read as a plain "..." would read
# it, closes the enclosing "..." early or opens a span bash never opens.
STRUCT = [
    ("quote in $() in \"\"", 'echo "$(echo "it\'s")"'),
    ("quote in backtick in \"\"", 'echo "`echo "it\'s"`"'),
    ("comment in $() in \"\"", 'echo "$(echo x # it\'s\n)"'),
    ("comment in backtick in \"\"", 'echo "`echo x # it\'s\n`"'),
    ("heredoc w/ quote in body, in $() in \"\"", 'echo "$(cat <<EOF\nit\'s "quoted\nEOF\n)"'),
    ("quoted-delim heredoc w/ quote, in $() in \"\"", 'echo "$(cat <<\'EOF\'\nit"s\nEOF\n)"'),
    ("$() in $() in \"\"", 'echo "$(echo "$(echo "it\'s")")"'),
    ("quote in $() in unquoted heredoc body", 'cat <<EOF\n$(echo "it\'s")\nEOF\necho x'),
    ("heredoc w/ quote in $() in unquoted heredoc body",
     'cat <<EOF\n$(cat <<X\nit\'s "q\nX\n)\nEOF\necho x'),
]

# (name, text, the delimiter of the nested heredoc fed to a shell)
NESTED = [
    ("bash heredoc in $() in \"\"", 'x="$(bash <<EOF\npkill -f SENTINEL\nEOF\n)"\n', "EOF"),
    ("bash heredoc in backtick in \"\"", 'x="`bash <<EOF\npkill -f SENTINEL\nEOF\n`"\n', "EOF"),
    ("bash heredoc in $() in unquoted heredoc body",
     'cat <<EOF\n$(bash <<X\npkill -f SENTINEL\nX\n)\nEOF\n', "X"),
]

fails = []


def check(cond, msg):
    print("  %s %s" % ("ok  " if cond else "FAIL", msg))
    if not cond:
        fails.append(msg)


print("direction 1/3: the code after each construct shows in the mask at all %d (live, quotes, "
      "fill) combinations" % len(COMBOS))
for name, pre in STRUCT:
    t = pre + TAIL
    sent = t.index("pkill -f SENTINEL")
    bad = []
    for live, quotes, fill in COMBOS:
        try:
            m = quote_mask.mask_quoted(t, quotes=quotes, fill=fill, live=live)
        except Exception as e:  # a crash is no reading at all
            bad.append("live=%s quotes=%r fill=%r: raised %r" % (live, quotes, fill, e))
            continue
        if len(m) != len(t):
            bad.append("live=%s quotes=%r fill=%r: length %d != %d" % (live, quotes, fill, len(m), len(t)))
        elif m[sent:sent + 17] != "pkill -f SENTINEL":
            bad.append("live=%s quotes=%r fill=%r: tail masked as %r" % (live, quotes, fill, m[sent:sent + 17]))
    check(not bad, "%s: %r%s" % (name, t, "" if not bad else "\n        " + "\n        ".join(bad)))

print("direction 1/3 (heredocs/continuations sites): no construct above leaves a heredoc open "
      "over the tail, nor reports a continuation where bash has none")
for name, pre in STRUCT:
    t = pre + TAIL
    sent = t.index("pkill -f SENTINEL")
    hds = quote_mask.heredocs(t)
    over = [h for h in hds if h["body"][0] <= sent < max(h["body"][1], h["end"])]
    check(not over, "%s: heredocs() bodies %r do not cover the tail" % (name, [h["body"] for h in hds]))
    check(quote_mask.continuations(t) == [], "%s: continuations() is [] (got %r)"
          % (name, quote_mask.continuations(t)))

print("direction 2/3: heredocs() finds every heredoc parse() reads, so the one fed to a shell is code")
for name, t, delim in NESTED:
    hds = quote_mask.heredocs(t)
    found = [h for h in hds if h["delim"] == delim]
    check(len(found) == 1, "%s: heredocs() finds the nested <<%s (got delims %r)"
          % (name, delim, [h["delim"] for h in hds]))
    body_at = t.index("pkill -f SENTINEL")
    names = bash_parse.code_heredocs(t)
    check(body_at in names, "%s: code_heredocs() names the body at %d (got %r)" % (name, body_at, names))
    cmds = [c.name for c in bash_parse.parse(t) if c.kw is None]
    check("pkill" in cmds, "%s: parse() reads the body's pkill as a command (got %r)" % (name, cmds))

print("direction 3/3: a quote in a heredoc body inside \"$(...)\" never closes the enclosing \"...\"")
t = 'echo "$(cat <<EOF\nsay "hi\nEOF\n)" ; pkill -f SENTINEL\n'
hds = quote_mask.heredocs(t)
check([h["delim"] for h in hds] == ["EOF"], "heredocs() reads the one heredoc, <<EOF (got %r)"
      % [h["delim"] for h in hds])
sent = t.index("pkill -f SENTINEL")
for live, quotes, fill in COMBOS:
    m = quote_mask.mask_quoted(t, quotes=quotes, fill=fill, live=live)
    if m[sent:sent + 17] != "pkill -f SENTINEL":
        check(False, "live=%s quotes=%r fill=%r: tail masked (%r)" % (live, quotes, fill, m[sent:sent + 17]))
        break
else:
    check(True, "the tail shows at every combination")

print("%d row(s) red" % len(fails) if fails else "all rows green")
sys.exit(1 if fails else 0)
