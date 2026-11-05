#!/usr/bin/env python3
"""Every invariant id the kit cites resolves in hooks/tests/INVARIANTS.md, and the register holds
nothing the kit does not cite.

An id is an `mh-` word: `mh-` and hyphen-joined lowercase words, not itself followed by a hyphen or
a word character (so a fixture's name PREFIX such as `mh-bind-live-` is not one). Three test
fixtures carry the prefix and are not ids; the register's header declares them, and this check
holds that declaration to the tree too.

Checked over every file git tracks (the register included, since its entries cite each other):

  1. every id cited anywhere resolves to a `## `<id>`` heading of the register, or is a declared
     fixture name;
  2. every heading is cited from somewhere other than its own entry;
  3. no heading is stated twice;
  4. every declared fixture name occurs in the tree outside the register (a stale declaration
     would let a real id hide behind it).

The instrument proves it can fail before it is believed: the same check runs on two altered
copies of the tree held in memory — one with an id nobody defines added to a hook, one with a
cited heading removed from the register — and each must be reported, naming the id.
"""
import os, re, subprocess, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
REGISTER = "hooks/tests/INVARIANTS.md"
ID = re.compile(r"(?<![\w-])mh-[a-z0-9]+(?:-[a-z0-9]+)*(?![\w-])")
HEADING = re.compile(r"(?m)^## `(mh-[a-z0-9-]+)`\s*$")
FIXTURES_DECL = re.compile(r"(?m)^Fixture names, not ids: (.*)$")


def tracked_files():
    out = subprocess.run(["git", "-C", ROOT, "ls-files", "-z"], capture_output=True, check=True).stdout
    files = {}
    for rel in out.decode().split("\0"):
        if not rel:
            continue
        try:
            with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
                files[rel] = fh.read()
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue
    return files


def check(files):
    """(problems, cited ids, resolved ids) for a {path: text} tree."""
    problems = []
    reg = files.get(REGISTER, "")
    heads = HEADING.findall(reg)
    for h in sorted({h for h in heads if heads.count(h) > 1}):
        problems.append(f"heading stated twice: {h}")
    heads = set(heads)
    m = FIXTURES_DECL.search(reg)
    fixtures = set(re.findall(r"`(mh-[a-z0-9-]+)`", m.group(1))) if m else set()
    if not m:
        problems.append("the register declares no fixture names (line 'Fixture names, not ids: ...')")

    # the register's own entries, so a self-mention is not counted as a citation
    entries = {}
    for part in re.split(r"(?m)^(?=## )", reg):
        hm = HEADING.match(part)
        if hm:
            entries[hm.group(1)] = part

    cited, citers = set(), {}
    for path, text in files.items():
        if path == REGISTER:
            chunks = [(k, v) for k, v in entries.items()]
        else:
            chunks = [(None, text)]
        for owner, chunk in chunks:
            for tok in ID.findall(chunk):
                if tok in fixtures:
                    continue
                cited.add(tok)
                if tok != owner:
                    citers.setdefault(tok, set()).add(path if owner is None else f"{path}#{owner}")
    for tok in sorted(cited - heads):
        where = sorted(p for p, t in files.items() if re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(tok), t))
        problems.append(f"UNRESOLVED {tok}  (cited in {', '.join(where)})")
    for h in sorted(heads - set(citers)):
        problems.append(f"UNCITED heading {h}: nothing outside its own entry cites it")
    for f in sorted(fixtures):
        if not any(f in t for p, t in files.items() if p != REGISTER):
            problems.append(f"STALE fixture declaration {f}: no file outside the register uses it")
    return problems, cited, cited & heads


def main():
    files = tracked_files()
    if REGISTER not in files:
        print(f"FAIL: {REGISTER} is not tracked")
        return 1

    # positive controls first: an instrument that cannot report a miss proves nothing
    ok = True
    bogus = "mh-" + "an-id-this-register-does-not-define"   # built here, so this file cites nothing
    alt = dict(files)
    alt["hooks/block-unsafe-kill.sh"] = alt["hooks/block-unsafe-kill.sh"] + f"\n# see {bogus}\n"
    p, _, _ = check(alt)
    if any(bogus in x and x.startswith("UNRESOLVED") for x in p):
        print(f"  ok   control: an id nobody defines ({bogus}) is reported UNRESOLVED")
    else:
        ok = False
        print(f"  FAIL control: an added undefined id was not reported: {p}")
    _, cited0, _ = check(files)
    victims = sorted(cited0 & set(HEADING.findall(files[REGISTER])))
    if not victims:
        ok = False
        print("  FAIL control: the register holds no cited heading, so the removal control cannot run")
        p, victim = [], None
    else:
        victim = victims[0]
        alt = dict(files)
        alt[REGISTER] = alt[REGISTER].replace(f"## `{victim}`\n", "## (removed by the control)\n")
        p, _, _ = check(alt)
    if victim is None:
        pass
    elif any(victim in x and x.startswith("UNRESOLVED") for x in p):
        print(f"  ok   control: a cited heading removed from the register ({victim}) is reported UNRESOLVED")
    else:
        ok = False
        print(f"  FAIL control: a removed heading was not reported: {p}")

    problems, cited, resolved = check(files)
    heads = set(HEADING.findall(files[REGISTER]))
    print(f"  ids cited: {len(cited)}   resolved: {len(resolved)}   register headings: {len(heads)}")
    for x in problems:
        print("  FAIL " + x)
    if problems or not ok:
        print(f"FAIL ({len(problems)} problem(s){'' if ok else ', a control did not fire'})")
        return 1
    print(f"OK: {len(resolved)}/{len(cited)} cited ids resolve; every heading is cited; controls fire")
    return 0


if __name__ == "__main__":
    sys.exit(main())
