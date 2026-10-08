#!/usr/bin/env python3
"""Regenerate tests/fixtures/bus/ from the REAL writer, `quintessence.busspool`.

WHY THE FIXTURES ARE GENERATED AND NOT TYPED. `session-presence` reads a format another repo
writes, and cannot import the module that writes it (see the bus section's own note: this is a
PreToolUse hook and its import list is stdlib only). A fixture spelled by hand would assert
against a format that may never have existed, and would agree with this repo's reader by
construction — which is the one thing it must not do. So the producer produces them.

The generator needs ~/quintessence on the path; the SUITE does not, which is the point:
the fixtures are committed, so the read direction is tested on any host, and only regeneration
needs the other repo.

    python3 tests/instruments/make-bus-fixtures.py [--engine ~/quintessence]

Recorded provenance is written to tests/fixtures/bus/PROVENANCE, and the suite prints it when
a conformance test fails, so a mismatch says which writer the fixtures came from rather than
leaving the next reader to guess.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "fixtures", "bus"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", default=os.path.expanduser(os.environ.get("QUINTESSENCE_SRC", "~/quintessence")))
    args = ap.parse_args()
    if not os.path.isdir(os.path.join(args.engine, "quintessence")):
        print(f"no quintessence package at {args.engine} (--engine to point elsewhere)")
        return 2
    sys.path.insert(0, args.engine)
    from quintessence import busspool

    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(os.path.join(OUT, "in"))
    os.makedirs(os.path.join(OUT, "out"))
    os.environ["QQ_BUS_DIR"] = OUT

    base = 1756300000.0
    cases = [
        ("a quote with its locator", {
            "to": "fair-kestrel", "kind": "note",
            "text": "poolside report the drafter at 2.81x on the same card",
            "origin": {"type": "quote", "locator": "https://example.invalid/rfc/24528#c17"}}),
        ("a synthesis with its sources", {
            "to": "fair-kestrel", "kind": "ask",
            "text": "six independent forks; one has a same-hardware benchmark. Worth measuring?",
            "origin": {"type": "synthesis",
                       "sources": ["https://example.invalid/rfc/24528",
                                   "https://example.invalid/fork/a",
                                   "https://example.invalid/fork/b",
                                   "https://example.invalid/fork/c"]}}),
        ("a pointer, broadcast", {
            "to": "*", "kind": "note", "text": "the thread that matters is #24528",
            "origin": {"type": "pointer", "locator": "https://example.invalid/rfc/24528"}}),
        ("a directive, which must point at a HEAD", {
            "to": "fair-kestrel", "kind": "note", "class": "directive",
            "ref": "hosted-session-inbox", "text": "the ruling is recorded there",
            "origin": {"type": "pointer", "locator": "qq:hosted-session-inbox"}}),
        ("a note for somebody else", {
            "to": "some-other-session", "kind": "note", "text": "not for you",
            "origin": {"type": "pointer", "locator": "https://example.invalid/x"}}),
        ("a peer announcing its handle", {
            "to": "*", "kind": "peer", "handle": "claude-ai/brisk-otter",
            "text": "hosted session claude-ai/brisk-otter is present",
            "origin": {"type": "pointer", "locator": "qq-bus-mcp/whoami"}}),
    ]
    written = []
    for i, (label, over) in enumerate(cases):
        note = {"v": busspool.SCHEMA_VERSION, "from": "claude-ai/brisk-otter",
                "class": "advisory"}
        note.update(over)
        mid = busspool.write_note("in", note, now=base + i)
        written.append((label, mid))

    rev = subprocess.run(["git", "-C", args.engine, "rev-parse", "--short", "HEAD"],
                         capture_output=True, text=True).stdout.strip() or "unknown"
    with open(os.path.join(OUT, "PROVENANCE"), "w") as f:
        f.write(f"written by quintessence.busspool at {args.engine} rev {rev}\n"
                f"schema v{busspool.SCHEMA_VERSION}; regenerate with "
                f"tests/instruments/make-bus-fixtures.py\n\n")
        for label, mid in written:
            f.write(f"{mid}  {label}\n")
    print(f"{len(written)} fixtures written to {OUT} from busspool at rev {rev}")
    for label, mid in written:
        print(f"  {mid}  {label}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
