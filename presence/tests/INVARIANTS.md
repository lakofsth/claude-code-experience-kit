# Invariants — agent-presence

One sentence per invariant, the rule that derives every site it binds, and the test that
quantifies over that derivation. A fix diff is judged against this register before it is
priced. Entries are keyed by **subject**, not by a running integer: a number read off the
tail collides the moment a branch is a second writer.

## `name-uniqueness-among-the-reachable`

**No two sessions that a banner, a listing or a note can name at one instant share a display
name.** *Reachable* is the union of two sets, and the invariant binds both: session records
that still exist, and rows of `names.tsv` whose issue is younger than `NAME_COOLDOWN`.

- Site derivation: the `taken` map built in `assign_name()` — every source it unions is a
  site, enumerated from that function rather than hand-listed.
- Pin: `TestNames.test_a_live_session_keeps_its_name_when_the_mapping_is_lost`,
  `TestNames.test_a_cooled_name_returns_to_the_pool`,
  `TestNames.test_a_live_holder_keeps_its_name_however_old_the_row_is`.

## `dated-lookup-is-total`

**Every name ever issued still resolves to the session that held it, given the date.**
`names.tsv` is append-only and is never reaped; `agent-presence --names [NAME]` prints every
holder of a name with the date it was issued, oldest first.

This is the invariant that pays for reuse. It replaces the earlier, stronger claim that a
name is never reissued — a claim that cost the pool its whole 1024 names every two to five
days. What is guaranteed now is that (name, date) is unique, not that name alone is.

- Site derivation: every writer of `names_file()` — `assign_name()` is the only one — and
  every reader: `read_name_rows()` and its two derived views.
- Pin: `TestNames.test_the_mapping_is_listable_and_survives_reaping`,
  `TestNames.test_names_lookup_shows_every_holder_of_a_reused_name`,
  `TestNames.test_a_session_keeps_its_name_after_the_name_is_reissued`.

## `a-name-is-minted-only-for-a-session-that-acts`

**No name is allocated on the SessionStart path.** A session that registers and never takes a
tool call — `claude -p` one-shots, which were 87% of all records measured on 2026-08-26 —
consumes nothing from the pool.

- Site derivation: the callers of `assign_name()`; every one must be reachable only from a
  tool call or from an explicit operator request.
- Pin: `TestNames.test_registering_alone_mints_no_name`,
  `TestNames.test_the_first_tool_call_mints_the_name`.

## `a-suffix-means-the-pool-is-full`

**A numeric suffix (`amber-heron-2`) appears only after every one of `NAME_PROBES` rehashes
collided** — it is the loud form of pool exhaustion, not the ordinary outcome of two ids
hashing alike.

- Site derivation: the fallback arm of `assign_name()`'s probe loop; there is exactly one.
- Pin: `TestNames.test_a_contended_name_rehashes_rather_than_suffixing`,
  `TestNames.test_a_full_pool_falls_back_to_a_suffix`.

## `a-warning-reaches-the-population-it-is-about`

**Every warning is emitted on a hook event the sessions it is about actually reach.** Naming
the right audience is not the same as reaching it: a warning addressed to long-lived processes
cannot be armed at SessionStart, because a long-lived process reaches SessionStart only when it
is cleared, and the population that has been running longest is the population that has been
cleared least.

This was D284, filed 2026-08-19 and fixed 2026-08-26. The stale-build warning was emitted only
from `cmd_register`; measured four and a half hours after it shipped, its founding case
(`alice-1c`, running 2.1.220 against 2.1.226) had begun its conversation seven hours earlier
and could never have been told. It now fires from `cmd_pretool`, which is the event a live
session does reach, under its own cooldown.

- Site derivation: every call to `emit()`, and for each warning it carries, the population that
  warning is about versus the hook event it is armed on.
- Pin: `TestStaleBinaryWarning` in full — its `stale()` helper drives a tool call, so every
  case in the class asserts the delivery path — plus
  `TestStaleBinaryWarning.test_session_start_no_longer_carries_the_skew_warning`,
  `..._is_throttled_between_tool_calls`, `..._re_warns_when_a_new_version_is_installed`.

## `hooks-never-break-the-tool-call`

**No failure inside this program may change the outcome of the tool call it hooks.**
Pre-existing; stated here because it is the invariant every other one is subordinate to.

- Site derivation: every `HOOK_COMMANDS` entry, called through `main()`'s blanket handler.
- Pin: `TestHooksNeverBreakTheToolCall` (quantifies over `HOOK_COMMANDS`).

## `a-hosted-note-arrives-with-its-provenance-or-is-named-as-lacking-it`

**No hosted note is rendered to a session without a line saying where its content came from** —
and where that is absent or unrecognised, the note is labelled as unsourced rather than
rendered as though it had said.

*Instance that earned it:* the 2026-08-26/27 relay. A figure crossed from a claude.ai session
into a working record by hand and steered the next experiment; the source read afterwards found
two published figures for that quantity disagreeing by 2×. The number survived and its
provenance did not. A hosted note is the only note in this inbox whose sender cannot see this
machine, so what it carries is all the provenance a reader will ever get.

This binds the READ side deliberately. `agent-send` refuses to send one without an origin and
`quintessence.busspool` refuses to write one, but a record reaches a leg by other routes too —
a hand-edit, a peer on an older build, a future caller — and the reader is the last place that
can say so.

- Site derivation: `render_hosted_provenance`'s branches, one per member of the origin types
  the writer offers, plus the fall-through that names everything else malformed.
- Pin: `TestProvenanceReachesTheReader.*` in `tests/test-session-presence.py`.

## `a-hosted-note-is-taken-exactly-once`

**A hosted note is delivered to a session once, and a note minted in the same second as one
already taken is not lost.** Ids sort in mint order, so a watermark decides this in one
comparison — except within a single second, where ids order by their random half and a note
can sort below a watermark the session has already passed.

*Bounded deliberately:* the same-second set is not a history. An id below the watermark from an
earlier second is treated as already seen, because re-delivering a note is worse than missing a
straggler, and an unbounded set of seen ids is the growth this directory has twice paid for.

- Site derivation: `bus_new_for`'s two arms, and the single critical section in `bus_ingest`
  that writes the watermark in the same lock as the copy.
- Pin: `TestANoteIsTakenOnce.*` in `tests/test-session-presence.py`.

## `the-reader-and-the-writer-are-checked-against-each-other`

**`session-presence`'s bus reader and `quintessence.busspool` never import each other, and are
held together by fixtures the writer produced.** This program is a PreToolUse hook whose import
list is stdlib only; reaching into another repo's deploy tree would let a missing or
half-promoted checkout break every tool call on the host.

- Site derivation: `tests/fixtures/bus/`, regenerated by
  `tests/instruments/make-bus-fixtures.py` from the real writer; every field the reader consults
  is asserted present on every fixture.
- Pin: `TestTheReaderReadsWhatTheWriterWrote.*` (read direction — runs anywhere, fixtures are
  committed) and `TestWhatThisWritesIsWhatTheOtherSideAccepts.*` (write direction — needs the
  writer's repo and SKIPS with a reason when it is absent, rather than reporting coverage it
  does not have). The write leg carries a positive control, so a validator that had become a
  no-op is a failure rather than a pass.

## `a-peer-chosen-path-renders-on-one-line`

**Every path another session chose that is rendered into this session's context — a tree it
wrote in, its cwd — occupies one line and is bounded**, exactly as a note body is. The tree
is the peer's own Edit target after realpath, so a directory name is text the peer picked, and
a newline in it would render as a second, differently-labelled line outside the delivery
framing (the hole `one_line()` already closes for notes). Found by the security-posture review
of 2026-10-08.

- Site derivation: every f-string in a `render_*` function or a hook entry that interpolates a
  value read from a peer's record (`trees`, `cwd`) — `render_collision`, `cmd_register`,
  `cmd_list`; the bound is `MAX_PATH_RENDER`.
- Pin: `TestCollisionWarning.test_a_peer_chosen_path_renders_on_one_line`.

## `a-session-id-is-one-path-component`

**A session id from a hook payload is accepted only in a shape that is a single path
component** (`SID_SHAPE`: an alphanumeric, then up to 127 of `[A-Za-z0-9_-]`); any other
value is no id, and the hook is silent and touches nothing. The id names the record, the
touch lock and the inbox under the registry, and `end` unlinks the record by it: at the base,
`end` with `"../sessions/bbb"` unlinked another session's record. Found by the
security-posture review of 2026-10-08.

- Site derivation: every reader of `payload["session_id"]` — `payload_sid()` is the only one,
  and the three hook entries call it.
- Pin: `TestHooksNeverBreakTheToolCall.test_a_session_id_that_is_not_a_path_component_is_ignored`.

## `a-names-row-is-one-line-of-four-fields`

**Every row `assign_name()` appends to `names.tsv` is one line of four tab-separated fields,
whatever the peer-chosen cwd contains.** The cwd comes from the hook payload — text the peer
picked, like its session id and its trees — and the file is the authority for "which session
holds this name": at the base a cwd of `"/x\nevil-name\tvictim\t0\t/z"` appended a second row
that `--names` then listed as `evil-name` held by `victim`. The cwd is written through
`one_line(…, MAX_PATH_RENDER)`, which collapses every whitespace run including tabs and
newlines, so a payload field can describe a row but never write one. Found by the
security-posture review of 2026-10-08 (recorded then as a row-fusing nit; it is a forge).

- Site derivation: every writer of `names_file()` — `assign_name()` is the only one, and the
  cwd is the only field of its row that a payload supplies verbatim (the name is from the word
  lists, the sid has passed `SID_SHAPE`, the stamp is an int).
- Pin: `TestNames.test_a_peer_chosen_cwd_cannot_forge_a_names_row`.

## `an-empty-address-is-not-a-broadcast`

**`agent-send` with an empty-string address is the usage error, not a send to every live
session.** Prefix matching is how an address resolves, and the empty string is a prefix of every
name and every id; the explicit `--all` is the only broadcast. Held at the base (the
security-posture review of 2026-10-08 recorded it as open; re-tested 2026-10-09 it did not
reproduce), pinned so that a later `is not None` guard cannot reopen it — that one-token change
delivered to every live session under the pin.

- Site derivation: the address branch of `cmd_send()` — the one site that resolves a bare
  token to recipients.
- Pin: `TestNotes.test_an_empty_address_is_a_usage_error_not_a_broadcast`.

## `no-case-depends-on-the-host-claude-code`

**No case's outcome depends on which Claude Code this host has installed**: the suite's
default PATH holds an interpreter and nothing else, and a case about version skew puts a fake
install on PATH itself. This suite learned it from a host upgrade that turned a fixture version
into a "stale process" mid-run and failed a names case; the pin below is what makes the
property held by construction rather than by every version case remembering to set PATH.

- Site derivation: `Base.env()` — the one place the subject's environment is built; the
  cases that need a host binary (`head` in the closed-pipe case) put the host PATH back
  by name.
- Pin: `TestStaleBinaryWarning.test_the_default_environment_hides_the_hosts_claude_code` —
  a newer fake install on the test process's own PATH, a stale-looking session, the plain
  `env()`: no warning. Dropping the PATH line in `env()` turns it red.
