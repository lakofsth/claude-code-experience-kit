# Invariants — agent-presence

One sentence per invariant, the rule that derives every site it binds, and the test that
quantifies over that derivation. Entries are keyed by **subject**, not by a running integer: a number read off the
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

This is the invariant that pays for reuse: a name is reissued once it has cooled, so what is
guaranteed is that (name, date) is unique, not that name alone is.

- Site derivation: every writer of `names_file()` — `assign_name()` is the only one — and
  every reader: `read_name_rows()` and its two derived views.
- Pin: `TestNames.test_the_mapping_is_listable_and_survives_reaping`,
  `TestNames.test_names_lookup_shows_every_holder_of_a_reused_name`,
  `TestNames.test_a_session_keeps_its_name_after_the_name_is_reissued`.

## `a-name-is-minted-only-for-a-session-that-acts`

**No name is allocated on the SessionStart path.** A session that registers and never takes a
tool call — `claude -p` one-shots, most of all registrations — consumes nothing from the
pool.

- Site derivation: the callers of `assign_name()`; every one must be reachable only from a
  tool call or from an explicit request. The second is `claim-name`, which claude-launch calls for an INTERACTIVE session it is starting; a `-p`
  one-shot passes the launcher untouched and mints nothing (pinned below by
  `TestLaunchedName.test_everything_else_passes_through_unnamed`).
- Pin: `TestNames.test_registering_alone_mints_no_name`,
  `TestNames.test_the_first_tool_call_mints_the_name`.

## `a-suffix-means-the-pool-is-full`

**A numeric suffix (`plain-lark-2`) appears only after every one of `NAME_PROBES` rehashes
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

Ledger D284: emitted from `cmd_register`, the stale-build warning would never reach a session
that has been in one conversation since before the upgrade. It fires from `cmd_pretool`, which
is the event a live session does reach, under its own cooldown.

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

A figure relayed without its provenance cannot be checked against its source. A hosted note is
the only note in this inbox whose sender cannot see this machine, so what it carries is all the
provenance a reader will ever get.

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
straggler, and an unbounded set of seen ids is growth nothing sweeps.

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
wrote in, its cwd — and every other field of its record printed beside it (its model, its id,
a hosted peer's handle), occupies one line and is bounded**, exactly as a note body is. The tree
is the peer's own Edit target after realpath, so a directory name is text the peer picked, and
a newline in it would render as a second, differently-labelled line outside the delivery
framing (the hole `one_line()` already closes for notes).

- Site derivation: every f-string in a `render_*` function or a hook entry that interpolates a
  value read from a peer's record (`trees`, `cwd`, `model`, `session_id`) or a hosted peer's
  bus record (`handle`) — `render_collision`, `cmd_register`, `cmd_list`,
  `render_hosted_peers`; paths are bounded by `MAX_PATH_RENDER`. Names reach these sites
  already flattened (`name_for`, `messaging_names`).
- Pin: `TestCollisionWarning.test_a_peer_chosen_path_renders_on_one_line` (collision warning,
  register banner and listing; tree, cwd and model). The hosted handle is flattened unpinned.

## `a-session-id-is-one-path-component`

**A session id from a hook payload is accepted only in a shape that is a single path
component** (`SID_SHAPE`: an alphanumeric, then up to 127 of `[A-Za-z0-9_-]`); any other
value is no id, and the hook is silent and touches nothing. The id names the record, the
touch lock and the inbox under the registry, and `end` unlinks the record by it: otherwise
`end` with `"../sessions/bbb"` would unlink another session's record.

- Site derivation: every reader of `payload["session_id"]` — `payload_sid()` is the only one,
  and the three hook entries call it.
- Pin: `TestHooksNeverBreakTheToolCall.test_a_session_id_that_is_not_a_path_component_is_ignored`.

## `a-names-row-is-one-line-of-four-fields`

**Every row `assign_name()` appends to `names.tsv` is one line of four tab-separated fields,
whatever the peer-chosen cwd contains.** The cwd comes from the hook payload — text the peer
picked, like its session id and its trees — and the file is the authority for "which session
holds this name": written raw, a cwd of `"/x\nevil-name\tvictim\t0\t/z"` would append a second
row that `--names` would list as `evil-name` held by `victim`. The cwd is written through
`one_line(…, MAX_PATH_RENDER)`, which collapses every whitespace run including tabs and
newlines, so a payload field can describe a row but never write one.

- Site derivation: every writer of `names_file()` — `assign_name()` is the only one, and the
  cwd is the only field of its row that a payload supplies verbatim (the name is from the word
  lists, the sid has passed `SID_SHAPE`, the stamp is an int).
- Pin: `TestNames.test_a_peer_chosen_cwd_cannot_forge_a_names_row`.

## `an-empty-address-is-not-a-broadcast`

**`agent-send` with an empty-string address is the usage error, not a send to every live
session.** Prefix matching is how an address resolves, and the empty string is a prefix of every
name and every id; the explicit `--all` is the only broadcast. Pinned so that an `is not None`
guard cannot open it — that one-token change would deliver to every live session.

- Site derivation: the address branch of `cmd_send()` — the one site that resolves a bare
  token to recipients.
- Pin: `TestNotes.test_an_empty_address_is_a_usage_error_not_a_broadcast`.

## `no-case-depends-on-the-host-claude-code`

**No case's outcome depends on which Claude Code this host has installed**: the suite's
default PATH holds an interpreter and nothing else, and a case about version skew puts a fake
install on PATH itself, so a host upgrade cannot turn a fixture version into a "stale process"
and fail a names case; the pin below is what makes the property held by construction rather than by every version case remembering to set PATH.

- Site derivation: `Base.env()` — the one place the subject's environment is built; the
  cases that need a host binary (`head` in the closed-pipe case) put the host PATH back
  by name.
- Pin: `TestStaleBinaryWarning.test_the_default_environment_hides_the_hosts_claude_code` —
  a newer fake install on the test process's own PATH, a stale-looking session, the plain
  `env()`: no warning. Dropping the PATH line in `env()` turns it red.

## `messaging-names-docstring-names-the-consumed-fields`

**`messaging_names()`'s docstring names every field of the harness's session record the function reads,
and says which of them empty the map.** Six are consumed: `sessionId`, `name`, `pid`, `procStart`,
`messagingSocketPath`, `version`. A harness release that renames `sessionId`, `name` or `pid` silently
drops every peer's messaging label from the injection (ledger D283).

- Site derivation: the `rec.get(...)` reads in `messaging_names()` and in `process_alive()`.
- Pin: `TestMessagingNameJoin.test_the_consumed_fields_are_the_documented_ones` — the docstring
  contains all six names, and renaming each of `sessionId`/`name`/`pid` in a fixture registry
  removes the label while renaming `messagingSocketPath`/`version` does not.

## `a-launched-session-answers-to-its-presence-name`

**An interactive session started through claude-launch is given, as Claude Code's `--name`, the
name this registry issues its session id**, so the name a peer note is signed with is also an
address Claude Code's SendMessage resolves. Everything the launcher does not start fresh (a
`-p`/`--print` one-shot, a resume or continue, an explicit `--session-id` or `--name`, a
subcommand) passes through with its arguments unchanged and no name issued. Without it a reply
to `plain-lark` fails ("No agent named 'plain-lark' is reachable") when that session answers
SendMessage only as `alice-09`.

- Site derivation: claude-launch's one `exec` that adds `--name`, and `cmd_claim_name()`, the
  one CLI caller of `assign_name()`.
- Pin: `TestLaunchedName.test_a_fresh_interactive_launch_is_named_as_presence_names_it`,
  `TestLaunchedName.test_claim_name_issues_the_name_the_first_tool_call_keeps`,
  `TestLaunchedName.test_everything_else_passes_through_unnamed`. Each turns red under its
  mutation: the launcher's exec without `--name`, `claim-name` printing `derive_name()` without
  recording, `-p|--print` dropped from the pass-through list.

## `a-cleared-session-keeps-its-launched-name`

**A session id whose live Claude Code process answers to a presence name (adjective-noun from
this registry's word lists, `-N` allowed) is issued that name, not a fresh one.** `/clear` gives
the same process a new session id and Claude Code keeps the `--name` claude-launch gave it, so
minting afresh
would split the two registries again. A name two live processes share is blanked by
`messaging_names()` and is never adopted; a Claude Code derived name (`alice-84`) is never
adopted.

- Site derivation: the adoption arm of `assign_name()`, its one reader of `messaging_names()`.
- Pin: `TestLaunchedName.test_a_cleared_session_keeps_its_launched_name`,
  `TestLaunchedName.test_a_derived_claude_code_name_is_never_adopted`; red with the adoption
  arm disabled, and with the word-list check dropped from `is_presence_name()`.


## `owner-is-the-running-session-that-last-wrote-there`

**`--owner <path>` names the session whose process is still running and that wrote at or
under `<path>` within `OWNER_WINDOW` (6 h; `--within` overrides) when it is the ONLY such
session, as one line `<session-id>\t<presence-name>\t<messaging-name or ->`; no such session,
or two or more, is exit 0 with no bytes on stdout (two or more also name themselves on stderr),
and a missing path is exit 2.** "Running" is the harness's own process record
(`messaging_names()`, pid + procStart), so a session idle at a prompt still owns its work;
presence's LIVE_WINDOW stands in only where the harness has no records at all. It answers under
every invocation name, because a dispatcher that hands work to the session already in a repo
calls it as `~/bin/agent-presence`, whose name otherwise dispatches to the listing and exit 0.

Amended 2026-11-04: not "the latest running writer". In a repo two running sessions both write
in, that answer flips with each save and each session asks separately, so A would be told the
work was held for B and later B that it was held for A — neither would be shown it. Ownership is
claimed only when it is unambiguous; an ambiguous repo has no owner, so the dispatcher offers the
work to every session. The slug keeps its old words because other records cite it.

- Site derivation: the one reader of `trees` for ownership is `writers_in()`; its callers are
  `owner_of()` (the decision) and `cmd_owner()` (the stderr naming of an ambiguous set), and
  `owner_of()`'s caller is `cmd_owner()` alone, reached from `main()` and `cmd_list()`.
- Named residual: a write in a git worktree outside the repo's own directory is recorded under the
  worktree's own toplevel, not the repo's, so it does not make its author the owner of `<repo>`.
  Reopen when a repo is routinely worked only from worktrees.
- Pin: `TestOwner` (six cases); mutations — harness liveness replaced, window removed, the `/`
  of the under-the-path test dropped, the any-name dispatch removed, and `owner_of()` returning
  the latest of several writers instead of only a sole one — each turn at least one case red
  (`test_two_running_writers_make_no_owner_whichever_saved_last` for the last).

## `claude-launch-waits-out-a-missing-binary`

**claude-launch, finding no `claude` on PATH but itself, re-scans PATH every 0.5 s for up to
`CLAUDE_LAUNCH_WAIT` seconds (default 15), saying once on stderr that it is waiting, and execs the
binary that appears; only when none appears does it exit 127.**

- Why: while npm reinstalls Claude Code it removes the package directory before it writes the
  new one, so the binary every `claude` on PATH links to is absent for a few seconds, and a
  launch in that window would find nothing and exit 127.
- Site derivation: the launcher's one lookup of the real binary, `find_real()`, the only reader
  of PATH in `claude-launch`; `CLAUDE_LAUNCH_REAL` (the suite's seam) bypasses it and is not waited on.
- Check: `presence/tests/test-claude-launch-waits.py` — a binary appearing 1.5 s in is
  exec'd; none at all exits 127 after the 2 s wait; one present from the start is exec'd at once
  with nothing said (control). Rows 1 and 2 are red with the re-scan loop replaced by
  `while false`.
- Stated limit: an update that takes longer than the wait still ends in 127.
