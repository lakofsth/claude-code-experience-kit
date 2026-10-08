# Claude Code Experience Kit

A grab-bag of small, harness-level customizations that noticeably improve day-to-day work
with an LLM coding agent — the pieces that aren't about *what* the agent knows but about
*how the session feels to run*, for both parties.

The organizing idea has shifted since this kit's first edition. The original premise was
**externalize the dials for the human**: the model can't see its own context fill, so put a
gauge on screen and let a person decide when to tell it to wrap up. That statusline is still
here (§1) — but the newer pieces close the loop on the agent's side: inject the same gauges
**into the model's context** (§2), keep its clock and gauges live across background re-wakes
(§3), and make the usage windows themselves start at predictable times (§4). An agent that
can see its own quota, burn rate, and wall-clock plans its work differently — it wraps up,
checkpoints, and paces itself without being told. The newest piece (§11) extends that outward:
several sessions running on one host can now see *each other*.

Everything here is **independent** — adopt any subset. Each section says what it does, *why*
it helps, and what to change for your setup. All personal specifics (timezones, hostnames, a
particular continuity store) are abstracted out; the hook scripts live in `hooks/`, the
systemd units in `anchors/`.

> **Deliberately excluded:** session-continuity machinery (a store of durable working state
> that outlives the session). These pieces stand on their own without it. A few have a
> natural "checkpoint your work before context runs out" seam where such a store *would*
> plug in — those spots are marked, with a store-free default.

---

## At a glance

| # | Piece | What it fixes | Surface |
|---|-------|---------------|---------|
| 1 | Statusline gauges | Human can't see context fill / quota / burn | `statusLine` + `hooks/statusline.sh` |
| 2 | Budget gauges → the agent | *Agent* can't see its own quota or burn rate | `UserPromptSubmit` + `hooks/inject-gauges.sh` |
| 3 | Live-clock heartbeat | Injected time/gauges freeze on non-prompt wakes; silent model swaps | `PreToolUse` + `hooks/pretool-clock.sh` |
| 4 | Usage-window anchors | 5h windows start at arbitrary times | systemd timer, `anchors/` |
| 5 | Standing per-turn pushes | Principles age out of long sessions | `UserPromptSubmit` + `hooks/agent-pushes.sh` |
| 6 | Session breadcrumb log | "Which transcript was that?" amnesia | `SessionEnd`/`PreCompact` hooks |
| 7 | Self-kill guard | `pkill -f` kills the agent's own session | `PreToolUse` + `hooks/block-unsafe-kill.sh` |
| 8 | Backtick-prose notice | Shell executes backticks inside prose writes | `PreToolUse` + `hooks/backtick-prose-warn.sh` |
| 9 | Cycle-mode keybinding | Terminals that can't send `Shift+Tab` | `keybindings.json` |
| 10 | Color & QoL settings | Washed-out output, stale gauges, no nudges | `settings.json` |
| 11 | Peer presence + note inbox | Concurrent sessions collide unseen on one host | `presence/` + `SessionStart`/`PreToolUse`/`SessionEnd` |

---

## 1. Statusline gauges (the human's dial)

**What it shows:** context-fill % (green <70%, yellow ≥70%, bold-red ≥90%) · time-left and
% consumed on the 5-hour usage window · **the session's presence name (§11), or a burn-rate
readout (written by §2) when there is no name** · dir (branch) · model.

`settings.json`:

```json
{
  "statusLine": { "type": "command", "command": "~/.claude/statusline.sh", "refreshInterval": 60 }
}
```

Script: `hooks/statusline.sh`. Input is JSON on stdin — fields:
<https://code.claude.com/docs/en/statusline>. `refreshInterval: 60` matters: it keeps the
usage-window countdown ticking between messages.

One slot, two tenants. If the presence registry (§11) has a name for this session, the name
takes that slot: with several windows open, *which session this is* matters more to a person
than tokens-per-percent, and it is what every other presence surface already says. The lookup
is one `awk` over `~/.local/state/claude-sessions/names.tsv` and it is fail-open — no presence
installed, no file, or a session that has not registered yet, and you get the burn readout
exactly as before. **Install nothing from §11 and this section is unchanged.** Nothing is lost
to the model either way: §2 injects the burndown into its context every turn regardless of
what the status line shows. `hooks/tests/test-statusline-name-slot.sh` drives all the branches
under a throwaway `HOME`.

Beyond displaying, the script **persists** the gauges to `~/.claude/.gauges.<session_id>`
every refresh — that file is what lets §2 and §3 hand the same numbers to the model. (Keyed
per session: a shared file gets clobbered across concurrent sessions. The `-` sentinel for
an empty field is load-bearing — without it an unset middle field collapses under `read` and
shifts the reset epoch into the percentage slot.)

## 2. Budget gauges → the agent  *(the piece that changes behavior most)*

**The problem.** The model has no introspective access to its context fill, its usage-window
consumption, or how fast it is burning either. It plans a deep task the same way at 5% quota
as at 95%.

**The fix:** `hooks/inject-gauges.sh` on `UserPromptSubmit` injects one line per turn:

```
Budget gauges (live): context-window 34% full; 5h-usage 62% used (5h resets 18:00 EEST) — burndown: fit 210k(w)/% -> ~14 turns to cap (n=9)
```

- **Gauges** come from the hook's own stdin JSON when present (freshest), falling back to
  the §1 statusline's persisted file.
- **Burn rate is self-calibrating**: each turn the hook logs the transcript's cumulative
  token components (input, output, cache-create, cache-read) against the harness-reported
  usage %, isolates the current 5h window (the trailing run where the meter is
  non-decreasing), and fits realized weighted-tokens-per-percent directly — no assumption
  about the provider's rate-limit weighting formula survives contact with reality, so the
  raw components are logged too and the prior can be re-fit. From the fit it projects
  **turns to cap** at the current pace.
- A percentage is validated to [0,100] before use; the one malformed value that actually
  shows up in practice is epoch-shaped (a reset timestamp shifted into the wrong slot by an
  old-format gauges file), and recognizing that shape is the diagnostic.

The same fit writes a compact `210k/% ~14t` status to `~/.claude/.burndown-status.<session_id>`
for §1's statusline, so both parties read one calibration. §1 displays it whenever the shared
slot is free — that is, unless §11 is installed and has named the session; the injected line
above carries the same fit to the model in either case.

## 3. Live-clock heartbeat (and "who is serving me?")

**The problem.** Everything injected at `UserPromptSubmit` is stamped once, when a human
submits. But turns are routinely re-woken *without* a prompt — a background task completes,
a dormant session resumes hours later — and the model then reasons from a frozen clock and
frozen gauges. Observed: one turn spanned 15:03→21:43 while the injected time still read
15:03. Separately, a session can be **moved to a different model between turns** with
nothing in context saying so; it goes on stamping records with the tier it started as.

**The fix:** `hooks/pretool-clock.sh` on `PreToolUse` (empty matcher = every tool). It fires
on the model's first action after *any* wake, throttled to once per 5 minutes so tool-call
bursts stay quiet — silent when fresh, speaks exactly when time jumped:

```
⏱ Live now: 21:43 EEST, Sun 13 Jul · gauges ctx 34% / 5h 62% · serving: claude-opus-5. (Refreshed on tool use — …)
```

It also reads the newest `message.model` from the session's own transcript and, on a
confirmed change, bypasses the throttle to say loudly which model is serving now (a
placeholder `<synthetic>` record written during the swap itself is treated as unknown, not
as a model — else one swap becomes two alerts). The hook injects `additionalContext` only —
never a `permissionDecision` — so permission flow is untouched, and it fails silent.

## 4. Usage-window anchors

**The problem.** A 5-hour usage window opens at your first message and resets five hours
later — so reset times wander with your day, and a late-evening session can open a window
whose reset lands mid-morning tomorrow, eating the fresh window you wanted at breakfast.

**The fix:** spend a few tokens on a schedule purely to *open* windows at chosen times.
`anchors/session-anchor.sh` sends a single `.` prompt on Haiku (minimal tokens by design);
`anchors/claude-anchor-hourly.timer` fires it **every hour except a quiet zone** (set to
your sleep hours). An hourly ping no-ops into any already-open window and opens one on the
hour into silence — stateless, self-healing: whatever drift the day accumulates, the chain
re-locks to an on-the-hour grid after the quiet gap. Your 5h windows then tile the day
predictably, and §2's "resets at" line becomes something the agent can actually plan
against.

Install: edit user/timezone in the three files, then
`session-anchor.sh → ~/.claude/`, units → `/etc/systemd/system/`,
`systemctl enable --now claude-anchor-hourly.timer`. `Persistent=false` is deliberate:
never catch up a missed fire — a stale anchor at the wrong minute is worse than none.

## 5. Standing per-turn pushes

**The problem.** Operating principles in `CLAUDE.md` are loaded once and slowly age out of
attention over a multi-hour session.

**The fix:** `hooks/agent-pushes.sh` on `UserPromptSubmit` re-injects a small set every
turn. Shipped set (each a no-op when not relevant):

- **Local time + log-timezone rule** — the human's live wall-clock, plus "machine logs may
  be UTC; convert and label." (§3 keeps this honest between prompts.)
- **Grounding counterweight** — verify claims at source before asserting them; when
  challenged, re-check before explaining; and treat a *negative* ("not present", "disabled",
  "no matches") as a claim that needs its instrument checked — would it have shown the thing
  if present? The convenient negative earns a second check, not a first one.
- **Closure check** — a self-qualified result ("should work", "probably fine") is a signal
  to interrogate now, not a landing.
- **Self-parallelize** — if background jobs are in flight, advance an independent thread
  instead of idle-polling; completion re-wakes you. Explicitly not a license for busywork.

Set `HUMAN_TZ` (e.g. `Europe/Helsinki`) in the hook's environment or `settings.json` `env`.

## 6. Session breadcrumb log

**The problem.** Sessions end (cleanly or via compaction) and the transcript vanishes into a
content-addressed path you'll never find again.

**The fix** — one JSONL line per `SessionEnd`/`PreCompact`, a greppable index of what ran
when and where its transcript lives (`settings.json`, merge into `hooks`):

```json
{
  "hooks": {
    "PreCompact": [
      { "hooks": [ { "type": "command",
        "command": "mkdir -p ~/.claude/session-snapshots && jq -c '{ts:(now|todate),event:\"precompact\",trigger:(.trigger//\"auto\"),session_id:.session_id,cwd:.cwd,transcript:.transcript_path}' >> ~/.claude/session-snapshots/session-log.jsonl 2>/dev/null; echo '{\"systemMessage\":\"Context compaction imminent — breadcrumb logged. If this session did substantive work, checkpoint it now before context is lost.\"}'" } ] }
    ],
    "SessionEnd": [
      { "hooks": [ { "type": "command",
        "command": "mkdir -p ~/.claude/session-snapshots && jq -c '{ts:(now|todate),event:\"session_end\",reason:(.reason//null),session_id:.session_id,cwd:.cwd,transcript:.transcript_path}' >> ~/.claude/session-snapshots/session-log.jsonl 2>/dev/null || true" } ] }
    ]
  }
}
```

*Continuity-store seam:* the `PreCompact` message's "checkpoint it now" is where a
continuity user triggers a snapshot; the log itself is store-free. A related habit the log
enables: transcripts quote every file the session ever printed, so a lost file with no
backup is often recoverable by grepping `~/.claude/projects` — the breadcrumb tells you
which transcript to grep.

## 7. Self-kill guard

`pkill -f <pattern>` — and `pgrep -f … | kill` — can match the *calling shell's own
cmdline* and kill the agent's session. Agents know this and do it anyway; the "safe" bracket
trick fails whenever the plain string appears elsewhere in the same command. So: a
structural guard, not a reminder. `hooks/block-unsafe-kill.sh` on `PreToolUse` (matcher
`Bash`) blocks `pkill -f` / `killall` / `pgrep -f`+`kill`, allows kill-by-PID, and strips
quoted strings and heredocs first so a commit message *mentioning* these commands passes
(v1 blocked its own commit message — precision is the difference between a guard that's
obeyed and one that's overridden reflexively).

Three widenings since the first edition, each from a case that got past it:

- **The strip is a real quote mask** (`hooks/quote_mask.py`, bash's own rules,
  length-preserving), not two regexes. The regex pair read the apostrophe in `"it's fine"` as
  an opening quote and ate everything up to the next quote — including `pkill -f`'s own
  argument — so `echo "it's fine"; pkill -f 'server'` passed silently.
- **A substitution is code wherever bash runs it.** The old strip removed every heredoc and
  every `"..."` wholesale, so a backticked `pkill -f …` inside an unquoted heredoc or a
  double-quoted string ran unexamined. Live `` `…` `` and `$(…)` are now carried out of those
  spans and tested as shell code in their own right.
- **A process name is not an owner.** `pkill -x name` stops *every* process with that name; on
  one host `pkill -x llama-server` reached four processes and three belonged to other
  services. `-x` is now counted at hook time (`pgrep -x`, the same matcher) and refused only
  when it would reach more than one process — and an `until`/`while` gate on *any* `pgrep`
  is refused too, since it hangs on a shared name just as surely as on a self-match. The
  advice the guard prints names the PID you captured and a resource gate instead.

`hooks/tests/test-block-unsafe-kill.py` runs the guard against 19 commands that must block and
16 that must pass, with real processes holding a shared name.

## 8. Backtick-prose notice

Writing prose through a double-quoted shell string is routine (commit messages, PR bodies);
backticks are routine inside that prose (markdown code spans); the shell executes them — the
span vanishes, or the command's *output* is spliced into the record.
`hooks/backtick-prose-warn.sh` warns, at the moment of the call, only when all three hold:
live backticks, an interpolating string, a durable-prose writer. It stays silent on the
correct form (a quoted heredoc), on single-quoted spans, and on ordinary substitution — a
hook that fires on the correct form trains the reader to ignore it. Warn only, fail-open;
add your own note-store's write verbs to the `writers` list.

## 9. Cycle-mode keybinding

The default permission-mode toggle is `Shift+Tab`, which some terminals and SSH clients
physically can't send (Android ConnectBot is the classic case). `keybindings.json` rebinds
mode-cycling to `Ctrl+Y` — avoid `Ctrl+A` and other multiplexer prefixes. Hot-loads, no
restart. Docs: <https://code.claude.com/docs/en/keybindings>.

## 10. Color & QoL settings

```json
{
  "env": { "FORCE_COLOR": "3", "COLORTERM": "truecolor" },
  "theme": "dark",
  "agentPushNotifEnabled": true
}
```

- **`FORCE_COLOR: 3` + `COLORTERM: truecolor`** — full 24-bit color through SSH/terminals
  that under-report their capabilities (no more washed-out diffs).
- **`agentPushNotifEnabled: true`** — push notification when a long agent turn finishes:
  walk away and get pinged instead of babysitting the terminal.

## 11. Peer presence and a peer-note inbox

**The problem.** Several Claude Code sessions run on one host at once and cannot see each
other. In one evening (2026-08-08) that cost four collisions: one session left uncommitted
work in a shared tree that another nearly merged over; one re-analysed a defect the other
already had a fix for; one pushed while the other held unpublished commits; one amended a
commit that had already been mirrored. Every one of those was a fact that already existed on
the machine, with no path between the two processes — a person carried each of them across by
hand.

**The fix:** `presence/session-presence`, two halves of one mechanism.

- **Presence.** Each session records its id, cwd, model and the trees it has written to,
  refreshed on the `PreToolUse` path that already fires. That alone answers *is anyone else in
  here*, and it warns before a write into a tree another live session is working in — once per
  (peer, tree) per 15 minutes, so an editing burst does not become a wall of notices.
- **Inbox.** `agent-send` leaves a note for a peer session, delivered on that session's next
  tool call.

**There is no push, and that is the right shape.** A session acts only when invoked, so a note
lands on the recipient's *next tool call* — seconds for a session that is working, never for
one sitting idle at a prompt. Any claim better than that would be false. It fits the problem
because the collisions happen precisely when both sessions are busy.

Nothing is ever locked. Every output is advisory context; no hook here returns a permission
decision, so permission flow is untouched. And "authorized" is not a security word here: every
session runs as the same uid, so anything that can write the inbox can write any tree it can
reach. This is coordination hygiene between cooperating processes.

**What a peer can put in front of you is bounded.** A note body and its pointer are flattened
to one line and truncated before they reach another session's context, and since this edition
so is every *path* a peer chose — the tree it wrote in, its cwd — because a directory name can
carry a newline and would otherwise render as a second, differently-labelled line outside the
"this is a peer claim" framing. A hook payload's session id is accepted only as a single
path-safe component: it names the record, the lock and the inbox under the registry, and the
`end` hook unlinks by it, so `../sessions/<other>` used to unlink a peer's record. Both are
pinned in `presence/tests/INVARIANTS.md`, which keys every invariant by subject and names the
test that quantifies over it.

**Names** are drawn from a sized pool, rehashed on contention rather than suffixed, cooled for
a fortnight after a session ends before they can be reissued, and `agent-presence --names`
answers "which session was *amber-heron*" for any date — `names.tsv` is append-only.

**A hosted leg, optional.** Besides local peers, the inbox can read notes written into
`<state>/bus/in` by a relay from a session running somewhere else (claude.ai, a hosted agent).
Such a note is rendered with its origin beside the text and labelled as a self-asserted
handle. This file carries its own reader rather than importing the relay's writer — a
PreToolUse hook that runs before every tool call must not depend on another project's
checkout — and what keeps the two in step is a conformance test over fixtures the real writer
produced (`presence/tests/fixtures/bus/`, regenerated by
`presence/tests/instruments/make-bus-fixtures.py` when that writer is on hand). With no relay
there is simply nothing in `bus/in`, and nothing changes.

### Names, not uuids

Sessions are surfaced by **name** — `level-wren`, `early-heron` — because a 36-character uuid
is not something a person can hold in mind or say out loud, and every warning, note and
listing is read by one. A name is derived from the session id (32 adjectives × 32 nouns), so
the same id always yields the same name and an **uncontended** name can be recomputed from the
id alone. One that had to be disambiguated (`amber-heron-2`) cannot — the suffix depends on
what was already taken — so the durable mapping, not the derivation, is authoritative.

Allocation checks every name ever issued *plus* every name a live record still holds, because
the point is to answer *which session was `amber-heron`* days later. The honest bound: a name
is not reissued to a different session **while either the mapping or the holder's own record
survives**. Lose both at once — a wiped state directory — and a name can be reused. That is
why the mapping is never reaped: records age out of the live window after 30 minutes and are
deleted after 3 days, and `names.tsv` outlives all of it, because a transcript path, a commit
trailer or a log line gives you the id and not the name.

```
agent-presence --names         the name -> session id mapping
agent-presence --whoami        this session's own names — what to sign a note with
```

### The other name every session has

Claude Code keeps a registry of its own at `~/.claude/sessions/<pid>.json`, and names the same
sessions differently there. That name is what its built-in `ListAgents` prints and its
`SendMessage` tool addresses. It is the same session on both sides, joined on the **session
id**, which both registries carry — so every surface here prints both names, and tells a
session its *own*: you cannot sign a message with a name you were never told, and a session
that reads a presence name out of an injection and tries to reply with it finds it is not an
address anywhere.

Three bounds worth knowing, each of which this tool reports rather than papering over:

- **The messaging name is not derived from the session id.** Read out of the installed CLI: it
  is the slugified basename of the directory the session was *started* in plus one random byte
  in hex — so a session launched from `~/alice` shows up as `alice-5e`, and relaunching it
  produces a different suffix. Nothing outside that registry can compute it, and `SendMessage`
  may want a `[ref]` besides. So take the address from `ListAgents` exactly as it prints it,
  and treat the name as what lets you *recognise* a peer.
- **Only live processes are named.** A record whose pid is gone — or whose pid now belongs to a
  different process, which the kernel start-time comparison catches — is not offered as an
  address; a name held by two live sessions is reported as ambiguous rather than printed as
  though it would route.
- **A live session can hold no messaging socket at all.** `SendMessage` cannot reach such a
  session; `agent-send` can. Its name is still printed, because that is how you recognise it,
  but marked `(no SendMessage socket — reach it with agent-send)`.

### Using it

```
agent-presence                 who is live, where they are writing, what is undelivered
agent-presence --all           include sessions that have aged out
agent-presence --json          one JSON record per line

agent-send --all "force-pushing the mirror in 30s"
agent-send --tree ~/proj "do not merge — I hold an uncommitted fix in parser.py"
agent-send level-wren "I already have a fix for that crash"
agent-send level-wren --class directive --ref release-plan "priority changed"
```

Address a session by name **or by any prefix of its session id** — for when a log or a
transcript gave you the id and not the name. Exit codes for `agent-send`: `0` delivered, `3` no
live recipient, `2` usage error; a send that reaches nobody says so rather than succeeding
quietly.

Every delivery is labelled as an untrusted peer **claim**: a note may be acted on defensively
(wait, re-check, do not merge) and is not a work order. An **advisory** note (the default) is
presence and intent. A **directive** note is refused unless it carries `--ref <name>`, a
pointer to a durable record rather than the instruction itself — otherwise arriving promptly
becomes a way to acquire authority nobody granted.

*Continuity-store seam:* set `AGENT_PRESENCE_REF_DIR` to a directory of `<name>.md` records and
those pointers are checked to resolve — at send time, and again at delivery, since a record can
be removed in between. Leave it unset (the default) and a `--ref` is an opaque label; the
coordination half needs no store at all. One consequence to know before pointing it somewhere:
writes inside that directory are deliberately *not* collision-warned, so point it at a note
store, not at a code tree.

### State, and installing it

State lives under `~/.local/state/claude-sessions/`: `sessions/<id>.json` (one record per
session), `inbox/<id>/` with delivered notes moved to `inbox/<id>/read/`, `names.tsv`,
`locks/`, `warn/`. Override the root with `AGENT_PRESENCE_DIR` — the suite does, which is how
it runs without touching a live registry.

`presence/install.sh` gates on the suite, then symlinks `agent-presence` and `agent-send` into
`~/bin` (override with `AGENT_PRESENCE_BIN`), refusing to overwrite anything that is not
already a symlink. It never writes your `settings.json`; it reads it, and prints this to paste
if the wiring is missing — merge into the `hooks` object:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command",
        "command": "/path/to/presence/session-presence register 2>/dev/null || true" } ] }
    ],
    "PreToolUse": [
      { "hooks": [ { "type": "command",
        "command": "/path/to/presence/session-presence pretool 2>/dev/null || true" } ] }
    ],
    "SessionEnd": [
      { "hooks": [ { "type": "command",
        "command": "/path/to/presence/session-presence end 2>/dev/null || true" } ] }
    ]
  }
}
```

Use the script's **own path**, not `agent-presence`: dispatch is by invocation name, so
`agent-presence register` would run the *listing* and silently register nothing. (The installer
prints the absolute path for you.) `PreToolUse` has an empty matcher on purpose — presence refreshes on *every*
tool call, which is what makes a note arrive within seconds. Each hook is fail-open: one that
breaks a tool call is worse than no hook.

`presence/tests/test-session-presence.py` (120 cases) drives the real script as a subprocess
across the real stdin boundary, with the registry, the `.claude` home, `HOME` and `PATH` all
redirected into a tmpdir — and refuses to run at all if the subject does not resolve its
registry inside that tmpdir.

---

## Install summary

Everything lives under `~/.claude/` (user-global) or a project-local `.claude/`. Drop the
`hooks/` scripts in and `chmod +x`, merge the `settings.json` fragments into one file, add
`keybindings.json`; the anchors (§4) are the one root-installed piece, and §11 keeps its own
directory (`presence/`) with an installer of its own. New hook blocks in `settings.json` take
effect on the next turn — no restart.

**Dependencies:** `jq` (all hook scripts), `python3` (§2 burn fit, §3 transcript parse,
§7/§8 guards, all of §11), `git` (statusline branch display only — degrades gracefully).

**Tests:** `hooks/tests/` and `presence/tests/` run from a checkout with no arguments and exit
non-zero on failure.

**Ordering note:** §1's statusline persists the gauges file that §2 falls back on and §3
reads — install §1 first if you want all three telling one story.

## License

AGPL-3.0-or-later.
