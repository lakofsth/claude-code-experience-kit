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
checkpoints, and paces itself without being told.

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

---

## 1. Statusline gauges (the human's dial)

**What it shows:** context-fill % (green <70%, yellow ≥70%, bold-red ≥90%) · time-left and
% consumed on the 5-hour usage window · a burn-rate readout (written by §2) · dir (branch) ·
model.

`settings.json`:

```json
{
  "statusLine": { "type": "command", "command": "~/.claude/statusline.sh", "refreshInterval": 60 }
}
```

Script: `hooks/statusline.sh`. Input is JSON on stdin — fields:
<https://code.claude.com/docs/en/statusline>. `refreshInterval: 60` matters: it keeps the
usage-window countdown ticking between messages.

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

The same fit writes a compact `210k/% ~14t` status for §1's statusline, so both parties read
one calibration.

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
`Bash`) blocks `pkill -f` / `killall` / `pgrep -f`+`kill`, allows kill-by-PID and
`pkill -x`, and strips quoted strings and heredocs first so a commit message *mentioning*
these commands passes (v1 blocked its own commit message — precision is the difference
between a guard that's obeyed and one that's overridden reflexively).

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

---

## Install summary

Everything lives under `~/.claude/` (user-global) or a project-local `.claude/`. Drop the
`hooks/` scripts in and `chmod +x`, merge the `settings.json` fragments into one file, add
`keybindings.json`; the anchors (§4) are the one root-installed piece. New hook blocks in
`settings.json` take effect on the next turn — no restart.

**Dependencies:** `jq` (all hook scripts), `python3` (§2 burn fit, §3 transcript parse,
§7/§8 guards), `git` (statusline branch display only — degrades gracefully).

**Ordering note:** §1's statusline persists the gauges file that §2 falls back on and §3
reads — install §1 first if you want all three telling one story.

## License

AGPL-3.0-or-later.
