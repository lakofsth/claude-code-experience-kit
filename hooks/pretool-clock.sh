#!/usr/bin/env bash
# PreToolUse heartbeat — re-anchor the model's LIVE clock (and budget gauges) on NON-PROMPT wakes,
# and name the model that is ACTUALLY serving the session.
#
# WHY (clock): the local-time and budget-gauge lines the model sees are injected at
# UserPromptSubmit, so they are stamped once, when a HUMAN submits. A turn re-woken WITHOUT a
# new prompt keeps the last prompt's stamp — and that happens routinely: a background-task
# completion re-invokes the session, and a dormant session can resume hours later. Observed: a
# single turn spanned 15:03->21:43 (a backgrounded watch task completing six hours later) while
# the injected time still read 15:03. UserPromptSubmit cannot fix this — there is no submit to
# fire on. PreToolUse CAN: it fires on the model's first action after ANY wake.
#
# WHY (model): a session can be moved to a different model BETWEEN turns, and nothing in the
# injected context says so — the session keeps stamping records with the tier it STARTED as.
# The transcript records what actually served each turn (message.model), so read it and say so.
# A CHANGE is reported loudly and bypasses the throttle — a silent swap is exactly the case
# worth interrupting for.
#
# THROTTLE: emitting every tool call would be constant noise. Emit at most once per THRESH
# seconds: an active tool-call burst stays quiet, while a long gap since the last emit always
# exceeds THRESH and re-stamps immediately — silent when fresh, speaks up when time jumped.
#
# SAFETY: injects additionalContext ONLY — never a permissionDecision, so permission flow is
# untouched. Silent (exit 0, no stdout) on every throttled call and on any error. If the
# transcript cannot be read, the model line is OMITTED — never guessed.
#
# Adapt: set HUMAN_TZ to the human's timezone (hook env or settings.json "env").

in=$(cat 2>/dev/null)
sid=$(jq -r '.session_id // "default"' <<<"$in" 2>/dev/null); sid=${sid:-default}

THRESH=300   # 5 min: fine enough to be a useful live clock, coarse enough that a burst of
             # tool calls emits at most once; any real dormancy blows past it.
mark="$HOME/.claude/.lastclock.$sid"
now=$(date +%s)
last=$(cat "$mark" 2>/dev/null || echo 0)
case "$last" in ''|*[!0-9]*) last=0;; esac
find "$HOME/.claude" -maxdepth 1 -name '.lastclock.*' -mtime +1 -delete 2>/dev/null || true

# ---- which model is actually serving this session ----------------------------------------------
# Fast path: newest "model" literal in the transcript, scanning from the end. A hit that
# DISAGREES with the stored marker is re-checked properly (parse the newest assistant record)
# before we shout, so a stray literal in some tool output cannot fake a swap alert.
tf=""; model=""; prev=""; switched=0
tf=$(ls -t "$HOME"/.claude/projects/*/"$sid".jsonl 2>/dev/null | head -1)
if [ -n "$tf" ] && [ -r "$tf" ]; then
  model=$(tac "$tf" 2>/dev/null | grep -m1 -oE '"model":"claude-[^"]+"' | cut -d'"' -f4)
fi
mmark="$HOME/.claude/.lastmodel.$sid"
prev=$(cat "$mmark" 2>/dev/null || echo "")
find "$HOME/.claude" -maxdepth 1 -name '.lastmodel.*' -mtime +1 -delete 2>/dev/null || true

if [ -n "$model" ] && [ -n "$prev" ] && [ "$model" != "$prev" ]; then
  confirmed=$(tac "$tf" 2>/dev/null | python3 -c '
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
    except Exception:
        continue
    if d.get("type") == "assistant":
        m = (d.get("message") or {}).get("model")
        if m:
            print(m)
            break
' 2>/dev/null)
  [ -n "$confirmed" ] && model="$confirmed"
  # A model value that is not a real tier — the harness writes a literal "<synthetic>" record
  # during a swap — is UNKNOWN, not a model. Naming it would stamp records with a placeholder,
  # and storing it turns one real swap into two alerts. Drop it and keep the previous marker
  # until a real tier appears.
  case "$model" in
    claude-*) : ;;
    *) model="" ; switched=0 ;;
  esac
  [ -n "$model" ] && [ "$model" != "$prev" ] && switched=1
fi
[ -n "$model" ] && printf '%s' "$model" > "$mmark" 2>/dev/null

# A confirmed swap always speaks, however recently we last emitted.
[ "$switched" = 1 ] || [ $(( now - last )) -ge "$THRESH" ] || exit 0
echo "$now" > "$mark" 2>/dev/null

HUMAN_TZ="${HUMAN_TZ:-UTC}"
tz=$(TZ="$HUMAN_TZ" date '+%H:%M %Z, %a %d %b')

# Fresh gauges: the statusline rewrites ~/.claude/.gauges.<sid> every <=60s independently of
# prompts, so reading it here is live. A percentage is a number in [0,100]; blank anything
# else (the '-' empty-field sentinel, or a reset epoch shifted into the wrong slot by an
# old-format file — a 10-digit "percentage" is a leaked timestamp, not corruption).
g=""
if read -r c f r 2>/dev/null < "$HOME/.claude/.gauges.$sid"; then
  _okpct() { case "$1" in ''|-|*[!0-9.]*) return 1;; esac; awk "BEGIN{exit !($1>=0 && $1<=100)}"; }
  _okpct "$c" || c=""
  _okpct "$f" || f=""
  [ -n "$c" ] && g="ctx ${c%.*}%"
  [ -n "$f" ] && g="${g:+$g / }5h ${f%.*}%"
fi

msg="⏱ Live now: ${tz}${g:+ · gauges ${g}}${model:+ · serving: ${model}}. (Refreshed on tool use — injected time/gauge lines freeze on background-task and multi-session re-wakes, so trust THIS over an older injected stamp for elapsed time / quota.)"

if [ "$switched" = 1 ]; then
  msg="⚠ MODEL CHANGED MID-SESSION: ${prev} → ${model}. This is read from the transcript's own record of what served the newest turn, so it is what happened, not a guess. You are ${model} NOW: anything you stamp with a model name from here (commit trailers, docs, reports) must say ${model}; records written earlier under ${prev} were correct when written. If this was an involuntary tier change, the work continues — but say so plainly to the human rather than carrying on as if nothing changed. ${msg}"
fi

jq -nc --arg c "$msg" '{hookSpecificOutput:{hookEventName:"PreToolUse",additionalContext:$c}}'
exit 0
