#!/usr/bin/env bash
# UserPromptSubmit hook — inject budget gauges + a self-calibrating burndown estimate into the
# model's context (it has no introspective access to either).
# Gauges: prefer this hook's OWN stdin JSON (freshest); fall back to ~/.claude/.gauges (statusline).
# Burndown: log {pct, raw token components} from the transcript each turn -> fit realized %/token
# DIRECTLY (no assumption about Anthropic's rate-limit weighting formula), per model, current window.
in=$(cat 2>/dev/null)
jq_() { jq -r "$1 // empty" <<<"$in" 2>/dev/null; }
ctx=$(jq_ '.context_window.used_percentage')
fh=$(jq_  '.rate_limits.five_hour.used_percentage')
rs=$(jq_  '.rate_limits.five_hour.resets_at')
tx=$(jq_  '.transcript_path')
model=$(jq_ '.model.id'); [ -n "$model" ] || model=$(jq_ '.model.display_name'); [ -n "$model" ] || model="?"
sid=$(jq_ '.session_id'); sid=${sid:-default}   # read THIS session's gauges, not a shared clobbered file
find ~/.claude -maxdepth 1 \( -name '.gauges.*' -o -name '.burndown-status.*' \) -mtime +1 -delete 2>/dev/null || true
src="live"
if [ -z "$fh$ctx" ]; then read -r ctx fh rs 2>/dev/null < ~/.claude/.gauges."$sid" || true; src="statusline<=60s"; fi

# A percentage is a number in [0,100]; blank anything else. What lands here in the bug is not
# random garbage but an EPOCH-SHAPED value — the reset Unix timestamp (~1.7e9, 10 digits) that
# shifted LEFT into the 5h-usage slot when an empty middle field collapsed under `read -r` in an
# old-format .gauges file (the "5h-usage 1783984200% used" bug). Recognizing the shape is the
# diagnostic: a 10-digit "percentage" is unmistakably a leaked timestamp, not corruption. Blanking
# is the right repair (the 5h clause then drops, which is correct — the fivehr field was genuinely
# empty, which is what caused the collapse; recovering the epoch into rs was tried and reverted, it
# changed no output because the reset only renders alongside a known fivehr). The clamp also covers
# a partial write / future format drift; `rs` is a real epoch and is never clamped.
_okpct() { case "$1" in ''|-|*[!0-9.]*) return 1;; esac; awk "BEGIN{exit !($1>=0 && $1<=100)}"; }
_okpct "$ctx" || ctx=""
_okpct "$fh"  || fh=""

# --- self-calibrating burndown ------------------------------------------------
burn=""
if [ -n "$tx" ] && [ -f "$tx" ] && [ -n "$fh" ]; then
  burn=$(TX="$tx" PCT="$fh" CTXV="${ctx:-}" MODEL="$model" SID="$sid" python3 - <<'PY' 2>/dev/null
import os,json,time
tx=os.environ["TX"]; pct=float(os.environ["PCT"]); model=os.environ["MODEL"]; sid=os.environ.get("SID","default")
o=i=cc=cr=0
for line in open(tx):
    try: u=(json.loads(line).get("message",{}) or {}).get("usage")
    except Exception: u=None
    if not u: continue
    o+=u.get("output_tokens",0); i+=u.get("input_tokens",0)
    cc+=u.get("cache_creation_input_tokens",0); cr+=u.get("cache_read_input_tokens",0)
# weighted prior (billing-ish; raw components also logged so the true weights can be re-fit later)
w=i+cr*0.1+cc*2+o*5
log=os.path.expanduser("~/.claude/.burndown.jsonl")
hist=[]
try:
    for l in open(log):
        try: hist.append(json.loads(l))
        except Exception: pass
except FileNotFoundError: pass
rec={"ts":int(time.time()),"session":sid,"model":model,"pct":pct,"w":round(w),"o":o,"i":i,"cc":cc,"cr":cr}
# de-dupe against THIS session's last record (concurrent sessions interleave into the shared log)
mine=[h for h in hist if h.get("session")==sid]
if not mine or mine[-1].get("w")!=rec["w"] or mine[-1].get("pct")!=pct:
    open(log,"a").write(json.dumps(rec)+"\n"); hist.append(rec)
same=[h for h in hist if h.get("session")==sid and h.get("model")==model and "w" in h and "pct" in h]
# isolate CURRENT 5h window = trailing run where pct is non-decreasing (a reset breaks the run)
win=[same[-1]] if same else []
for h in reversed(same[:-1]):
    if h["pct"]<=win[0]["pct"]: win.insert(0,h)
    else: break
if len(win)>=2:
    dw=win[-1]["w"]-win[0]["w"]; dp=win[-1]["pct"]-win[0]["pct"]
    kpp=dw/dp/1000 if dw>0 and dp>0 else 0   # weighted ktok per 1% (needs a >=1% meter move)
    if kpp>0:
        rate=dp/(len(win)-1)                 # avg %/turn over the window (stable-ish)
        turns=int((100-pct)/rate) if rate>0 else 0
        status=f"{kpp:.0f}k/% ~{turns}t"
        inj=f"burndown: fit {kpp:.0f}k(w)/% -> ~{turns} turns to cap (n={len(win)})"
    else:
        status="cal"                         # meter static within window -> nothing to fit yet
        inj=f"burndown: calibrating (n={len(win)}, meter static at {pct:.0f}% — needs a 1% tick)"
    try: open(os.path.expanduser(f"~/.claude/.burndown-status.{sid}"),"w").write(status)
    except Exception: pass
    print(inj)
PY
)
fi

[ -n "$ctx$fh" ] || exit 0
line="Budget gauges ($src): context-window ${ctx:-?}% full"
# Only add the 5h clause (and its reset + burndown) when the usage is actually known — a blank
# percentage ("5h-usage % used") reads as broken, and burndown was fit on a known fh anyway.
if [ -n "$fh" ]; then
  line="$line; 5h-usage ${fh%.*}% used"
  [ -n "$rs" ] && { r=$(date -d "@${rs%.*}" '+%H:%M %Z' 2>/dev/null); [ -n "$r" ] && line="$line (5h resets $r)"; }
  [ -n "$burn" ] && line="$line — $burn"
fi
echo "$line"
