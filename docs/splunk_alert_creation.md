# Creating Alerts in Splunk — Practical Guide

How to create, configure, and manage alerts in Splunk through the UI.
All examples use `index=sysmon host=cti-win-detonation` from the BeastIntel lab.

---

## What an Alert Is

A Splunk alert is a saved search that runs on a schedule. When the results meet
a trigger condition (e.g. results > 0), Splunk fires an action — writing to
`index=_audit`, sending an email, calling a webhook, or triggering a SOAR
playbook. This is the bridge between raw telemetry and operational response.

---

## Creating an Alert — Step by Step

### Step 1: Build and validate the search first

Always write and test your SPL in Search & Reporting before saving as an alert.
Set the time range to `Last 60 minutes` and confirm results look correct.

Example — PowerShell encoded command:
```spl
index=sysmon host=cti-win-detonation EventCode=1
Image="*\powershell.exe"
(CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*IEX*")
| table _time Computer User CommandLine
| sort - _time
```

### Step 2: Save as Alert

Once the search returns expected results:
1. Click **Save As** → **Alert**
2. Fill in the alert form:

| Field | What to set | Why |
|---|---|---|
| **Title** | `BeastIntel - T1140 PowerShell Base64` | Consistent naming — `BeastIntel - <TTP>` prefix |
| **Description** | `Detects PowerShell with Base64 encoded command (LummaC2 ClickFix dropper)` | Useful for the alert manager and handoff notes |
| **Permissions** | Shared in App | Makes it visible to other analysts |
| **Alert type** | Scheduled | Runs on a schedule vs real-time |
| **Time range** | Run every `1 Hour`, search `Last 1 hour` | Prevents gap/overlap in coverage |
| **Cron schedule** | `0 * * * *` | Top of every hour — use cron if you need offset timing |

### Step 3: Configure the Trigger Condition

This is where the alert fires or stays silent:

| Field | What to set | Why |
|---|---|---|
| **Trigger alert when** | `Number of Results` | Simplest and most reliable |
| **is greater than** | `0` | Fire on any hit |
| **Trigger** | `Once` | Prevents alert storms — fires once per scheduled run even if 100 results |
| **Throttle** | ✓ Enable, `60 minutes` | Suppresses repeat fires — stops noise if the same event persists |

> For higher-fidelity alerts, use **"Number of Results" > 0** for rare/high-confidence
> TTPs (T1036 double extension) and add throttling. For noisy searches
> (T1082 systeminfo which fires legitimately), tune the threshold higher or
> add `NOT` exclusions before saving.

### Step 4: Configure Actions

What happens when the alert fires:

**Minimum (always set these):**
- ✓ **Add to Triggered Alerts** — appears in the Splunk Alert Manager UI (`Activity → Triggered Alerts`)
- ✓ **Log Event** — writes `action=alert_fired` to `index=_audit` — queryable, auditable

**Optional (for production SOC):**
- **Send Email** — alert body, include top 5 results
- **Webhook** — POST to SOAR (Splunk SOAR, Tines, XSOAR) to auto-create a ticket
- **Run a Script** — trigger automated enrichment

### Step 5: Save and verify

1. Click **Save**
2. Go to **Activity → Triggered Alerts** — your alert appears in the list
3. To test immediately: **Settings → Searches, Reports and Alerts** → find your alert → **Run**
4. Verify it fires: search `index=_audit action=alert_fired savedsearch_name="BeastIntel*" earliest=-15m`

---

## Alert Configuration Reference

### Scheduling options

| Schedule | Cron | Use case |
|---|---|---|
| Every 5 min | `*/5 * * * *` | High-priority, near-real-time (noisy, use sparingly) |
| Every 15 min | `*/15 * * * *` | Active incident hunting |
| Every hour | `0 * * * *` | Standard detection rule |
| Every 6 hours | `0 */6 * * *` | Lower-priority, daily summary rules |

### Throttle guidance

| TTP type | Throttle setting |
|---|---|
| High-confidence, rare (T1036 double extension) | 60 min — suppress repeats within the run window |
| Discovery tools (T1082 systeminfo) | 120 min — these fire frequently, reduce noise |
| Kill chain correlation | No throttle — every firing is meaningful |

---

## Managing Existing Alerts

**View all BeastIntel alerts:**
`Settings → Searches, Reports and Alerts` → filter by name `BeastIntel`

**Check what fired in the last 24h:**
```spl
index=_audit action=alert_fired savedsearch_name="BeastIntel*" earliest=-24h
| eval Rule=replace(savedsearch_name,"BeastIntel - LUMMAC2-","")
| stats count AS Fires, max(_time) AS LastFired by Rule
| eval LastFired=strftime(LastFired,"%Y-%m-%d %H:%M UTC")
| sort - Fires
```

**Check alert history for a specific rule:**
```spl
index=_audit action=alert_fired savedsearch_name="BeastIntel - LUMMAC2-T1140*" earliest=-7d
| table _time savedsearch_name result_count
```

**Edit an alert:** Settings → Searches, Reports and Alerts → click the alert name → Edit

---

## Creating a Correlation Alert (multi-TTP)

Alerts become more powerful when they detect combinations of techniques — a
single systeminfo execution is low confidence; systeminfo *followed by*
PowerShell Base64 *followed by* a network connection is high confidence.

```spl
index=sysmon host=cti-win-detonation earliest=-30m
| eval TTP=case(
    EventCode=1 AND match(Image,"systeminfo\.exe|whoami\.exe"),"recon",
    EventCode=1 AND match(Image,"powershell\.exe") AND match(CommandLine,"IEX|EncodedCommand"),"dropper",
    EventCode=1 AND match(Image,"rundll32\.exe") AND match(CommandLine,"Public|AppData"),"exec",
    EventCode=11 AND match(TargetFilename,"Cookies"),"data_access",
    true(),null())
| where isnotnull(TTP)
| stats dc(TTP) AS unique_stages, values(TTP) AS stages, count by Computer
| where unique_stages >= 3
| sort - unique_stages
```

Save this as `BeastIntel - KILL CHAIN MULTI-STAGE` with trigger `results > 0`.
Three or more distinct kill chain stages from the same host in 30 minutes is
high-confidence compromise — escalate immediately.

---

## Interview Talking Points

- "I write the detection search first, validate it returns the right results, then
  save as a scheduled alert — never save an untested search as an alert."
- "Throttling is critical in production — an alert that fires 500 times an hour
  trains analysts to ignore it. I tune the threshold and throttle window before
  the alert goes live."
- "The action I always set is `log_event` to `_audit` — it gives you an auditable
  history of what fired and when, independent of whether anyone looked at the
  Alert Manager UI."
- "For high-confidence, low-frequency TTPs I use `results > 0`. For noisier
  searches I tune the threshold or add NOT exclusions for known-good processes
  before saving."
- "Correlation alerts across multiple TTPs from the same host within a short
  window are the most valuable — a single systeminfo execution could be an admin,
  three kill chain stages from the same host in 30 minutes is an incident."
