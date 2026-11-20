# OSSEC/Wazuh analysisd scoped hunt — 2026-11-20

## Validated findings

### 1. HIGH — `doDiff` stack use-after-return via `last_events`

| Field | Value |
|---|---|
| **Title** | `doDiff` stores stack address of `flastcontent` in `rule->last_events` |
| **Severity** | HIGH |
| **Location** | `src/analysisd/dodiff.c:74,147-148` (sink: `src/analysisd/alerts/log.c:408-412`) |

**Evidence:** `flastcontent` is an automatic buffer. On content change, `rule->last_events[1] = flastcontent` then `return (1)`. `OS_Log` later `fprintf`s that pointer. ASan replica: `stack-use-after-return`. Default rule 533 (`check_diff` on `ossec: output: 'netstat -tan`) is reachable by any registered agent with two differing lines.

**Attack path:** Agent sends two `ossec: output: 'netstat -tan': ...` events (no syslog date → `ossec` decoder). First seeds the diff file; second triggers UAF while writing the level-7 alert.

**Impact:** Undefined behavior in analysisd — stack leak into alerts (and consumers) and crash under hardening; alerting/AR/mail/integrations degraded or down.

**Remediation:** Heap-allocate previous content before storing in `last_events`; never publish stack addresses.

### 2. MEDIUM — Rootcheck JSON key injection into `rule` object

| Field | Value |
|---|---|
| **Title** | Attacker-controlled `{Name: values}` becomes a cJSON key on the alert `rule` object |
| **Severity** | MEDIUM |
| **Location** | `src/analysisd/format/json_extended.c` `W_JSON_ParseRootcheck` (~104-107) |

**Evidence:** `cJSON_AddItemToObject(rule, token, ...)` uses the capture name as key. Short tokens like `{level: 999}` avoid the known 30-byte overflow and `trim(NULL)`. Local cJSON print: `{"level":7,"comment":"real","level":["999"],"comment":["pwned"]}`.

**Attack path:** `jsonout_output` yes → ROOTCHECK_MQ rootcheck-group alert → `W_ParseJSON` → duplicate keys in `alerts.json`.

**Impact:** Alert-stream integrity / SIEM type-confusion for last-key or typed parsers.

**Remediation:** Allowlist compliance keys or nest under a fixed object; reject collisions with `level`/`comment`/`sidid`/`groups`.

## Near-misses

- `logcollector` `command=`: `remote_commands` default 0
- `description_append` / `comment_append`: integrator sink already reported
- SonicWall `strncpy(category, ..., 7)` without NUL: strcmp targets too short for practical OOB
- ossecalert `agent-info` fopen traversal: needs intermediate dirs (skipped class)
- accumulator / `trim("")` / FTS ignore newline / doDiff path-by-name: no complete MEDIUM+ chain
- Skipped known: json_extended 30-byte, trim(NULL), hostname/location strncpy, totalResults, fullog strncpy, ossecalert impersonation, RK_File OOB, RK/DB traversal, GetAlertData smuggling
