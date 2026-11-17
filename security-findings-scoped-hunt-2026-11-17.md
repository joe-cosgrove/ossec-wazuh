# OSSEC/Wazuh scoped security hunt — 2026-11-17

Commit reviewed: `0643b5cb8a7f150c3a4823d1a53f8acd80ea5a61` (master)

Scope: analysisd `json_extended.c` (remaining overflows), csyslogd, custom_output, active-response scripts (excl. ossec-slack.sh), agentlessd, logcollector, os_maild headers (excl. DATA dot-stuffing), cleanevent/decoders, accumulator/geoip/compiled_rules.

## Validated MEDIUM+ findings

### 1. HIGH — `match_regex` unbounded `totalResults` heap OOB write (distinct from 30-byte buffer overflow)

| Field | Value |
|---|---|
| **Severity** | HIGH |
| **Location** | `src/analysisd/format/json_extended.c` — `match_regex()` ~307–335; caller `W_JSON_ParseRootcheck()` ~69–127 |
| **Title** | Rootcheck JSON path writes past `results[MAX_MATCHES]` with no index check |

**Description**

`W_JSON_ParseRootcheck` allocates `results[0..9]` (10 heap buffers) then calls `match_regex()`. That function loops with `regexec` over the entire `full_log` and, for every capture (`i > 0`), does:

```c
sprintf(results[totalResults], "%.*s", (finish - start), to_match + start);
totalResults = totalResults + 1;
```

There is no `totalResults < MAX_MATCHES` guard. Eleven or more `{Tag: values}` matches (regex `\{([A-Za-z0-9_]*: [A-Za-z0-9_., ]*)\}`) write through `results[10+]`, i.e. unallocated pointer slots — classic heap OOB write.

This is **not** the already-known bug where each `results[i]` is only 30 bytes (`MAX_STRING_LESS`) and a single long capture overflows that buffer. That remains excluded. This finding is the missing upper bound on **how many** captures are stored.

**Impact**

Heap corruption in `ossec-analysisd` (typically user `ossec`). Reliable crash (DoS of alerting, mail, AR, integrations). Plausible code execution depending on allocator layout.

**Attack path**

1. Manager has `jsonout_output` enabled (Wazuh `install.sh` writes `<jsonout_output>yes</jsonout_output>` by default).
2. Attacker controls a registered agent (or its rootcheck output).
3. Agent emits a rootcheck-class alert whose `full_log` contains ≥11 substrings matching `\{name: values\}` (stock CIS/PCI rootcheck lines use this shape; a compromised agent can emit many in one message).
4. Rule group includes `rootcheck` → `Eventinfo_to_jsonstr` → `W_ParseJSON` → `W_isRootcheck` → `W_JSON_ParseRootcheck` → `match_regex`.
5. Eleventh capture writes `results[10]` → heap OOB.

**Evidence**

- `src/analysisd/format/json_extended.c:85-86` — `results[i] = malloc(MAX_STRING_LESS)` for `i < MAX_MATCHES` only
- `src/analysisd/format/json_extended.c:328-330` — `sprintf(results[totalResults], ...)` with no bounds check; `totalResults++`
- `src/analysisd/format/json_extended.c:34-35` / `to_json.c:233` — rootcheck JSON parse on alert path
- `install.sh:549` — default `jsonout_output` yes
- `etc/rules/ossec_rules.xml` — rootcheck group on rootcheck rules
- Local replica: 12 synthetic `{pci_dss_N: 1.N}` tokens → write attempted at `results[10]`

**Remediation**

Stop storing when `totalResults >= MAX_MATCHES`. Prefer `snprintf(results[i], MAX_STRING_LESS, ...)`. Cap matches and reject/truncate oversized captures.

---

### 2. HIGH — `W_JSON_ParseRootcheck` `fullog[1024]` strncpy without NUL (distinct from hostname/location)

| Field | Value |
|---|---|
| **Severity** | HIGH |
| **Location** | `src/analysisd/format/json_extended.c` — `W_JSON_ParseRootcheck()` ~82–100 |

**Description**

```c
char fullog[MAX_STRING]; /* 1024 */
strncpy(fullog, lf->full_log, MAX_STRING);
find_text = fullog;
matches = match_regex(&r, find_text, results);
```

If `lf->full_log` length ≥ 1024, `strncpy` leaves `fullog` with **no terminating NUL**. `match_regex` → `regexec` requires a C string; the call reads off the end of the stack buffer (UB). This is the same class of bug as the excluded hostname/location `strncpy`+`str_cut` issue, but a **different buffer and call chain** inside the rootcheck JSON parser, and it is not cured by fixing only `W_JSON_ParseHostname` / `W_JSON_ParseLocation`.

Agent messages can be up to `OS_MAXSTR` (6144), so ≥1024-byte rootcheck `full_log` is reachable.

**Impact**

Stack over-read in analysisd; typically crash/DoS when JSON-encoding a long rootcheck alert. Combined with finding 1, long multi-tag messages are a practical trigger surface.

**Attack path**

1. `jsonout_output` enabled; rootcheck alert fires.
2. Attacker-controlled `full_log` ≥ 1024 bytes (compromised agent rootcheck/log).
3. `W_JSON_ParseRootcheck` copies without NUL; `regexec` walks past `fullog`.
4. analysisd crashes or mis-parses adjacent stack.

**Evidence**

- `src/analysisd/format/json_extended.c:82` — `char fullog[MAX_STRING];`
- `src/analysisd/format/json_extended.c:95` — `strncpy(fullog, lf->full_log, MAX_STRING);` (no `fullog[MAX_STRING-1]='\0'`)
- `src/analysisd/format/json_extended.c:98-100` — unterminated buffer passed to `match_regex` / `regexec`
- `src/headers/defs.h:33` — `OS_MAXSTR` = 6144
- Local replica: poison `fullog` with `'X'`, `strncpy` 2000-byte source → no NUL in 1024 bytes; scan continued past 1024

**Remediation**

`fullog[MAX_STRING-1] = '\0'` after strncpy, or use `snprintf(fullog, sizeof(fullog), "%s", lf->full_log)`.

---

## Near-misses (not reported as MEDIUM+)

| Area | Why it fails validation |
|---|---|
| **ossec-tweeter.sh quote-break RCE** | `ALERTFULL` expands inside double quotes; shell does **not** re-parse embedded `"`, `$()`, or backticks. Verified with `sh`/`bash` (single argv). Distinct from excluded `ossec-slack.sh` command-substitution issue. |
| **disable-account / host-deny / firewall-drop / ip-customblock / route-null / firewalld-drop / pf** | `analysisd` gates AR with `CRAFTED_IP` (`^[a-zA-Z.:_0-9-]*$`) and `CRAFTED_USER` (`^[a-zA-Z._0-9@?-]*$`) before `OS_Exec` (`analysisd.c:984-1000`). Blocks shell metacharacters, spaces, `/`. `eval` paths on BSD/AIX are therefore not injectable via srcip. |
| **csyslogd CEF/Splunk field injection** | Agent-influenced `comment` via OpenSCAP `description_append`/`title` can break CEF pipes or Splunk quotes when csyslogd CEF/Splunk format is enabled — real injection into SIEM semantics, but requires non-default csyslogd+format plus oscap; treated as conditional / below bar vs. analysisd memory corruption. JSON csyslog path uses cJSON (escaped). No `printf(user)` format-string sink. |
| **os_maild Subject/To header injection** | `To`/`From` from config only. Default subject uses location truncated at `>` (`os_maild_client.c:131-155`); agent prefix is name/IP (validated charset). `maild.full_subject` defaults to 0. SMS subject uses rule comment — needs granular SMS format. DATA dot-stuffing excluded. |
| **custom_output_search_replace / OS_CustomLog** | Search tokens are fixed constants; agent data is replacement **values** only. Output is `fprintf` to alert log, not a shell. `escape_newlines` on `full_log`. No overflow chain to RCE. |
| **agentlessd** | `system`/`popen` built from admin `ossec.conf` (`type`/`server`/`options`). Remote script `$args` comes from that same config. Not remote attacker-controlled without config write. |
| **logcollector command/full_command** | `popen(logff[].command)` from localfile config; `logcollector.remote_commands=0` by default rejects manager-pushed commands. |
| **cleanevent / plugin decoders / geoip / accumulator / compiled_rules** | No new remote → memory-corruption or command-exec chain beyond exclusions. Accumulator key uses `snprintf` into 256-byte buffer with `OS_FLSIZE==256`. GeoIP `snprintf` bounded. compiled_rules samples are strcmp-style helpers. RK_File/DB_File `../` after `->` needs a non-existent intermediate directory — not creatable remotely. |
| **hostname/location strncpy + str_cut** | Explicitly excluded (already known). |
| **rootcheck 30-byte `sprintf` into `malloc(30)`** | Explicitly excluded (already known). |
