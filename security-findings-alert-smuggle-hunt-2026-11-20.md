# OSSEC/Wazuh AppSec hunt — alert-file field smuggling (2026-11-20)

Commit reviewed: `27a9e6d57dfd4c00d03a9f17341eb913dfe63cb7` (workspace at hunt time)

## Focus

src/os_csyslogd, src/os_maild (non–DATA-dot-stuffing), src/os_dbd (non–location/srcip), src/os_integrator (non–location/ruledescription-from-description_append), src/analysisd/output, src/wazuh_db, src/reportd, src/monitord, integrations/, src/shared/read-alert.c

## Exclusions honored

All 18 already-reported items (integrator location RCE, description_append OpenSCAP RCE, dbd location/srcip SQLi, authd, win AR, maild DATA, ossec-slack.sh, zip-slip, TCP length, verify_msg_id, JSON rootcheck overflows, ossecalert, UnmergeFiles, agent-auth TLS, win FILE_UPDATE backslash, JSON hostname/location strncpy, rootcheck/syscheck fopen).

## Validated NEW findings

### 1. CRITICAL — Alert log field smuggling → integrator shell RCE

**Location:** `src/shared/read-alert.c` (+ `src/analysisd/alerts/log.c`, `src/os_integrator/integrator.c`)

**Title:** Multiline `full_log` smuggles fake `Rule:` / `** Alert` lines into GetAlertData, overwriting unsanitized `ruledescription` / `alertlocation` for Slack/PagerDuty RCE.

**Distinctness:** Not location-suffix RCE (#1). Not description_append OpenSCAP title (#16). Root cause is GetAlertData treating attacker log-body lines as structured alert fields after OS_Log writes raw newlines from `full_log`.

### 2. HIGH — Alert log field smuggling → os_dbd `alertid` SQL injection

**Location:** `src/shared/read-alert.c` (+ `src/os_dbd/alert.c`)

**Title:** Same smuggling overwrites `alertid`, which both MySQL and PostgreSQL INSERT paths interpolate without `osdb_escapestr`.

**Distinctness:** Not the already-reported location / PostgreSQL srcip-dstip SQLi (#3). New field, new write path via alert-header reparse inside the log body.

## Near-misses (not reported as NEW MEDIUM+)

| Candidate | Why rejected |
|---|---|
| Src IP / location overwrite via same smuggle into PostgreSQL IP / location SQL | Same sinks as already-reported #3; smuggle is an alternate write path, not a new impact class beyond alertid |
| csyslogd PRI/framing injection via smuggled comment/location newlines | Requires non-default `<syslog_output>`; SIEM integrity, not manager RCE |
| maild Subject CRLF via smuggled comment | Needs `maild.full_subject=1` or SMS_FORMAT granular mail (defaults off) |
| monitord report email body SMTP DATA | Same class as already-reported maild DATA (#6); reports optional |
| wazuh_db agent name in DB path | Enrollment `OS_IsValidName` blocks `/`; queries parameterized |
| analysisd/output zeromq/picviz/prelude | Optional compile flags; ZeroMQ unauth PUB is medium exposure only when enabled |
| prefilter_cmd popen | Requires admin `<prefilter_cmd>` |
| integrator `alertdate` | Manager clock unless full header takeover; low value vs location/comment |

## Method

- Traced agent SECURE_MQ payload → remoted → OS_CleanMSG → OS_Log `%.1256s` → GetAlertData line parser → integratord / os_dbd sinks.
- Local non-destructive bash `. alertfile` PoCs created marker files for both comment-only and full header-takeover payloads.
- Confirmed rule 1002 (default BAD_WORDS, level 2 ≥ `log_alert_level` 1) writes alerts without custom rules.
