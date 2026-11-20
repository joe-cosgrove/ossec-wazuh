# OSSEC/Wazuh output-daemons security review (2026-11-20)

## Scope

- `src/os_maild`
- `src/os_csyslogd`
- `src/os_dbd` (beyond already-known unsanitized `alertid` interpolation)
- `src/os_integrator` (beyond already-known `/tmp` predictable names and sourcing alert files)
- `src/reportd`
- `src/monitord`
- `integrations/`

## Exclusions honored

GetAlertData `Rule:` smuggling → integrator RCE; GetAlertData `** Alert` smuggling → `alertid` SQLi; integrator `/tmp` symlink; slack/pagerduty sourcing; `ossec2mysql.pl` host backticks; `ossec-tweeter.sh`; `ossec-slack.sh`; location / PostgreSQL srcip-dstip dbd SQLi; maild SMTP DATA dot-stuffing; description_append OpenSCAP RCE.

## Result

**NONE** — no new validated MEDIUM/HIGH/CRITICAL findings with a complete registered-agent → impact chain in the scoped sinks beyond the exclusion list.

## Near-misses (triaged out)

| Candidate | Evidence | Why rejected |
|---|---|---|
| Default Subject CRLF | `src/os_maild/os_maild_client.c:131-155`, `sendmail.c:496-510` | Subject truncates location at `>`; remoted always inserts `->`; agent-controlled suffix removed under default `maild.full_subject=0` |
| full_subject / SMS Subject CRLF | `MAIL_SUBJECT_FULL` / `SMS_SUBJECT` use `comment` | Requires non-default `full_subject=1` or granular `SMS_FORMAT` |
| csyslog framing / CEF / Splunk injection | `src/os_csyslogd/alert.c:97-267` | `<syslog_output>` not in shipped configs; SIEM semantic integrity only; JSON path uses cJSON |
| dbd category SQL | `src/os_dbd/rules.c:34-56` | Groups from local rules XML; escaped; signature INSERT is commented out |
| MySQL `tld` from `srcgeoip` | `src/os_dbd/alert.c:183-193` (`%.2s`) | At most two attacker-influenced bytes; not a practical SQLi chain |
| monitord daily report SMTP DATA | `generate_reports.c:72-78`, `sendcustomemail.c:221-224` | Same impact class as already-reported maild DATA smuggling; reports not enabled in shipped configs |
| integrator `$()` via unsanitized location | `integrator.c:274` + `integrations/slack:39` | Alternate payload for already-excluded sourcing/location RCE |
| `system()` with apikey/hookurl | `integrator.c:282-283` | Values from `ossec.conf` only |
| reportd / monitord path ops | `src/reportd/report.c`, `manage_files.c`, `sign_log.c` | Privsep + fixed log paths; no agent-controlled path/command sink |

## Method

- Traced agent-controlled alert fields through `GetAlertData` into each daemon sink (`snprintf`/`system`/`curl`/SMTP/SQL).
- Re-checked default vs optional config gates (`full_subject`, `syslog_output`, `database`, `integration`, `reports`).
- Cross-checked prior hunts covering the same trees to avoid re-reporting excluded items.
