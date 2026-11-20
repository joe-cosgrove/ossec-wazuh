# OSSEC/Wazuh AppSec hunt — csyslog / maild / analysisd output / integrator

Commit reviewed: workspace `master` at hunt time.

## Focus

- `src/os_csyslogd/` (custom syslog forwarding)
- `src/os_maild/` (beyond SMTP DATA smuggling)
- `src/analysisd/output/`
- `src/os_integrator/` (beyond known alert-file shell sourcing)

## Exclusions honored

- SMTP DATA / dot-stuffing in `sendmail.c`
- `integrator.c` sourcing alert files with unsanitized `location` / `comment`
- GetAlertData header smuggling

## Result

**none** — no NEW validated MEDIUM/HIGH/CRITICAL findings with a complete registered-agent → impact chain in the focused sinks beyond the exclusion list.

## Near-misses (triaged out)

| Candidate | Evidence | Why rejected |
|---|---|---|
| **csyslogd syslog framing / field injection** (`alert.c` DEFAULT/CEF/Splunk) | `src/os_csyslogd/alert.c:97-267` interpolates `comment`, `location`, `log[0]` without CRLF/`\|`/`"` escaping | Requires non-default `<syslog_output>`; GetAlertData strips `\n` via `os_clearnl`, so PRI/hostname stay config/`__shost`; SIEM semantic break only, not manager RCE. JSON path uses cJSON (escaped). |
| **csyslogd format-string** | `field_add_*` take `format` then `value` (`csyslogd.c:88-177`) | `format` is always a string literal from `alert.c`; attacker never controls the format argument. |
| **field_add_string snprintf size formula** | `sizeof(buffer) - dest_sz - 1` is `strlen(dest)-1` (`csyslogd.c:106`) | Empty `dest` would pass a huge `n` and overflow `buffer[2048]`, but callers always `snprintf` a non-empty syslog header first — unreachable. |
| **maild Subject CRLF (default path)** | `os_maild_client.c:131-155`, `sendmail.c:496-510` | Default subject uses location truncated at `>` (agent suffix removed). Remoted always inserts `->`. Agent name charset is `[A-Za-z0-9._-]`. No CRLF in Subject under default `maild.full_subject=0`. |
| **maild Subject CRLF via SMS / full_subject + OpenSCAP title** | `SMS_SUBJECT` / `MAIL_SUBJECT_FULL` use `comment`; `oscap_rules.xml` `description_append` title | Real header injection if granular `SMS_FORMAT` or `full_subject=1`, but both are off by default; same comment control already covered by excluded integrator RCE. |
| **maild body → SMTP header injection** | `MAIL_BODY` after `ENDHEADER` | Location/comment/log with CRLF remain in DATA body after the blank line; not extra SMTP headers. DATA `.` smuggling excluded. |
| **integrator `alertdate` shell injection** | `integrator.c:274` writes unsanitized `date` | Manager clock unless GetAlertData header takeover (excluded); redundant with known location/comment sourcing RCE. |
| **integrator `/tmp` tempfile race** | `integrator.c:187-190` predictable `/tmp/<name>-<time>-<random>.alert` | Local TOCTOU/symlink, not a registered-agent event path. |
| **integrator `system()` hookurl/apikey breakout** | `integrator.c:282` | Values from `ossec.conf` only, not agent-controlled. |
| **ZeroMQ unauthenticated PUB** | `analysisd/output/zeromq.c:66-93` CURVE only if both certs set | Optional `ZEROMQ_OUTPUT_ENABLED` + `zeromq_output`; alert confidentiality exposure when enabled without CURVE, not default. |
| **picviz quote / field break** | `picviz.c:51-55` | Optional `PICVIZ_OUTPUT_ENABLED`; log-format integrity only. |
| **prelude IDMEF** | `prelude.c` uses libprelude typed setters | Optional compile; no SQL/shell sink from agent fields. |
| **jsonout.c** | Thin `Eventinfo_to_jsonstr` wrapper | Known rootcheck JSON issues live in `format/json_extended.c` (out of this focus / already reported). |

## Method

- Traced agent `SECURE_MQ` → remoted `[id] (name) ip` → `OS_CleanMSG` → `OS_Log` → `GetAlertData` / direct analysisd output.
- Re-read all sinks in the four trees for `printf`/`system`/`popen`/CRLF header use.
- Confirmed `os_clearnl` strips only `\n` (not relevant to default Subject), and default Subject truncation removes the agent-controlled `->` suffix.
- Cross-checked against prior hunt near-miss tables for the same sinks to avoid re-reporting.
