# OSSEC/Wazuh analysisd + logcollector deep hunt — 2026-11-20

Commit reviewed: `1b58546cc9616ba7aaade65ad02e3869f01e98f1`

## Scope

- `src/analysisd/` — decoders (plugins + hostinfo/geoip), format/json (non-excluded), alerts, accumulator, fts, lists, dodiff (non-excluded), stats, output, OS_Log / OS_CustomLog
- `src/logcollector/` — nmapg, mysql, postgresql, mssql, djb, ossecalert, win_el, win_event_channel, syslog, command (excl. known snortfull + multiline overflows)

## Exclusions honored

GetAlertData header smuggling; JSON rootcheck 30-byte sprintf; trim(NULL); rootcheck key injection; nested-alert rule impersonation; nested-alert fopen traversal; RK_File unbounded cache; doDiff dangling last_events; doDiff hostname path via ASL Host; DecodeSyscheck/DecodeRootcheck fopen(lf->location); snortfull + multiline overflows.

## Result: NO NEW validated MEDIUM/HIGH/CRITICAL

No complete new attack chain reached MEDIUM+ after source review and cross-check against prior hunts on this tree.

## Near-misses (below bar or blocked)

| Area | Why not MEDIUM+ |
|------|-----------------|
| `read_nmapg` signed `final_msg_s` | Truncated huge IP makes `final_msg_s` negative; guarded by `final_msg_s < 27` before `strncat` |
| `read_mysql` / `read_postgresql` / `read_mssql` room checks | Continuation path uses `sizeof(buffer) - buffer_len > str_len + 256`; `buffer_len` cannot exceed buffer; no underflow write |
| `read_djb_multilog` `strncpy(buffer, p, OS_MAXSTR)` | `fgets` cap `OS_MAXSTR - OS_LOG_HEADER` keeps `p` shorter than `OS_MAXSTR`; NUL always copied |
| `read_ossecalert` snprintf assembly | Bounded by `OS_SIZE_2048`; GetAlertData smuggle excluded |
| `read_win_el` `size_left` accounting | Negative `size_left` skips further `strncat`; max length stays under `OS_MAXSTR` |
| SonicWall `category[8]` `strncpy(..., 7)` no NUL | Only compared to short literals (`"32"`, etc.); `strcmp` returns before OOB |
| Accumulator `_key` / NULL hostname | Truncation rejected; agent/local paths set hostname before accumulate |
| FTS / IGnore newlines | `IGnore` `strcmp` broken by `fgets` newline; stock ignore rules not a reliable suppress surface |
| FTS / hostinfo unbounded growth | Registered agent can grow `/queue/fts/*` and hostinfo DB (CPU/disk); same class as known RK growth; no memory-corruption chain |
| Lists `OS_DBSearchKeyAddressValue` `malloc(vlen)` without NUL | `_os_strcmp`/`strcasecmp` OOB read possible, but no stock rules use address `match_value` lists |
| Lists `RULE_DYNAMIC` + NULL `lf->fields[i]` | NULL deref if custom list-on-dynamic-field rule; no default rules |
| `custom_output_search_replace` / `OS_CustomLog` | Fixed search tokens; values not re-parsed as format/shell; cross-token injection only reshapes alert text |
| `W_JSON_ParseGroups` / Groups strncpy | Rule `group` is admin XML, not agent-controlled |
| `W_JSON_ParseTimestamp` `sprintf` into 21 | Exact fit for normal dates; year≥10000 only |
| Picviz quote injection | Optional `PICVIZ_OUTPUT_ENABLED` compile flag |
| `logcollector command=` | `remote_commands` default 0 |
| `getloglocation` paths | `year`/`mon`/`day` from `localtime`, not attacker |
| doDiff agent-name `..` | `OS_IsValidName` allows `.` so name `..` → `/queue/<sigid>/last-entry`; limited ossec-write blast; below MEDIUM vs ASL `/` finding |

## Surfaces reviewed (source)

- logcollector: `read_nmapg.c`, `read_mysql_log.c`, `read_postgresql_log.c`, `read_mssql_log.c`, `read_djb_multilog.c`, `read_ossecalert.c`, `read_syslog.c`, `read_win_el.c`, `read_win_event_channel.c`, `read_command.c`/`read_fullcommand.c`
- analysisd plugins: `sonicwall_decoder.c`, `pf_decoder.c`, `symantecws_decoder.c`, `hostinfo.c`, `geoip.c`
- analysisd core: `accumulator.c`, `fts.c`, `lists.c`/`lists_list.c`/`lists_make.c`, `stats.c`, `alerts/log.c`, `alerts/getloglocation.c`, `alerts/exec.c`, `format/json_extended.c` (non-rootcheck paths), `format/to_json.c`, `output/{jsonout,picviz,zeromq,prelude}.c`, `cleanevent.c` ASL path (non-doDiff), `dodiff.c` (non-excluded angles only)
