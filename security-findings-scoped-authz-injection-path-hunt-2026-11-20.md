# OSSEC/Wazuh scoped authz/injection/path hunt — 2026-11-20

Commit: `cebf1db2e0c9f5eaca05fdb7c266be5309851939` (master)

## Scope

Focus areas from the research brief:

1. `src/wazuh_db/*` SQL concatenation / agent name path (`wdb_agent.c`, `wdb_fim.c`, `wdb_pm.c`)
2. `src/os_dbd/*` remaining SQL interpolation besides alertid
3. Path traversal: syscheck, rootcheck, seechanges, getloglocation, custom_output, file-queue, merge, remoted `c_files`
4. `src/os_csyslogd`, `src/os_maild`, `src/os_integrator` remaining
5. `src/analysisd/format`, `src/shared/custom_output_search_replace.c`, `src/os_xml`, config parsers
6. contrib: `ossec2rss.php`, `ossec2snorby`, `ossec-batch-manager.pl`, `compile_alerts.pl`, `ossec_report_contrib.pl`
7. Win32 UI (`src/win32/ui`)
8. Hardcoded credentials (variable/file:line only)
9. `src/analysisd/decoders/plugins/*` besides ossecalert
10. `extensions/update/ruleset/ossec_ruleset.py`, `src/init/wazuh/*`

Excluded known issues honored (header smuggling / alertid SQLi, nested-alert, ossecalert fopen PT, doDiff hostname PT, json_extended keys, ossec2mysql.pl host CMDi, integratord /tmp symlink, OS_IsValidIP).

## Result: **NONE**

No **NEW** validated MEDIUM/HIGH/CRITICAL findings with complete attacker→impact chains in this scope beyond issues already flagged in prior hunts.

## Validated non-issues (re-checked)

### wazuh_db
- All application SQL in `wdb_fim.c` / `wdb_pm.c` / `wdb_agent.c` uses static SQL + `sqlite3_bind_*`.
- DB path `var/db/agents/%03d-%s.db` uses enrollment-gated names (`OS_IsValidName` = `[A-Za-z0-9._-]`, rejects `/`).
- Runtime name comes from remoted keystore locmsg (`[%s] (%s) %s`), not the agent `->` suffix.
- `SQLITE_OPEN_READWRITE` without CREATE on open — cannot create DBs via path tricks.

### os_dbd (besides alertid)
- Location SELECT/INSERT and PostgreSQL srcip/dstip string interpolation remain vulnerable — **already flagged** (not re-reported).
- `user` / `full_log` go through `osdb_escapestr`; server hostname escaped at insert.
- Rules category insert uses config-time rule group text (admin XML), not agent events.

### Path traversal surfaces
- `seechanges.c`: builds under `DIFF_DIR_PATH/local/<filename>`; `filter()` escapes `"\$\`` before `system(diff)`; watched paths are local config.
- `getloglocation.c`: year/mon/day from `localtime`, not agent fields.
- `file-queue.c`: date-based alert paths only.
- `MergeAppendFile` / remoted `c_files`: embeds `basename` only; stock push cannot plant `../` members.
- `UnmergeFiles`: would follow `../` in hand-crafted `merged.mg` only (manager/admin write to `etc/shared`).
- `DB_File` / `RK_File` `lf->location` fopen: agent `->` suffix can include `/`, but intermediate dirs under `queue/syscheck|rootcheck` are not created — open fails (prior near-miss).
- Windows `FILE_UPDATE` `\` escape — **already flagged**.

### Output daemons / integrator
- Integrator location / OpenSCAP `ruledescription` source RCE — **already flagged**.
- Maild SMTP DATA dot-stuffing — **already flagged**.
- Subject CRLF: default subject truncates at `>` in `->`, stripping agent suffix; `full_subject` is non-default.
- csyslog CEF/Splunk field break: optional `syslog_output`; SIEM-semantic only.
- Unquoted `$ruledescription` in slack/pagerduty does **not** re-parse `$(...)` after assignment (bash parameter expansion ≠ eval); quote-break at `. $ALERTFILE` remains the real RCE (already flagged).

### format / custom_output / os_xml / plugins
- `custom_output_search_replace.c`: pure string replace; no shell/SQL.
- `os_xml`: custom parser; no ENTITY/DOCTYPE/external refs → no XXE.
- Plugins `pf` / `sonicwall` / `symantecws`: field extract only; sonicwall `category[8]` strncpy near-miss only.
- `json_extended` OOB / rootcheck keys / hostname strncpy — already flagged or excluded.

### contrib
- `ossec2snorby` / `ossec2mysqld` / `ossectop` `host $alerthost` — same class as excluded/already-reported ossec2mysql family.
- `ossec2rss.php`: `htmlspecialchars` on lines; intentional web exposure of alerts.log.
- `compile_alerts.pl` / `ossec_report_contrib.pl`: admin CLI concat/report only.
- `ossec-batch-manager.pl`: local keyfile tool; rid unlink uses operator-supplied id.
- `active-list.pl` SQL concat: IP CRAFTED-gated; alertid/ruleid numeric from manager; optional contrib.

### Win32 UI / credentials / init / ruleset
- Win32 UI: local admin dialogs; `set_ossec_server` / `set_ossec_key` write config; `run_cmd` unused by UI paths; `_spawnlp notepad` with fixed paths.
- Placeholder DB passwords in contrib (`$conf{dbpasswd}` in ossec2mysql.pl:94, ossec2mysqld.pl:95, ossec2snorby.pl:136) and `active-list.pl` `$db_pass` — placeholders / samples, not live secrets; below MEDIUM for this bar.
- `ossec_ruleset.py` HTTP zip-slip — **already flagged**.
- `init/wazuh/database.py` parameterized; `upgrade.py` / `wazuh.sh` install-time only.

## Rejected near-misses

1. **host-deny `IP:allow` via CRAFTED_IP colon** — can write `ALL:…:allow` into hosts.deny when combined with known Wazuh `[id]` local-AR misroute; libwrap uncommon on modern sshd; sabotage not RCE; previously rejected.
2. **disable-account leading `-` USER** — CRAFTED allows `-`; `passwd -l ${USER}` option confusion; command not default-bound to any AR.
3. **DB_File/RK_File location `../`** — needs pre-created intermediate directory components under queue/.
4. **UnmergeFiles `../` members** — requires malicious `merged.mg` planted as admin/manager.
5. **Integrator `/tmp` predictable alert names** — local symlink race; excluded class / local attacker.
6. **csyslog CEF pipe/newline injection** — non-default syslog_output; downstream SIEM dependent.
7. **maild Subject via OpenSCAP title CRLF** — requires `full_subject`; default off.
8. **wdb_update_pm bind/placeholder mismatch** — logic bug (no-op/wrong update), not injectable.
9. **Agent name `..` → `001-..db`** — single path component, not parent traversal.
10. **json_extended `dateTimestamp` malloc(21)** — year/mon/hour from localtime, not agent-controlled.
11. **Win32 UI / batch-manager / compile_alerts** — local privileged operator tools only.
12. **Placeholder `$conf{dbpasswd}` / `$db_pass`** — sample defaults; operators expected to override; no remote chain.

## Evidence anchors

- remoted locmsg: `src/remoted/secure.c` (keystore id/name/ip)
- SECURE_MQ suffix: `src/shared/mq_op.c`
- OS_IsValidName: `src/addagent/validate.c`
- wdb binds: `src/wazuh_db/wdb_{fim,pm,agent}.c`
- os_dbd location/PG IPs: `src/os_dbd/alert.c` (prior finding)
- seechanges filter: `src/syscheckd/seechanges.c`
- Merge basename: `src/shared/file_op.c` `MergeAppendFile`
- UnmergeFiles: `src/shared/file_op.c`
- os_xml: no ENTITY paths under `src/os_xml/`
- plugins: `src/analysisd/decoders/plugins/{pf,sonicwall,symantecws}_decoder.c`
