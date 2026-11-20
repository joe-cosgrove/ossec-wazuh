# OSSEC/Wazuh analysisd/logcollector/syscheck/execd/AR hunt — 2026-11-20

Scope: `src/analysisd` (beyond known GetAlertData/json_extended/trim/JSON-key/ossecalert/RK_File/doDiff-UAF), `src/logcollector` (beyond snortfull), `src/syscheckd`, `src/os_execd`, `src/rootcheck`, `active-response/` (beyond tweeter), with explicit validation of doDiff hostname `/` path join.

## Result: 2 NEW (1 HIGH + 1 MEDIUM)

### 1. HIGH — `read_multiline` size_t underflow → stack overflow

| Field | Value |
|---|---|
| **Title** | Multiline log reader underflows remaining length and overflows `buffer[OS_MAXSTR+1]` |
| **Severity** | HIGH |
| **Location** | `src/logcollector/read_multiline.c:66-72` |

**Evidence:** Accumulation does `strncpy(buffer + buffer_size, str, OS_MAXSTR - buffer_size - 2)` after optionally writing a space at `buffer[buffer_size]`. With `log_format` multiline N where N≥3, two max-length lines (`fgets` of `OS_MAXSTR - OS_LOG_HEADER`) leave `strlen(buffer)` ≈ 6142–6144. The third line then computes `OS_MAXSTR - buffer_size - 2` as a wrapped `size_t` and `strncpy`s past the end of the stack buffer. Local replica: after two long lines, L3 prints `n=18446744073709551615`; ASan aborts on a bounded OOB write at `buffer+6143`.

Distinct from `read_snortfull` (different file, `f_msg_size - 40` signed underflow).

**Attack path:**
1. Operator configures `<localfile><log_format>multiline:3</log_format>` (or higher) on a writable path.
2. Attacker writes ≥3 lines each ≥~5887 bytes (no early newline).
3. `read_multiline` underflows the `strncpy` length on the third accumulation.
4. logcollector crashes or corrupts stack as the logcollector user.

**Impact:** Denial of service; likely native code execution in ossec-logcollector when multiline monitoring is enabled.

**Remediation:** Track remaining capacity as `size_t`; refuse to append when `buffer_size + 1 + strlen(str) >= OS_MAXSTR`; always NUL-terminate after `strncpy`.

### 2. MEDIUM — `doDiff` path join allows `/` in hostname (ASL Host), distinct from UAF / ossecalert

| Field | Value |
|---|---|
| **Title** | `doDiff` joins unsanitized hostname into `/queue/diff/.../last-entry` enabling chroot path traversal writes |
| **Severity** | MEDIUM |
| **Location** | `src/analysisd/dodiff.c:14-66,81-102` (+ `cleanevent.c:431-447`, `os_regex_maps.c:13-22`) |

**Validation (requested):**
- **Real:** Yes. `_add2last` `mkdir`/`fopen`/`fwrite` on `DIFF_DIR/hostname/sigid/last-entry` with no rejection of `/` or `..`.
- **Distinct from UAF:** Yes. UAF is `rule->last_events[1] = flastcontent` (stack). This is a filesystem write sink on the same `snprintf` path.
- **Distinct from ossecalert fopen:** Yes. ossecalert writes `AGENTINFO_DIR/hostname->location` from the nested-alert decoder; this writes under `/queue/diff` via `check_diff`.
- **Stock traditional syslog same-line does NOT work:** `Jan … ../../evil ossec: output:…` makes CleanMSG treat `ossec` as `program_name` and strips it from `lf->log`, so decoder `^ossec: ` / rule 530 fail. Prior memsafe writeup that claimed that chain overstated reachability.
- **Reachable stock chain:** OSX ASL-shaped events set `lf->hostname` from `[Host …]` with **no** `hostname_map` filter (cleanevent Host branch), while `lf->log` stays the `[Message …]` body. Message `ossec: output: 'netstat -tan': …` matches rules 530/533; Host `../../etc/shared` yields `queue/diff/../../etc/shared/533/last-entry`. Syslog remoted (or a monitored ASL file) required; secure agent path only uses alphanumeric agent names inside `(…)`, so agents alone cannot inject `/` into the paren branch.

**Attack path:**
1. Enable remoted syslog (or monitor ASL logs) so analysisd sees ASL-framed lines.
2. Send two ASL events with `[Message ossec: output: 'netstat -tan': A|B]` and `[Host ../../etc/shared]` (or other existing chroot parent).
3. Rule 533 `check_diff` → `doDiff` → `_add2last` creates `<escaped>/533/last-entry` and writes attacker message bytes as `ossecr`.

**Impact:** Attacker-controlled file create/overwrite of `…/<sigid>/last-entry` under attacker-influenced directories inside the analysisd chroot (e.g. under `etc/shared/`). Basename is fixed; not a free rename to `ar.conf`, but still a path-traversal write primitive.

**Remediation:** Reject hostname path components containing `/`, `..`, or non-allowlisted bytes; hash/encode the host key before joining under `DIFF_DIR`.

## Near-misses / NONE in other scoped areas

- **Syscheck decoder `DB_File` / rootcheck `RK_File`:** `lf->location` may contain `../`, but path components require a missing intermediate directory `(name) ip->..` before traversal resolves; same class as prior exclusions. Not new MEDIUM+.
- **syscheckd `seechanges`:** `system(diff …)` escapes `"\$\``; directory entries cannot embed `/`; `report_changes` is opt-in. No new MEDIUM+.
- **logcollector mysql/pgsql/mssql/command/nmapg:** pgsql/mssql room checks prevent `strncat` overflow; `command=` gated by `remote_commands` default 0; no journal reader in this tree.
- **os_execd Linux:** `execv` argv; CRAFTED_IP/USER regex before AR. Win `CreateProcess` quote break already filed.
- **active-response (non-tweeter):** `ossec-slack.sh` double-quote `${ALERTFULL}` already filed; host-deny/firewall-drop/ip-customblock/disable-account use argv after IP/user allowlists; firewall-drop `eval` near-miss only with allowlisted IP.
- **doDiff agent `(name)` branch:** `OS_IsValidName` alphanumeric only — no `/`.

## Exclusions honored

GetAlertData smuggling; json_extended rootcheck 30-byte; trim(NULL); JSON key injection; ossecalert rule impersonation + fopen traversal; rootcheck RK_File 256; doDiff dangling `last_events`; read_snortfull; ossec-tweeter.sh.
