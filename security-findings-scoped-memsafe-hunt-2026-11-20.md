# OSSEC/Wazuh scoped memory-safety / crypto / protocol hunt — 2026-11-20

Commit: cae5d89028f2cd54e937e3ef013c5b15c4957ef2 (master at hunt start)

Focus: `src/remoted`, `src/os_crypto`, `src/os_net`, `src/os_auth`, `src/analysisd` (excl. already-reported json_extended/rootcheck/dodiff-UAF/ossecalert), `src/client-agent`, `src/logcollector`, `src/syscheckd`, `src/os_xml`, `src/os_zlib`.

Excluded already-reported items honored (18 listed in prompt + prior hunt near-misses unless newly elevated).

## Result: 2 NEW (1 HIGH + 1 MEDIUM)

### 1. HIGH — logcollector `read_snortfull` signed size underflow → `strncat` stack overflow

**Location:** `src/logcollector/read_snortfull.c:17-64`

**Bug:** `f_msg_size` is a signed `int` initialized to `OS_MAXSTR` (6144). After copying a long first `[**] [` line it does `f_msg_size -= strlen(str) + 1`. When the first line is ≥6105 bytes, a later preprocessor/date line calls:

```c
strncat(f_msg, ++q, f_msg_size - 40);
```

with a **negative** third argument. That converts to a huge `size_t`, so `strncat` writes far past stack buffer `f_msg[OS_MAXSTR+1]`.

The Classification / Priority paths can also drive `f_msg_size` negative before the third-line `strncat(f_msg, ++q, f_msg_size)`.

**Attack chain:**

1. Operator enables a localfile with `<log_format>snort-full</log_format>` (supported first-class format in `localfile-config.c` / `logcollector.c`).
2. Attacker can write the monitored file (world/group-writable alert file, compromised snort user, or plant via another writable path).
3. Write a ≥6105-byte line starting with `[**] [` followed by a second line matching `MM/DD-...` with a space (preprocessor path), e.g. `01/13-15:00:00.000000 1.2.3.4 -> 5.6.7.8 PAYLOAD`.
4. `read_snortfull` runs as the logcollector user; `strncat` overflows `f_msg` on the stack → crash or code execution in ossec-logcollector.

**Impact:** Memory corruption in logcollector (typically `ossec` user). Crash of log collection; likely RCE in that process context when the overflow is controlled.

**Remediation:** Track remaining space as `size_t`, reject/clamp when `f_msg_size < 40` (or `< strlen(append)+1`) before every `strncat`, and never pass a signed expression that can go negative as the length.

### 2. MEDIUM — `doDiff` hostname path traversal via syslog + `check_diff`

**Location:** `src/analysisd/dodiff.c:81-102`, `_add2last` at `14-66`; enabler `src/os_regex/os_regex_maps.c` (`hostname_map` allows `/`); rules `etc/rules/ossec_rules.xml:163-167` (rule 533); decoder `etc/ossec_decoders/ossec_decoders.xml:30-32` (`prematch>^ossec: `).

**Bug:** For non-`(agent)` hostnames, `doDiff` builds `/queue/diff/<hostname>/<sigid>/last-entry` with no sanitization of `/` or `..`. Syslog hostname parsing accepts `/` via `hostname_map`. `_add2last` will `mkdir` two trailing path components and `fopen`/`fwrite` attacker log bytes.

**Attack chain:**

1. Operator enables remoted `<connection>syslog</connection>` (and allowed-ips; dotted-quad netmask ACL bypass is a separate already-reported HIGH).
2. Attacker sends a syslog datagram whose hostname is a traversal (e.g. `../../tmp/pwn`) and whose message body starts with `ossec: output: 'netstat -tan` (matches decoder `ossec` + rule 533 `check_diff`).
3. `OS_CleanMSG` sets `lf->hostname` from the crafted hostname; rule 533 calls `doDiff`.
4. Path resolves under the analysisd chroot to e.g. `/tmp/pwn/533/last-entry` and writes attacker-controlled `lf->log`.

**Impact:** Arbitrary directory creation and file write of attacker content as the analysisd user (`ossecr`) anywhere under the OSSEC chroot where parents exist or the two-level mkdir succeeds. Final basename is always `last-entry` under `<sigid>/`, so this is not a free rename overwrite of `client.keys`, but it is a real write-escape from `/queue/diff`.

**Remediation:** Reject hostname bytes outside `[A-Za-z0-9._@-]` (drop `/`), or map hostname through a safe encoding before path join; refuse `..` path components.

## Near-misses (not reported)

| Item | Why not MEDIUM+ |
|------|-----------------|
| Syscheck `DB_File` / RK-style `../` in location | Agent location always prefixed `(name) ip->…`; first path component must exist as a directory; syscheck also bounds `MAX_AGENTS` |
| Agent name `..` → doDiff `/queue/../<sigid>/` | Limited blast (`/queue/<sigid>/last-entry`); admin must enroll name `..` |
| `seechanges_createpath` `..` under DIFF_DIR | Needs `report_changes` (not in default `check_all`) + writable watched dir with `..` name; filter escapes shell metacharacters for `system(diff)` |
| `UnmergeFiles` inner `../` | Stock `MergeFiles` uses basename only; needs hand-crafted merged.mg on manager (trusted) |
| Win `FILE_UPDATE` `\` traversal | Already reported |
| authd `SSL_read` without NUL | Child crash/DoS; prior near-miss; open enroll already HIGH |
| Hardcoded Blowfish CBC IV | Known crypto weakness; alone not a new exploit chain |
| `os_zlib_uncompress` `dst[dst_size]='\\0'` | Already reported; callers use `OS_MAXSTR+1` buffers |
| `OS_RecvConnUDP` off-by-one | Test-only callers |
| logcollector `command=` / `popen` | `remote_commands=0` default |
| os_xml XXE / ENTITY | Custom parser; no external entities |
| Plugin decoders (pf/sonicwall/symantec) | Field extract only; sonicwall `category[8]` strncpy near-miss only |
| TCP negative length / `!id!` UINT_MAX / syslogtcp r_sz=0 | Already reported |

## Exclusions honored

remoted `!id!` underflow; Syslog-TCP `OS_RecvTCPBuffer` r_sz=0; `verify_msg_id=0`; JSON rootcheck 30-byte sprintf; Rootcheck trim(NULL); RK_File 256 cache; doDiff last_events UAF; Rootcheck JSON key injection; Nested-alert decoder impersonation; Nested-alert fopen traversal; OS_IsValidIP dotted-quad netmask; authd pool exit; wazuh_db agent name traversal; W_JSON_ParseGroups strncpy; os_zlib NUL; authd root after chroot; Windows srandom(time); match_regex totalResults OOB; W_JSON_ParseRootcheck fullog strncpy; GetAlertData header smuggling.
