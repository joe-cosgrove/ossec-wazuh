# OSSEC/Wazuh memory-safety / network-protocol hunt — 2026-11-20

Commit: `ec156bb8f99110d36bb0885fa4a8b1775c911d05` (master)

## Scope

`src/logcollector/*.c` (excl. known snortfull/multiline), `src/remoted/*.c`, `src/os_net`, `src/os_crypto`, analysisd plugin decoders, `os_maild`, `os_csyslogd`, `monitord`, `syscheckd`, `rootcheck`, `addagent`, `os_auth`.

## Exclusions honored (not re-reported)

- remoted `!id!` → `recv_b=0` → UINT_MAX Blowfish decrypt overflow
- syslogtcp `OS_RecvTCPBuffer` success `0` as byte count → `storage_buffer` overflow
- remoted TCP `accept` `ErrorExit` on EMFILE
- `read_snortfull.c` signed remaining-length underflow
- `read_multiline.c` size_t underflow
- doDiff `last_events` dangling stack pointer UAF
- `json_extended.c` rootcheck 30-byte `sprintf` / `trim(NULL)`
- DecodeRootcheck `RK_File` unbounded `MAX_AGENTS` cache overflow
- `OS_IsValidIP` dotted-quad netmask ACL bypass
- default `remoted.verify_msg_id=0` replay
- authd `POOL_SIZE` break/exit on exhaustion

## Result: 3 validated (2 HIGH + 1 MEDIUM)

---

### HIGH-1 — Agent TCP length prefix completely unchecked → stack overflow (pre-crypto)

**Location:** `src/client-agent/receiver.c`, `src/client-agent/receiver-win.c`, `src/client-agent/start_agent.c`  
**Type:** `netsize_t` = `int32_t` (`src/headers/shared.h`)

**Description:** On TCP, the agent reads a plaintext `int32_t` length, then `recv(buffer, length)` into `char buffer[OS_MAXSTR+1]` (6145 bytes) with **no** check that `1 <= length <= OS_MAXSTR`. Remoted at least rejects `length > OS_MAXSTR` (still misses `<= 0`); the agent rejects nothing. Framing is processed **before** Blowfish/`ReadSecMSG`.

| length | remoted (`length > OS_MAXSTR`) | agent | effect on agent |
|--------|--------------------------------|-------|-----------------|
| -1 / 0 | accepted (signed gap) | accepted | `size_t` huge → overflow |
| 6144 | accepted | accepted | OK |
| 6145 | rejected | accepted | fills buffer; `buffer[recv_b]='\0'` OOB (+1) in `receiver.c` |
| 7000+ | rejected | accepted | `recv` writes past stack buffer |

**Impact:** Crash or likely code execution as the agent user (Linux `ossec`/chroot; Windows LocalSystem) without possessing the agent key — only MITM / manager impersonation on the TCP framing layer.

**Attack path:**
1. Agent configured with `<protocol>tcp</protocol>` (supported; agent connects out).
2. Attacker is on-path, spoofs/redirects manager IP/DNS, or injects into the agent TCP session.
3. Attacker sends 4-byte little-endian length `7000` (or any `> 6145`), then ≥7000 payload bytes.
4. `receive_msg` / `start_agent` overflows `buffer[OS_MAXSTR+1]` before crypto.

**Evidence:**
- `src/headers/shared.h:104` — `typedef int32_t netsize_t`
- `src/client-agent/receiver.c:45-67` — TCP `recv` length then `recv(..., length)` then `buffer[recv_b]='\0'`
- `src/client-agent/receiver-win.c:80-88` — same
- `src/client-agent/start_agent.c:163-166` — same (no NUL write; still oversized `recv`)
- `src/remoted/secure.c:155` — contrast: remoted has `length > OS_MAXSTR`
- Local model: length=7000 → 855 bytes past `OS_MAXSTR+1`

**Remediation:** After reading the prefix, require `length > 0 && length <= OS_MAXSTR` (and `length <= sizeof(buffer)-1` before any terminating NUL). Close the socket on violation. Apply the same lower-bound check in remoted.

---

### HIGH-2 — csyslogd `field_add_string` / `field_add_truncated` memory corruption on near-full alert buffer

**Location:** `src/os_csyslogd/csyslogd.c` (`field_add_string`, `field_add_truncated`), called from `src/os_csyslogd/alert.c`

**Description:** `OS_Alert_SendSyslog` builds into `char syslog_msg[OS_SIZE_2048]` (exactly 2048 bytes). After a large `snprintf` of location/comment, `strlen(dest)` can be 2047 → `dest_sz`/`available_sz` = 1.

1. **`field_add_string`:** `strncat(dest, buffer, dest_sz)` with `dest_sz==1` writes one payload byte at index 2047 and a NUL at index **2048** — one byte past the array (classic strncat off-by-one; remaining space must reserve the terminator).
2. **`field_add_truncated`:** When `1 <= available_sz <= 3` and the value must be truncated, `field_sz = available_sz - strlen(format) + fmt_size` yields a tiny `malloc(field_sz+1)`, `os_substr` refuses non-positive length (leaves `""`), then `strcat(truncated, "...")` writes 4 bytes into a 1–3 byte heap buffer.

Agent-controlled alert `location` / `comment` / `log[0]` (via registered agent events that become mailed/logged alerts) can inflate the initial `snprintf` so later `field_add_*` calls run with `available_sz` in {1,2,3}.

**Impact:** Stack off-by-one and/or small-heap overflow in `ossec-csyslogd` → crash (DoS of syslog forwarding) or plausible code execution as the csyslogd user when `<syslog_output>` is enabled.

**Attack path:**
1. Operator enables `<syslog_output>` (supported; not shipped enabled by default).
2. Attacker with a registered agent key emits events that produce alerts whose location/comment/log inflate the CEF/DEFAULT/Splunk header `snprintf` to ~2047 bytes (long `->` location suffix and/or long rule comment path).
3. Subsequent `field_add_string` / `field_add_truncated` run with `available_sz` ∈ {1,2,3}.
4. Stack and/or heap memory corrupted.

**Evidence:**
- `src/os_csyslogd/alert.c:23` — `char syslog_msg[OS_SIZE_2048]` (no +1)
- `src/os_csyslogd/alert.c:97-116` — initial `snprintf` then `field_add_*`
- `src/os_csyslogd/csyslogd.c:88-110` — `field_add_string`: `strncat(dest, buffer, dest_sz)`
- `src/os_csyslogd/csyslogd.c:114-156` — `field_add_truncated`: `malloc(field_sz+1)` then `strcat(truncated, trailer)` after failed `os_substr`
- `src/shared/string_op.c:63-70` — `os_substr` returns -3 when `length <= 0` after `dest[0]='\0'`
- Local model: `avail=1` → `malloc(1)` + `strcat("...")` needs 4; `strlen=2047` + `strncat(n=1)` writes index 2048

**Remediation:** Size `syslog_msg` as `OS_SIZE_2048+1` or pass `sizeof(syslog_msg)`. In `field_add_*`, use remaining = `size - strlen(dest) - 1` and never `strncat`/`strcat` without that reserve. In `field_add_truncated`, require `field_sz > (int)strlen(trailer)` before truncate+`strcat`; use `snprintf` into the heap buffer.

---

### MEDIUM-1 — doDiff joins unsanitized syslog hostname into `/queue/diff` path (chroot write)

**Location:** `src/analysisd/dodiff.c` (distinct from the excluded `last_events` stack UAF)

**Description:** When `lf->hostname[0] != '('`, doDiff builds `DIFF_DIR/hostname/sigid/last-entry`. `hostname_map` allows `/`. Stock rule 533 (`check_diff`) matches `ossec: output: 'netstat -tan`, and the `ossec` decoder prematches `^ossec: `, so a syslog UDP/TCP event with a traversal hostname and that body triggers `_add2last` `mkdir`/`fopen`/`fwrite` outside `/queue/diff` under the analysisd chroot.

**Impact:** Unauthenticated (when syslog remote + `allowips` permits the source) write of attacker log bytes to attacker-chosen directories under the OSSEC chroot as `ossecr`. Basename is fixed as `last-entry` under `<sigid>/`.

**Attack path:**
1. Operator enables remoted `<connection>syslog</connection>` with `allowips` including the attacker (or uses the known dotted-quad netmask ACL bypass).
2. Attacker sends syslog: `'<pri>Mon DD HH:MM:SS ../../tmp/pwn ossec: output: 'netstat -tan': crafted\n'`.
3. analysisd decodes as ossec; rule 533 `check_diff` runs doDiff.
4. File `/tmp/pwn/533/last-entry` (in chroot) is created with attacker content.

**Evidence:**
- `src/analysisd/dodiff.c:14-66`, `81-102`
- `src/os_regex/os_regex_maps.c:13-22` — `/` allowed in hostname
- `etc/ossec_decoders/ossec_decoders.xml:30-32`
- `etc/rules/ossec_rules.xml:163-167`
- `src/analysisd/cleanevent.c:127-128`

**Remediation:** Sanitize hostname for path use (reject `/`, `..`, non-allowlisted bytes) or hash/encode it before joining under `DIFF_DIR`.

---

## Near-misses (rejected as NEW MEDIUM+)

| Candidate | Why rejected |
|---|---|
| `create_db.c` `PATH_MAX - dir_size - 2` size_t underflow | Real code bug at `dir_size >= PATH_MAX-1`, but on Linux max creatable dir-with-child length is ~4093; underflow threshold 4095 — unreachable without exotic FS/long-path setups |
| `prefilter_cmd` `popen("%s %s", cmd, fname)` | Unquoted filename injection **if** `<prefilter_cmd>` set; admin config; default `NULL`; default FIM dirs not world-writable |
| `UnmergeFiles` inner `../` | Already reported prior hunts |
| Win `FILE_UPDATE` `\` escape | Already reported; excluded class |
| `json_extended` `fullog` strncpy / `totalResults` OOB | Prior hunt findings; adjacent to excluded 30-byte/`trim` cluster |
| RK_File / DB_File / ossecalert `../` | First path component is `(name) ip-><token>`; intermediate dir must exist — not creatable remotely |
| authd `SSL_read` unterminated buffer | OOB read; `OS_IsValidName` usually rejects; no reliable CE |
| Blowfish static IV alone | MD5 still required; no forge without key |
| `os_zlib` `dst[dst_size]='\0'` | In-bounds with `OS_MAXSTR+1` destinations |
| nmapg / mysql / pgsql / mssql / djb readers | Remaining-space guards adequate for MEDIUM+ |
| Plugin decoders (pf/sonicwall/symantec/ossecalert) | Field extraction; no new remote overflow chain beyond known ossecalert notes |
| maild Subject CRLF | Default truncates at `>`; DATA dot-stuffing excluded |
| monitord / addagent `FormatID` | Local CLI / fixed paths |

## Method

Static review of listed trees; contrasted remoted vs agent TCP framing; modeled csyslogd `available_sz`∈{1,2,3} heap/stack writes; traced doDiff hostname_map `/`; probed `create_db` PATH_MAX reachability on Linux (`best dir-with-child=4093`).
