# OSSEC/Wazuh remoted / auth / crypto / analysisd scoped hunt — 2026-11-20

Commit: `27a9e6d57dfd4c00d03a9f17341eb913dfe63cb7` (master at hunt start; findings apply to same tree)

## Result: 2 NEW HIGH

Excluded known items (not re-reported): authd no -P, agent-auth no -v, TCP signed length prefix, verify_msg_id=0, json_extended overflows, ossecalert, UnmergeFiles, win FILE_UPDATE backslash, integrator location/description_append RCE, maild DATA, dbd SQLi, AR [id] misclass, ossec-slack.sh, zip-slip, rootcheck/syscheck fopen traversal.

---

### HIGH-1 — Dynamic `!id!` prefix accounting underflows `ReadSecMSG` size to UINT_MAX (UDP/TCP secure remoted)

**Location:** `src/remoted/secure.c` (`HandleSecureMessage`) → `src/os_crypto/shared/msgs.c` (`ReadSecMSG`) → `src/os_crypto/blowfish/bf_op.c` (`OS_BF_Str`)

**Bug:** For messages starting with `!`, remoted strips `!` + digits + `!` while decrementing `recv_b`, then calls `ReadSecMSG(..., recv_b - 1)` with an `unsigned int` size. When the datagram/frame is exactly `!<id>!` (length = 2 + len(id)), `recv_b` becomes 0 and `recv_b - 1` converts to `0xFFFFFFFF`. `OS_BF_Str` / `BF_cbc_encrypt` then decrypts with that size into stack `cleartext_msg[OS_MAXSTR+1]`.

The payload after the stripped prefix must begin with `:` for `ReadSecMSG` to proceed. remoted’s receive buffer is **not** NUL-terminated per packet and is reused, so bytes past the short frame remain from a prior packet. A prior frame of the form `!<id>!:...` (normal dynamic-IP agent traffic) leaves a `:` at the critical offset. After the short overwrite, the colon check passes and the UINT_MAX decrypt runs **before** MD5/counter authentication — only `OS_IsAllowedDynamicID` (id + IP) is required, not the agent key.

**Attack chain:**
1. Manager runs secure remoted (default `<connection>secure</connection>`).
2. At least one agent exists whose key IP is `any` (authd without `-i`, the common default) **or** attacker can UDP-spoof a pinned agent IP.
3. Attacker learns/guesses the agent id (`001`, `1024`–`1280` for authd dichotomic ids, etc.).
4. Optional prime: send any longer UDP/TCP payload that leaves `:` at index `2+len(id)` (on a live manager, prior `!id!:ciphertext` traffic often already did this).
5. Send exactly `!<id>!` (UDP datagram or TCP frame with length = `2+len(id)` — a **valid positive** length, not the excluded negative TCP prefix).
6. `HandleSecureMessage` passes `buffer_size = UINT_MAX` into `ReadSecMSG` → stack smash in remoted (ossec user). Crash is certain; code execution is plausible.

**Why this is not the known TCP-length bug:** The known issue is a signed TCP length prefix `<= 0` accepted because only `length > OS_MAXSTR` is checked. This bug triggers with a **valid** positive length/UDP size equal to `2+len(id)`, via `!id!` stripping arithmetic, and also affects **UDP**.

**Evidence:**
- `src/remoted/secure.c:223-262` — `!id!` strip, `recv_b -= 2`, `ReadSecMSG(..., recv_b - 1)`
- `src/remoted/secure.c:191-198` — UDP path: no per-packet NUL; buffer reused
- `src/os_crypto/shared/msgs.c:185-197` — requires leading `:`, then `OS_BF_Str(..., buffer_size, ...)`
- `src/os_crypto/blowfish/bf_op.c:24-36` — `BF_cbc_encrypt` with attacker-controlled size
- `src/os_crypto/shared/keys.c:408-424` — `OS_IsAllowedDynamicID` is id+IP only
- `src/addagent/validate.c:92-93` — authd without IP stores `any`
- Local replica: `!001!` after leftover `!001!:...` → `buffer_size = 0xffffffff`

**Remediation:** Reject unless `1 <= (recv_b after strip) <= OS_MAXSTR` before `ReadSecMSG`. Pass the remaining ciphertext length explicitly (do not use `recv_b - 1` after mutating `recv_b`). NUL-terminate the receive buffer at `recv_b`. Cap `OS_BF_Str` size to the cleartext buffer length.

---

### HIGH-2 — Syslog-TCP remoted treats `OS_RecvTCPBuffer` success (0) as byte count → `strncat` overflow

**Location:** `src/remoted/syslogtcp.c` (`HandleClient`) + `src/os_net/os_net.c` (`OS_RecvTCPBuffer`)

**Bug:** `OS_RecvTCPBuffer` returns `0` on success and `-1` on failure; it does **not** return the recv size. `HandleClient` stores that return in `r_sz` and uses it as a length: `(sb_size - r_sz) <= 2` never trips for a full buffer, and `sb_size -= r_sz` never shrinks. Incomplete lines (no `\n`) are `strncat`’d into `storage_buffer[OS_MAXSTR+2]` repeatedly with `n = OS_MAXSTR` until the stack buffer overflows.

**Attack chain:**
1. Operator configures remoted with `<connection>syslog</connection>` and `<protocol>tcp</protocol>` (supported mode; requires `<allowed-ips>`).
2. Attacker’s address is allowed (explicit host or broad CIDR — common for device log collection).
3. Attacker opens TCP to the syslog remoted port and sends repeated chunks **without** newlines (e.g. 100-byte blocks).
4. Child `HandleClient` keeps appending; after ~62×100 bytes, `storage_buffer` overflows.
5. Impact: crash of the forked remoted child; plausible code execution as the remoted user (privileges already dropped via `Privsep_SetUser`).

**Evidence:**
- `src/os_net/os_net.c:384-392` — returns `0` / `-1`, not byte count
- `src/tests/test_os_net.c:43` — tests assert return `== 0` on success
- `src/remoted/syslogtcp.c:56-77` — `r_sz = OS_RecvTCPBuffer(...)`; `sb_size -= r_sz`; `strncat(..., sb_size)`
- `src/remoted/remoted.c:76-78` — TCP non-secure → `HandleSyslogTCP`
- Local simulation: overflow at iteration 61 (`storage_len=6200 > 6146`)

**Remediation:** Change `OS_RecvTCPBuffer` to return the received length (or add a size out-parameter) and update callers. In `HandleClient`, track remaining capacity from `strlen(storage_buffer)` and refuse appends that would exceed `sizeof(storage_buffer) - 1`.

---

## Near-misses (not reported as MEDIUM+)

| Candidate | Why rejected |
|---|---|
| authd `SSL_read(buf, sizeof(buf))` unterminated + OOB walk for closing `'` | Real OOB read/possible 1-byte NUL write; `OS_IsValidName` usually rejects; no reliable CE chain beyond known “root after chroot” near-miss |
| authd stays root after chroot | No new memory corruption that elevates beyond known near-miss |
| `W_JSON_ParseGroups` strncpy | Group strings from rule XML, not agent |
| RK_File / wazuh_db name traversal | Already failed: `OS_IsValidName` / `(name) ip->` first component |
| os_zlib_uncompress `dst[dst_size]='\0'` | In-bounds with `OS_MAXSTR+1` destinations when compress succeeds |
| os_xml XXE / billion laughs | Custom parser; no external entities; `XML_MAXSIZE` caps strings; admin-local files only |
| os_regex execute | Patterns from config; agent supplies subject only; no new remote overflow chain |
| Plugin decoders (pf/sonicwall/symantec) | Field extraction only; AR still gated by CRAFTED_* |
| fts/accumulator/lists/cleanevent | No new attacker→corrupt chain beyond excluded JSON/location bugs |
| remoted.pass_empty_keyfile / win srandom(time) | Prior near-misses; no new complete chain |
| Format-string via attacker log | Logging paths use constant format strings |

## Method notes
- Read remoted secure/syslog/syslogtcp/manager/ar-forward, client-agent receivers, os_auth, os_crypto msgs/keys/bf_op, os_xml, os_regex, os_net, analysisd plugins/fts/accumulator/lists/cleanevent, addagent.
- Confirmed `!id!` underflow with C replica (`buffer_size=0xffffffff`) and Python leftover-`:` simulation.
- Confirmed syslogtcp `r_sz=0` strncat overflow with Python capacity simulation.
