# OSSEC/Wazuh auth/authz/crypto/secrets hunt — 2026-11-20

Commit: 1bf240ddbcb1a5557b480459762d0ba662715dcc (master)

## Scope

- `src/os_auth/`, `src/os_crypto/`, `src/addagent/`, `src/remoted/` (beyond excluded bugs)
- `src/os_crypto/shared/keys.c`, `src/shared/validate_op.c`
- Token/session/key handling, hardcoded credentials

## Excluded (do not re-report)

- remoted `!id!` leftover colon UINT_MAX overflow
- Syslog-TCP `OS_RecvTCPBuffer` r_sz=0 overflow
- `remoted.verify_msg_id=0` replay
- Agentless SSH auto-accept host keys
- Blowfish static IV alone

## Result: 2 NEW findings (1 HIGH, 1 MEDIUM)

### 1. HIGH — `OS_IsValidIP` dotted-quad netmask uses address instead of mask (ACL bypass)

**Location:** `src/shared/validate_op.c:361-366`

**Bug:** In the “Full netmask” branch (`a.b.c.d/w.x.y.z`), after nul-terminating at `/`, `nmask` is set with `inet_addr(ip_address)` (the network address) instead of `inet_addr(tmp_str)` (the mask). Only the literal `255.255.255.255` mask is handled correctly. CIDR forms (`/24`) are unaffected.

**Attack chain (syslog remoted):**
1. Operator enables `<connection>syslog</connection>` (UDP or TCP) and sets e.g. `<allowed-ips>10.0.0.0/255.255.255.0</allowed-ips>` (syntax allowed by `ip_address_regex`).
2. Intended policy: only `10.0.0.0/24`.
3. Effective check becomes `(client_ip & 10.0.0.0) == 10.0.0.0`, which accepts large unrelated ranges (e.g. `11.0.0.1`, `14.0.0.1`, `42.1.1.1`, `255.0.0.1`).
4. Network attacker spoofs/sends syslog from an incorrectly allowed IP past `OS_IPNotAllowed` in `syslog.c` / `syslogtcp.c`.
5. Impact: unauthenticated alert injection into analysisd (and any enabled mail/AR/integrations fed by those alerts). Same bug weakens `denied-ips`, agent IP CIDR-with-dotted-mask binding via `OS_IsAllowedDynamicID` → `OS_IPFound`, and AR `white_list` matching.

**Evidence:**
- `src/shared/validate_op.c:17-19` (regex allows dotted mask)
- `src/shared/validate_op.c:332-366` (bug: `inet_addr(ip_address)` for nmask)
- `src/shared/validate_op.c:223-244` (`OS_IPFound` uses stored netmask)
- `src/config/remote-config.c:160-174` (allowed-ips → `OS_IsValidIP`)
- `src/remoted/syslog.c:94-98`, `src/remoted/syslogtcp.c:179-183`

**Remediation:** Use `inet_addr(tmp_str)` (or parse the mask octets) when setting `nmask`. Add regression tests for `10.1.2.0/255.255.255.0` vs `10.1.3.1` / `11.1.2.1`.

### 2. MEDIUM — authd exits permanently when enrollment pool is exhausted

**Location:** `src/os_auth/main-server.c:381-383`

**Bug:** When `active_processes >= POOL_SIZE` (512), the accept loop `break`s out of `while (1)` and falls through to `clean_exit`, shutting down authd instead of refusing the connection and continuing to serve.

**Attack chain:**
1. Attacker can reach TCP 1515 (authd listening).
2. Opens 512 TCP connections and holds them (children block in `SSL_accept` / `SSL_read`; parent already counted them in `active_processes`).
3. One more successful `accept` hits the pool check and `break`s.
4. Authd calls `clean_exit` and terminates until an external supervisor restarts it.
5. Impact: unauthenticated availability kill of enrollment (no agent key required).

**Evidence:**
- `src/headers/defs.h:39` (`POOL_SIZE 512`)
- `src/os_auth/main-server.c:358-384` (loop + break)
- `src/os_auth/main-server.c:571-572` (`clean_exit` after loop)

**Remediation:** On pool exhaustion, `close(client_sock)` and `continue` (optionally with a short delay). Never leave the listen loop for a concurrency limit.

## Checked — no NEW MEDIUM+ complete chains

| Area | Notes |
|------|--------|
| `os_auth` enrollment crypto | Open enrollment without `-P`, agent-auth without `-v`, password logged, SSL_read NUL — already reported in prior hunts; not re-filed |
| `os_crypto` msgs/keys | Auth is Blowfish+zlib+MD5 under agent key; static IV alone excluded; no forge path without key |
| `keys.c` / ID-IP maps | Empty `pass_empty_keyfile` does not accept traffic; duplicate `any` uses `!id!` path |
| `addagent` import/bulk | Local CLI; names/IDs validated; `wdb_insert_agent` parameterized |
| `remoted` secure/manager | Excluded length/`!id!`/verify_msg_id bugs; control/file push uses manager-side shared dir names; peer_info update requires valid decrypt |
| Hardcoded credentials | No live passwords/API keys in first-party `src/` (placeholders / rule sample logs only) |
| GetRandomNoise + strdup | Truncates at NUL before MD5; still ~256 bytes expected entropy — rejected as practical break |
| Concurrent authd keyfile race | Can drop a key line under parallel enroll; integrity/DoS, not silent takeover of pinned agent without `-f` |

## Near-misses rejected

1. Authd never `Privsep_SetUser` (root after chroot) — elevates impact of other authd bugs; no new write primitive.
2. `agent-auth` `OS_StrBreak` NULL deref on OOM — local crash only.
3. MD5/Blowfish age — integrity bound to shared key; no new offline forge without key.
4. `OSHash_Get` NULL-key infinite loop — keys not attacker-null in this path.
