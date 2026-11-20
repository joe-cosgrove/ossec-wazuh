# OSSEC/Wazuh remoted / auth / crypto / client-agent / os_net hunt — 2026-11-20

Commit at hunt start: `1b58546cc9616ba7aaade65ad02e3869f01e98f1` (master)

## Scope

- `src/remoted/` (secure.c, syslog.c, syslogtcp.c, manager.c, sendmsg.c, ar-forward.c)
- `src/os_auth/`, `src/os_crypto/`, `src/client-agent/`, `src/os_net/`

## Exclusions honored (not re-reported)

- plaintext `!id!` leftover colon UINT_MAX decrypt overflow
- syslogtcp `OS_RecvTCPBuffer` returns 0 → strncat overflow
- `remoted.verify_msg_id=0` replay
- `OS_IsValidIP` dotted-quad netmask ACL bypass
- authd pool exhaustion DoS
- Blowfish static IV alone

Also not re-filed as “the remoted signed TCP length” issue (remoted checks `length > OS_MAXSTR` but misses `<= 0`). Finding #1 below is a **different** agent-side bug: **no length gate at all**, including **positive** oversized frames that remoted would reject.

## Result: 2 NEW HIGH

---

### HIGH-1 — client-agent TCP length prefix has no bounds check → stack overflow (pre-crypto)

**Location:** `src/client-agent/receiver.c:45-52`, `src/client-agent/receiver-win.c:80-88`, `src/client-agent/start_agent.c:163-166`  
**Type:** `netsize_t` = `int32_t` (`src/headers/shared.h:104`)

**Bug:** On TCP, the agent reads a plaintext `int32_t` length, then `recv(buffer, length)` into `char buffer[OS_MAXSTR+1]` (6145 bytes) with **no** check that `1 <= length <= OS_MAXSTR`. Remoted’s secure path at least rejects `length > OS_MAXSTR` (still missing `<= 0`); the agent rejects nothing.

| length | remoted (`length > OS_MAXSTR`) | agent | effect on agent |
|--------|--------------------------------|-------|-----------------|
| -1 | accepted (signed gap) | accepted | `size_t` huge → overflow |
| 6144 | accepted | accepted | OK |
| 6145 | **rejected** | accepted | fills buffer; `buffer[recv_b]='\0'` OOB (+1) in `receiver.c` |
| 6146+ / 7000 | **rejected** | accepted | `recv` writes past stack buffer |

**Attack chain:**
1. Agent configured with `<protocol>tcp</protocol>` (supported; agent connects out to manager).
2. Attacker is on-path (MITM), spoofs/redirects the manager IP/DNS, or otherwise injects into the agent’s TCP session.
3. Attacker sends a 4-byte little-endian length `7000` (or any `> 6145`), then ≥7000 payload bytes.
4. Framing is processed **before** Blowfish/`ReadSecMSG` — no agent key required for the overflow.
5. Stack buffer in `receive_msg` / `receiver_thread` / `start_agent` overflows → crash; exploitable corruption is plausible. Windows agent path runs as LocalSystem; Linux agent as `ossec` inside chroot.

**Why this is not the excluded / remoted signed-length item:** Remoted refuses positive `length > OS_MAXSTR`. This finding is agent-side total absence of validation, demonstrated with **positive** lengths remoted would drop. User exclusion list did not include TCP length bugs; prior notes about “signed remoted length” do not cover this agent positive-overflow gate gap.

**Evidence:**
- `src/headers/shared.h:104` — `typedef int32_t netsize_t`
- `src/client-agent/receiver.c:39-57` — TCP recv length then `recv(..., length)` then `buffer[recv_b]='\0'`
- `src/client-agent/receiver-win.c:74-93` — same
- `src/client-agent/start_agent.c:162-171` — same (no NUL write, still oversized `recv`)
- `src/remoted/secure.c:155` — contrast: remoted has `length > OS_MAXSTR`
- Local model: length=7000 → 855 bytes past `OS_MAXSTR+1` stack buffer

**Remediation:** After reading the prefix, require `length > 0 && length <= OS_MAXSTR` (and ideally `length <= sizeof(buffer)-1` before any terminating NUL). Close the socket on violation. Apply the same check in remoted for `length <= 0`.

---

### HIGH-2 — remoted secure TCP: unbounded accepts + `ErrorExit` on `accept` failure → unauthenticated daemon kill

**Location:** `src/remoted/secure.c:132-146` (also `epoll_ctl` ADD/DEL `ErrorExit` paths at 144-145, 164-165, 179-180)

**Bug:** In TCP secure mode, every `accept` is added to epoll with **no connection limit and no idle timeout**. Failed `accept` (e.g. `EMFILE`/`ENFILE` after FD exhaustion) calls `ErrorExit(ACCEPT_ERROR)`, terminating the whole remoted process. Syslog-TCP correctly `continue`s on accept failure (`syslogtcp.c:174-177`); secure TCP does not.

**Attack chain:**
1. Manager enables secure remoted with `<protocol>tcp</protocol>` (supported; default stock conf is UDP, but TCP is first-class).
2. Attacker opens and holds ~`ulimit -n` TCP connections to the remoted port (default 1514), sending no data (FDs stay open; no `SO_RCVTIMEO` on accepted sockets).
3. Next `accept` returns -1 (`EMFILE`/`ENFILE`).
4. `ErrorExit(ACCEPT_ERROR)` kills remoted → all agents lose the manager channel until an external supervisor restarts it.
5. No agent key, enrollment password, or allowed-ips check is involved (secure TCP accepts before crypto).

**Evidence:**
- `src/remoted/secure.c:133-136` — `accept` → `ErrorExit`
- `src/remoted/secure.c:143-146` — `epoll_ctl(ADD)` → `ErrorExit`
- `src/error_messages/error_messages.h:94` — `ACCEPT_ERROR`
- `src/remoted/syslogtcp.c:174-177` — safer pattern (`merror` + `continue`)
- `src/config/remote-config.c:211-214` — TCP is explicit config; UDP is default when unset
- `src/os_net/os_net.c:503-507` — `OS_SetRecvTimeout` exists but is not applied to remoted client FDs

**Remediation:** On `accept` failure, log and `continue` (at least for `EMFILE`/`ENFILE`/`ECONNABORTED`/`EINTR`). Cap concurrent unauthenticated connections; set idle recv timeouts; never `ErrorExit` for recoverable accept/epoll errors on live client FDs.

---

## Near-misses (not reported as MEDIUM+)

| Candidate | Why rejected |
|-----------|--------------|
| Remoted signed TCP `length <= 0` | Related known class; remoted upper-bound exists; agent finding above covers the stronger agent gap |
| AR-forward “missing auth” | Trusts Unix `ARQUEUE` (`0660`); remote agents cannot write it; local ossec-group is trusted IPC by design |
| manager.c merge path / `send_file_toagent` | Names from `readdir` of manager `SHAREDCFG_DIR`; `MergeAppendFile` uses basename only |
| agent.conf injection via protocol | Agents cannot upload into manager shared/; push is manager→agent |
| key-request protocol | Not present in this tree (legacy authd enrollment only) |
| agent-auth TLS verify only with `-v` | Already reported prior hunt |
| check_cert `CN=*` / `*.com` wildcards | Matches single-label / one-level names; needs a CA-issued pathological cert — no practical untrusted-CA path |
| authd `SSL_read` unterminated / root after chroot | Prior near-miss / related reports; no new complete CE chain |
| UnmergeFiles `../` | Already reported |
| Win `FILE_UPDATE` `\` escape | Already reported |
| GetRandomNoise `strdup` truncates at NUL | Avg ~256 bytes entropy; both empty is ~1/65536 at startup — not a reliable break |
| Blowfish static IV bit-flip | MD5 over plaintext still required; no forge without key (excluded cluster) |
| `OS_FreeKeys` / `wait_for_msgs` UAF | Narrow reload race; prior near-miss |

## Method

Static review of listed directories; contrasted remoted vs agent TCP framing; modeled overflow sizes; confirmed accept/`ErrorExit` vs syslogtcp `continue`; re-checked authd/check_cert/AR-forward/manager merge against exclusions and prior hunts.
