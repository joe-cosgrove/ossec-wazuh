# OSSEC/Wazuh network-facing daemons hunt — 2026-11-20

Commit at hunt start: `6560c7b0` (master)

## Scope

- `src/remoted` (beyond UINT_MAX leftover-colon, syslogtcp r_sz=0, verify_msg_id=0, OS_IsValidIP netmask)
- `src/os_auth` (beyond POOL_SIZE break/exit)
- `src/os_crypto`
- `src/client-agent`
- `src/addagent`

Classes: buffer overflows, auth bypass, key confusion, weak crypto with exploit path, unauthenticated enrollment, file overwrite, command injection. MEDIUM+ only.

## Result: **1 NEW HIGH**

### HIGH — Windows `FILE_UPDATE` backslash path escape (`receiver-win.c`)

**Location:** `src/client-agent/receiver-win.c:173-185` (close/MD5 keep at `191-230`)

**Bug:** Name sanitization replaces `/` with `-` and flips a leading `.`, then `fopen("shared/" + name, "w")`. Backslash is untouched. Windows treats `\` as a separator, so `..\\ossec.conf` escapes `shared/`.

**Attack chain:**

1. Obtain Windows agent key (stolen endpoint, open authd, etc.).
2. Impersonate manager on the secure channel; send `#!-up file <md5> ..\ossec.conf` (or deeper `..\..\..\` chains).
3. Agent `fopen`s outside `shared/` (e.g. install-dir `ossec.conf`, or `Users\Public\...`).
4. Payload frames write content; `#!-close file` MD5 matches attacker-supplied sum; file kept.
5. LocalSystem now executes/trusts attacker-controlled files.

**Why new:** Distinct from UnmergeFiles `../` member traversal. Prior notes assumed FILE_UPDATE sanitization protected the download path; `/`-only filtering fails on Windows `\`.

**Remediation:** Reject `\`, `/`, `..`, and drive prefixes; allowlist basename only under `SHAREDCFG_DIR`.

## Near-misses (not filed)

| Item | Why rejected |
|------|----------------|
| `OS_FreeKeys` + `wait_for_msgs` UAF during key reload | Narrow window after intentional `sleep(1)`; needs concurrent keyfile update |
| authd parallel `OS_AddNewAgent` rename race | Lost enrollment / integrity, not a clean key-confusion exploit |
| `FormatID` `sprintf` into short `strdup` (`manage_agents -e 1`) | Local root admin CLI only |
| syslogtcp unbounded fork | Same allowlist surface as known r_sz=0 overflow; weaker impact |
| Blowfish static IV malleability | No forge path beyond excluded replay |
| authd root-after-chroot / SSL_read NUL | Already filed |

## Remoted / os_auth / os_crypto / addagent

No additional MEDIUM+ complete chains beyond exclusions and the Windows agent finding above.
