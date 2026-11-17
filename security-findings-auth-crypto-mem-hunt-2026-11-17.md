# OSSEC/Wazuh auth/crypto/memory scoped hunt — 2026-11-17

Commit reviewed: `3e0901e328113443cdf30b01ec413e826b6112f7` (master)

## Scope

Authentication/authorization bypass, privilege escalation, IDOR, token/session flaws, cryptography/secrets, buffer/integer overflows, format strings, UAF, dangerous defaults.

Focus areas: `src/os_auth`, `src/os_crypto` (beyond known replay/IV), `src/remoted`, `src/client-agent`, `src/analysisd` (decoders, json_extended remaining, eventinfo), `src/os_net`, `src/os_xml`, `src/os_regex`, `src/os_zlib`, `src/shared`, `src/addagent`, `src/os_execd`, `src/win32`, `src/wazuh_db` (agent `.db` path), `install.sh` / `etc/internal_options.conf` / `etc/ossec.conf` defaults.

## Exclusions honored

- authd open enrollment without `-P`
- agent-auth TLS verify only with `-v`
- TCP signed int32 length overflow (remoted/agents)
- `remoted.verify_msg_id=0` replay
- `json_extended.c` rootcheck 30-byte `sprintf`, unbounded `totalResults`, hostname/location `strncpy` without NUL
- `ossecalert_decoder.c` rule impersonation
- Blowfish static IV as a sole issue

## Result: none validated

No **new** MEDIUM+ findings with a complete registered-agent or network-attacker end-to-end path beyond the exclusion list and previously reported findings.

## Near-misses (failed validation)

| Candidate | Why it failed |
|---|---|
| **wazuh_db `%03d-%s.db` path traversal via agent name** | `wdb_create_agent_db` / `wdb_open_agent` interpolate `name` into `var/db/agents/`. Enrollment and manage-agents gate names with `OS_IsValidName` (`[A-Za-z0-9._-]`, 2..128) — no `/`. `wdb_agent_loc2name` takes the parenthesized name from remoted’s authenticated keystore entry, not the agent-controlled `->` suffix. |
| **RK_File / DB_File / ossecalert `agent_file` `../` write** | After remoted + `OS_CleanMSG`, location is `(name) ip->SUFFIX`. `fopen("/queue/rootcheck/" + location)` only traverses when `SUFFIX` contains `/`, and the first path component is then `(name) ip-><token>` (must already exist as a directory). Agents cannot `mkdir` under `queue/rootcheck`. Local unix-queue forgery without the `[id] (name) ip` prefix can escape, but the alert queue is `0660` and requires existing ossec-group access — outside “registered agent / network attacker”. |
| **`W_JSON_ParseGroups` `strncpy` without NUL** | `strncpy(buffer, lf->generated_rule->group, 1024)` lacks a terminator if `group` ≥ 1024. `group` comes from rule XML (or a looked-up rule via excluded ossecalert), not agent-controlled text. Longest stock rule group ≈ 82 bytes. |
| **`trim()` on empty / `strtok` NULL in `W_JSON_ParseRootcheck`** | ASan confirms `trim("")` is a stack under-read. With the rootcheck regex, captures always contain `: `; `strtok` does not return empty tokens. `trim(NULL)` needs a capture without `:`, which the regex forbids unless an already-excluded overflow corrupts `results[i]`. |
| **`os_zlib_uncompress` `dst[dst_size]='\0'`** | Callers pass dest of size `OS_MAXSTR+1` and max len `OS_MAXSTR`, so the NUL lands on the last in-bounds byte (may clobber the final payload byte, not a past-end write). |
| **authd stays root after chroot** | No `Privsep_SetUser`; pairs with known unterminated `SSL_read` (already reported). No new network→root memory corruption path beyond that. |
| **authd default IP `any` (no `-i`)** | Real binding weakness, but inseparable from excluded open enrollment / replay design; UDP spoofing still bypasses `-i`. Not filed alone. |
| **Windows agent `srandom(time(0))`** | Weak nonce entropy; forging still needs the agent key and lands in the excluded static-IV/replay crypto cluster. |
| **Plugin decoders (pf / sonicwall / symantecws)** | Bounded copies / regex extracts into heap via `os_strdup`. No new rule-impersonation or memory-corruption chain. |
| **`remoted.pass_empty_keyfile=1`** | Keeps remoted up with empty keys; useful only as a helper for excluded open authd, not a standalone bypass. |
| **Integrator / AR / maild / UnmergeFiles / win FILE_UPDATE / description_append** | Already reported in prior hunts; out of scope for this pass. |

## Evidence notes (traced)

- Agent name allowlist: `src/addagent/validate.c:370-387`
- DB path build: `src/wazuh_db/wdb_agent.c:161`, `src/wazuh_db/wdb.c:47-51`
- Location → name: `src/wazuh_db/wdb.c:64-90`
- Rootcheck file join: `src/analysisd/decoders/rootcheck.c:90-99`
- Remoted location prefix: `src/remoted/secure.c:286-294`, `src/shared/mq_op.c:71-85`
- CleanMSG `[id]` strip: `src/analysisd/cleanevent.c:482-497`
- ParseGroups strncpy: `src/analysisd/format/json_extended.c:150`
- Rootcheck trim/strtok: `src/analysisd/format/json_extended.c:104-120`, `350-360`
- Authd `use_pass`/`use_ip_address` defaults: `src/os_auth/main-server.c:147-149`
- zlib NUL: `src/os_zlib/os_zlib.c:30-42`
- Windows PRNG seed: `src/win32/win_agent.c:209-211`
