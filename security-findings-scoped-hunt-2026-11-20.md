# OSSEC/Wazuh scoped AppSec hunt — 2026-11-20

Commit reviewed: workspace `master` at `12bd70ed` (plus prior focus-area code).

## Focus

active-response/ (except ossec-slack.sh), src/os_execd/, src/analysisd/alerts/exec.c (beyond [id] AR), wm_exec.c / wm_oscap.c / oscap.py, logcollector read_command / read_fullcommand, agentlessd, custom_output_search_replace.c.

## Validated finding

### 1. HIGH — Agentless SSH host-key auto-accept + root-only `.ssh` → perpetual MITM credential theft

| Field | Value |
|---|---|
| **Severity** | HIGH |
| **Location** | `src/agentlessd/scripts/ssh.exp` |
| **Title** | Agentless SSH auto-accepts host keys while ossec cannot persist known_hosts |

**Description**

Password-based agentless checks `spawn ssh $hostname`, then on `*sure you want to continue connecting*` send `yes` and later `send "$pass\r"` from `.passlist`. `ossec-agentlessd` setuid’s to `ossec` (home = install prefix via `adduser.sh`) without chroot. Make install creates `${PREFIX}/.ssh` as `0700` root-owned, so user `ossec` cannot write `known_hosts`. Host-key prompts therefore recur; Expect keeps accepting. On-path attacker steals SSH (and optional su) passwords for monitored hosts.

**Impact**

Cross-trust credential theft / access to agentless targets (often network devices) whenever agentless password auth is enabled.

**Attack path**

1. Enable agentlessd; register password hosts.
2. agentlessd runs as `ossec`; cannot update root `0700` `.ssh`.
3. MITM SSH; Expect accepts new host key and sends password.
4. Attacker obtains credentials for the real target.

**Evidence**

- `src/agentlessd/scripts/ssh.exp:23-27`, `46-48`
- `src/agentlessd/scripts/ssh_nopass.exp:18-21`
- `src/agentlessd/scripts/main.exp:84-87`
- `src/agentlessd/scripts/su.exp:21-22`
- `src/agentlessd/main.c:129-147`
- `src/init/adduser.sh:69-75`
- `src/Makefile:434`

**Remediation**

`StrictHostKeyChecking=yes` (or pinned keys); `UserKnownHostsFile` writable by the agentlessd user; install `.ssh` as that user `0700`; remove Expect `yes` on new keys; prefer key auth.

**Why distinct**

Not in the excluded list. Different from agent-auth TLS skip: SSH/su secrets for third-party hosts; root `0700` `.ssh` makes auto-accept perpetual.

---

## Near-misses

| Candidate | Why rejected |
|---|---|
| host-deny tcp_wrappers `:allow`/`spawn` | CRAFTED_IP blocks spaces/`/`; needs `.` in IP; unreliable RCE |
| ossec-tweeter ALERTFULL | No re-parse of `$()` inside expanded vars |
| firewall-drop eval | CRAFTED_IP blocks metacharacters |
| ip-customblock `../` | `/` blocked by CRAFTED_IP |
| disable-account leading `-` | No reliable cross-user impact; not default-bound |
| route-null `default` | Not in default AR bindings |
| exec.c `filename` NULL `%s` | Libc-dependent; often non-fatal |
| custom_output search/replace | Values into fprintf log only |
| wm_oscap / oscap.py | Config argv; `shell=False` / execve |
| logcollector command | `remote_commands=0` default |
| agentless `$args` / unquoted options | Admin `ossec.conf` only |
| register_host `chmod 744` | Parent dirs `0550` block world |
| RK_File/DB_File `../` re-check | Intermediate `(name) ip->..` dir must exist; not creatable remotely |
| prefilter_cmd popen | Admin config + local filenames |
