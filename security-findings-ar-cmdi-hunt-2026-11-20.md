# OSSEC/Wazuh command-injection / RCE hunt — 2026-11-20

Commit reviewed: workspace `master` (`1b58546c` and prior).

## Scope

- `active-response/` (all `.sh` / `.cmd`)
- `src/os_execd/`
- `src/analysisd/alerts/exec.c`, `active-response.c`
- `src/agentlessd/` (excl. known SSH host-key auto-accept)
- `contrib/`, `integrations/`, `wodles/`
- `src/logcollector/read_command.c`, `read_fullcommand.c`
- `src/syscheckd/seechanges.c` `system(diff_cmd)`
- `src/os_crypto/md5_sha1/md5_sha1_op.c` `popen`
- Related: custom_alert_output, csyslogd, maild (header→RCE angle only)

## Exclusions honored

- ossec-tweeter.sh / ossec-slack.sh AR ALERTFULL quote-expansion claims
- ossec2mysql.pl `host $alerthost` backticks
- integratord `/tmp` symlink + slack/pagerduty `. $ALERTFILE` source RCE
- GetAlertData `Rule:` smuggling into integrator
- agentless SSH host-key auto-accept MITM
- Already-flagged: win_execd CreateProcess quote-break, Wazuh `[id]` local-AR misroute, integrator location/comment RCE, etc.

---

## Validated finding

### 1. HIGH — Windows AR `.cmd` scripts expand unsanitized location via unquoted `%4`–`%9` (cmd.exe metachar RCE)

| Field | Value |
|---|---|
| **Severity** | HIGH |
| **Location** | `active-response/win/netsh.cmd:9`, `active-response/win/restart-ossec.cmd:9` |
| **Title** | Windows stock AR scripts re-parse agent-controlled location after `%` expansion |

**Description**

`WinExecdRun` builds:

```text
"<command>" add "<user>" "<ip>" "<tmp_msg>"
```

and passes that single string to `CreateProcess` (`src/os_execd/win_execd.c:208-211`). `tmp_msg` is everything after user/ip — including `time.ftell`, rule id, **`lf->location`**, and filename (`src/analysisd/alerts/exec.c:83-92` / remote AR path). analysisd regex-gates only `dstuser` / `srcip` (`CRAFTED_*`); **location is not sanitized**.

Stock `netsh.cmd` and `restart-ossec.cmd` log with:

```bat
ECHO %DATE% %TIME% %0 %1 %2 %3 %4 %5 %6 %7 %8 %9 >> active-response/active-responses.log
```

That line runs **before** action validation. In `cmd.exe`, `%n` expansion happens first; the resulting line is then re-parsed for `&`, `|`, `<`, `>`. A location suffix containing `&calc&` (no double-quote required) becomes a chained command as LocalSystem.

This is distinct from the already-flagged `win_execd.c` CreateProcess quote-break (`"` in location tearing the outer quotes). Here CreateProcess quoting can be perfect; the sink is the shipped `.cmd` unquoted `%` expansion. Fixing only CreateProcess argv handling does not fix these scripts.

**Impact**

Command execution as LocalSystem on every Windows agent that has active response enabled, whenever the manager forwards an AR whose embedded event location carries cmd metacharacters (including `location=all` fan-out).

**Attack path**

1. Operator enables AR on Windows agents (`<active-response><disabled>no</disabled>` — default is `yes` in `src/win32/ossec.conf:117-119`) and configures a manager AR that reaches those agents (`location` all / specific / remote).
2. Attacker controls a registered agent key.
3. Agent emits an alert-capable event whose SECURE_MQ location suffix contains cmd metacharacters, e.g. `x&calc&y` (agent fully controls the `->` suffix via the location field in its secure message; remoted builds `[id] (name) ip` + that suffix).
4. analysisd fires AR; remoted forwards `execd name user ip <tmp_msg>` with raw location inside `tmp_msg`.
5. `WinExecdRun` launches `netsh.cmd` / `restart-ossec.cmd`; line 9 expands `%4` unquoted; `&calc&` runs as LocalSystem before any netsh/restart logic.

**Evidence**

- `active-response/win/netsh.cmd:9`
- `active-response/win/restart-ossec.cmd:9`
- `src/os_execd/win_execd.c:125-143` (tmp_msg = remainder after user/ip)
- `src/os_execd/win_execd.c:165-166`, `208-211` (quoted CreateProcess line)
- `src/analysisd/alerts/exec.c:83-92`, `105-120` (raw `lf->location` in AR message)
- `src/analysisd/analysisd.c:984-1006` (CRAFTED gates user/ip only; not location)
- `src/remoted/secure.c:286-294`, `src/shared/mq_op.c:71-85` (agent-controlled `->` suffix)
- `src/client-agent/receiver-win.c:120-125`

**Remediation**

- In all Windows AR `.cmd` files, quote expansions: `ECHO ... "%4" ...` (and never pass location into a line that cmd will re-parse).
- Prefer dropping location/filename from Windows AR argv entirely for scripts that only need action/user/ip.
- Sanitize location the same way as CRAFTED_IP (reject `&|<>()%%"` etc.) before `OS_Exec`.
- Keep Windows AR disabled unless required.

**Why distinct / not excluded**

Not the CreateProcess `"` break (different sink and trigger byte). Not slack/tweeter/integrator/mysql/agentless-MITM exclusions.

---

## Result summary

**1 NEW HIGH** finding (Windows `.cmd` unquoted `%` / location metachar RCE).

No additional NEW MEDIUM+ end-to-end cmdi/RCE chains validated in the remaining scoped sinks beyond exclusions and already-flagged issues.

## Near-misses (why they fail)

| Candidate | Why not MEDIUM+ RCE |
|---|---|
| host-deny `ALL:${IP}` with `1.2.3.4:allow` | CRAFTED_IP allows `:`; can invert tcp_wrappers action (AR sabotage). `spawn` needs space/`/` — both blocked. Not command execution. |
| firewall-drop.sh `eval` (ipfilter/AIX) | Shell metacharacters required for breakout are blocked by CRAFTED_IP on the AR path. |
| firewalld-drop rich-rule `'${IP}'` | Single quote / spaces blocked by CRAFTED_IP. |
| disable-account.sh unquoted `$USER` | CRAFTED_USER allows leading `-`/`?` (option/glob confusion only). Command defined but **not** default-bound. |
| route-null.sh `route add ${IP} reject` | `default` matches CRAFTED_IP but script not default-bound. |
| ossec-slack.sh / ossec-tweeter.sh `${ALERTFULL}` | Parameter expansion does **not** re-scan `$()` / backticks (verified in `sh`). Excluded class / false-positive twin. |
| Linux AR `echo "... $4 $5"` | Inside double quotes, `;|&` are literal; `$()` from expanded values is not re-parsed. |
| seechanges.c `system(diff_cmd)` | Paths double-quoted; Unix `filter()` escapes `` "\ $` ``. Windows filter rejects `%`. `&` inside quoted `fc` args is literal to cmd. |
| md5_sha1_op.c `popen("%s %s", prefilter, fname)` | Real unquoted-filename injection **if** `<prefilter_cmd>` is set, but that is admin config; default `NULL`. Default FIM dirs are not world-writable → no default LPE chain. |
| logcollector `popen(command)` | Command from local `ossec.conf`; `logcollector.remote_commands=0` by default. |
| agentless `popen` / `$args` / `diff_cmd` | Host/type/options from admin `ossec.conf` / `.passlist` only. Compromised SSH *target* can spoof FWD:/LOG: lines (alert injection), not manager shell. Host-key MITM excluded. |
| custom_alert_output / OS_CustomLog | Token replacement into `fprintf` log only — no shell. |
| csyslogd alert formatting | Syslog framing to network only; no `system`/`popen`. |
| maild Subject/headers | CRLF subject issues are mail/header class; SMTP DATA relay already flagged; no shell/RCE sink from headers in-tree. |
| integrations/slack `. $ALERTFILE` | Excluded (known source RCE / Rule smuggling / location). |
| contrib ossec2mysql/ossectop `host $alerthost` | Excluded known pattern. |
| wodles/oscap/oscap.py | `subprocess` argv list, `shell=False`; args from wodle config. |
| exec.c remote NULL `filename` | Prints `(null)` / UB — not injection. |
| active-list.pl SQL concat | Optional contrib; IP forced through dotted-quad check + CRAFTED_IP; alertId/ruleId manager-numeric. |
| route-null.cmd `%2` | Uses user slot as IP (broken wiring vs execd argv); CRAFTED_USER blocks dots → not a working IP inject path. |
