# PIA WireGuard OPNsense Stack — Deep Audit
**Auditor:** opencode · **Hosts:** Router `172.16.1.1` (OPNsense, csh) · DNS/DHCP `172.16.1.2` (Technitium+nginx, csh) · Client `172.16.1.101` (Debian, systemd-resolved)

> **Two audits, one file.**
> - **2026-10-28 ~20:08 — Post-cleanup deep audit (current focus):** verifies the split-brain fix held and the deployment is clean + coherent (sections A–H below).
> - **2026-10-28 ~16:15 — Original confirmation re-audit:** the full baseline-vs-observed matrix A–G (further down).

---

## 🔬 POST-CLEANUP DEEP AUDIT — `172.16.1.1`  (2026-10-28 ~20:08 ET)
*Runs after the split-brain fix + full cleanup. Besides the usual health checks, **G** verifies the deployment is coherent (one script, right place, right config, right monitor) and **H** proves the new script survives the real 5-minute monitor.*

### A — Crash triggers — 🟢 clean
| Check | Observed | Verdict |
|---|---|---|
| `PHP_errors.log` | **ABSENT** (no Fatal/Exception/Warning) | PASS |
| `/var/crash/` dumps | **0** real (no panics/OOM coredumps) | PASS |

### B — Kernel + logs — 🟢 clean
| Check | Observed | Verdict |
|---|---|---|
| Kernel panic / OOM / watchdog / hw-err | 0 / 0 / 0 / 0 | PASS |
| System log errors | 0 | PASS |
| configd errors | 2 — both the *old* 17:40 "Execute error", **pre-cleanup** residue (see H) | PASS (historical) |

### C — Idempotency — 🟢 solid
Ran the `/conf/` script **twice**, both `exit 0`, `PHP_errors.log` stayed **ABSENT** after. No runaway artifacts, no crash noise.

### D — Tunnel + split-horizon — 🟢 correct
| Check | Observed | Verdict |
|---|---|---|
| `wg0` | UP, handshake 1m40s, 57 MiB in / 16 MiB out | PASS |
| Router egress | `104.159.102.188` (ISP — traffic bypasses tunnel) | PASS |
| `default` route | → `104.159.102.129` via `vtnet1` | PASS |
| `193.56.117.221/32` (Jellyfin) | → `172.16.1.3` via LAN — split-tunnel intact | PASS |
| `100.64.0.0/10` + `192.168.0.0/24` | → `172.16.1.3` (Tailscale/LAN) | PASS |

### E — Artifacts — 🟢 no orphans
1 server (`PIA-WG`, port 51815) + 1 client (`PIA-WG-server`) + 3 routes. All expected, nothing stray.

### F — Resources — 🟢 healthy
Disk **29%** (6.2G free) · load **0.34** · **0** real zombies · 8 SSH sessions · up 2h25m.

### G — Deployment integrity (new section — did the cleanup hold?) — 🟢
| Check | Observed | Verdict |
|---|---|---|
| `/conf/PIAWireguard.py` MD5 | `d290c321…` = **matches repo/fork byte-for-byte** | PASS |
| Config resolves to | `/conf/PIAWireguard.json` (script reads its **own dir**) | PASS |
| Monitor points at | `python3 /conf/PIAWireguard.py` | PASS |
| `/usr/local/etc/` twins | **0** (gone) | PASS |
| `ListRegions.py` on router | **gone** (deprecated in repo, not needed on router) | PASS |
| `.bak`/`.orig` clutter | **0** | PASS |
| Backup safety net | 11 files in `/root/pia-backup-20261028/` | PASS |

→ One script, in the right place, reading the right config, driven by the right monitor. No redundancy, no clutter.

### H — Monitor live-tick (proven in the wild) — 🟢
Watched the 5-minute monitor run the **new** `/conf/` script **4×** (19:50 / 19:55 / 20:00 / 20:05) — every tick returned **"returned"** (success). The **only** "Execute error" in the log is the old **17:40** one, pre-cleanup. Split-brain genuinely resolved, not just in theory.

### Post-cleanup verdict
> **🟢 HEALTHY — all A–H pass.** Functionally clean *and* the deployment is coherent. The earlier split-brain is confirmed gone: a single `PIAWireguard.py` lives in `/conf/` (byte-identical to the repo), reads `/conf/PIAWireguard.json`, and the OPNsense monitor drives *that* copy — proven by four clean ticks. The 2 configd errors are historical (17:40, pre-fix) and will age out on the next log rotation.
>
> **Follow-ups (none urgent):** ① On the next firmware update, re-verify `/conf/PIAWireguard.py` survived (it should — `/conf/` is upgrade-proof) and that `/usr/local/etc/` didn't get a stale twin re-created. ② Optionally prune `ListRegions.py` from the *parent* repo (upstream's call; it's already deprecated in this fork). ③ Watch one more monitor cycle or two to see the 17:40 error scroll out of `latest.log`.

---

# Fresh Re-Audit (original confirmation run)
**Date:** 2026-10-28 ~16:15 | **Scope:** matrix sections A–G (baseline-vs-observed confirmation)

**TL;DR: HEALTHY.** One confirmed drift (OPNsense 25.10.2 → 26.7, cosmetic-only). All A–G sections PASS. Live migration was a clean no-op (PIA returned the same US Chicago server). DNS/DHCP/split-tunnel chain fully proven. Config sha256 byte-for-byte unchanged.

---

## A — Environment / Identity / Config

| # | Check | Expected (baseline) | Observed | Verdict |
|---|---|---|---|---|
| A1 | OS identity | OPNsense 25.10.2 (FreeBSD 15.1) | OPNsense **26.7** "Xenial Xenops", FreeBSD `15.1-RELEASE-p4`, PHP 8.5.12 | **DRIFT** (cosmetic) |
| A2 | Python | 3.13.x | 3.13.15 | PASS |
| A3 | requests | 2.3x | 2.34.2 | PASS |
| A4 | urllib3 | 2.x | 2.8.0 | PASS |
| A5 | Script MD5 + line count + py_compile | c042975c…, 626 ln, RC0 | c042975c17329a6eb66d3651eb22a02c, 626 ln, RC0 | PASS |
| A6 | Config sha256 | 35894ead…ec050 | **35894eade839f9d20985836f312a3e78cae8785d1ae59d333093613d300ec050** | **PASS (identical)** |
| A7 | CA cert present | ca.rsa.4096.crt in /usr/local/etc + /conf | both present, 2719 B | PASS |

**A1 detail — the OPNsense version drift:**
- Baseline said **25.10.2**; observed is **26.7** (confirmed via `/usr/local/opnsense/data/firmware/upgrade.html` + changelog listing to 26.7.7).
- `kern.osreldate = 1501000` (FreeBSD 15.1) — **same** as baseline. So the FreeBSD base is unchanged; only the OPNsense appliance layer jumped a minor version.
- Uptime ~19h49m, load `1.28 1.19 1.13`, disk `/` 29% (2.5G/9.4G). Healthy.
- **Impact:** LOW. The script resolves its config **relative to its own dir** (`sys.path[0]`), hardcodes only `/usr/local/sbin/configctl` and `/usr/local/share/certs/ca-root-nss.crt` (both still present in 26.7). No version-pinned code paths broke. The `.bak` config differs from live **only in JSON indentation** (data identical — verified by `json.load` equality).

## B — Tunnel Health (wg0)

| # | Check | Expected | Observed | Verdict |
|---|---|---|---|---|
| B7 | Instance count | 1 server + 1 client, no orphans | **1 server** (PIA-WG, port 51815, tun 10.193.11.119/32, gw 10.193.0.1) + **1 client** (PIA-WG-server, tun 0.0.0.0/0, keepalive 25) | PASS |
| B8 | wg0 up + endpoint | UP, 193.56.117.153:1337 | UP, endpoint 193.56.117.153:1337, keepalive 25s | PASS |
| B9 | Handshake age | < 60s | fresh throughout audit (3s–56s range) | PASS |
| B10 | Transfer counters | increasing | 697→798 MiB recv during audit | PASS |
| B11 | State files sane | /tmp/wg0_router + wg0_piaserverinfo consistent | `wg0_router`=10.193.0.1; `piaserverinfo` server_ip=193.56.117.153, server_vip=10.193.0.1, peer 10.193.11.119, region us_chicago, dns [10.0.0.243,10.0.0.242] — all consistent | PASS |

## C — Script Behavior + Live Migration

| # | Check | Expected | Observed | Verdict |
|---|---|---|---|---|
| C12 | `--help` | RC 0, 3 subcommands | RC 0; shows `--help`, `--listregions`, `--changeserver` | PASS |
| C13 | `--listregions` | us_chicago present | RC 0, 216 regions, `us_chicago` listed (`PF:False Geo:False`) | PASS |
| C14 | `--changeserver all` (live) | from→to endpoint, re-handshake <60s, no half-state | RC 0; from=193.56.117.153 → to=193.56.117.153 (**same server re-issued**), fresh handshake at +15s | PASS (no-op) |
| C15 | Post-migration | 1/1, config sha unchanged, .bak intact | 1/1; sha256 still 35894ead…; .bak==live (data) | PASS |

**Migration nuance:** the forced `--changeserver all` asked PIA for a us_chicago server and got back the *same* 193.56.117.153 (Server-11539-3a). So the "endpoint change" was a clean **re-handshake no-op** — no half-state, no orphan, config untouched. To force a genuinely *different* IP you'd change `regionId` (e.g. to a different city) — not required for this confirmation run.

## D — DNS / DHCP Chain

| # | Check | Expected | Observed | Verdict |
|---|---|---|---|---|
| D16 | Docker on .2 | technitium + nginx | technitium Up 2h (53/67 udp+tcp), nginx Up 11h healthy (443→8443) | PASS |
| D17 | Technitium DNS timing | ~<25ms | cold ~18ms, warm ~16-17ms; A=1.1.1.1, AAAA=2606:4700:4700::1001 | PASS |
| D18 | dhcrelay .1→.2 | relay running, →172.16.1.2 | `sockstat`: `dhcrelay` PID 91252, `udp4 172.16.1.1:67→172.16.1.2:67`; managed by `<DHCRelay>` in /conf/config.xml (name "Technitium DNS Server") | PASS |
| D19 | .101 uplink DNS | 172.16.1.2 | `resolvectl status`: uplink = 172.16.1.2 (Default Route: yes); resolves in ~18ms | PASS |
| D20 | End-to-end .101→.2→PIA | resolves through chain | .101 resolves google.com via .2; .2 reaches PIA .243 upstream | PASS |

**.242/.243 nuance (known cosmetic):**
- From **router**: dig to 10.0.0.242/.243 **times out** (~4.1s) — the router's own resolver points at 127.0.0.1 + 172.16.1.2, and those PIA-internal names don't resolve from the router side.
- From **.2**: ping to .242/.243 times out **but `dig @10.0.0.242/.243` answers** in ~80-90ms.
- **Conclusion:** not a regression. The PIA-internal DNS servers are reachable over the tunnel from the DNS box (where they matter); the router-side timeout is a known artifact of the router resolving its own queries outside the tunnel. No client-facing impact (clients hit .2, not .242 directly).

## E — Split-Tunnel Proof

| # | Check | Expected | Observed | Verdict |
|---|---|---|---|---|
| E21 | Router WAN egress | 104.159.102.188 (ISP) | `vtnet1`=104.159.102.188; `curl ipify` = **104.159.102.188** | PASS |
| E22 | .101 traceroute hop2 | WAN/ISP (NOT a PIA 10.0.0.x IP) | hop1=172.16.1.1 (router), **hop2=10.184.206.1 (ATT/WAN)** — not PIA | PASS |
| E23 | Split-tunnel semantics | only WG-tagged traffic goes through PIA | default route via vtnet1 (ISP); wg0 carries only the `0.0.0.0/0`-tagged PIA peer traffic — router egress = ISP IP confirms LAN/WAN traffic bypasses the tunnel | PASS |

## F — Failure Modes

| # | Test | Expected RC | Observed | Verdict |
|---|---|---|---|---|
| F24 | bad regionId (`nonexistent_xyz`) | RC 2, "region not found", no mutation | **RC 2**, `ERROR: Region nonexistent_xyz not found` (line 502) | PASS |
| F25 | bad OPNsense key/secret | RC 1, fails **before** mutation | **RC 1**, `401 Failed unauthorized` at searchServer; instances-before=1, instances-after=1 | PASS |
| F26 | config unchanged after tests | sha256 == baseline | 35894ead…ec050 (identical) | PASS |
| F27 | .bak intact | .bak data == live | DATA IDENTICAL (indentation differs only) | PASS |

Failure isolation is clean: bad region exits at the PIA-region-lookup (RC 2) *after* reading OPNsense; bad creds exit at the very first OPNsense API call (RC 1) *before* any server/client mutation. Neither leaves orphans.

## G — Fragility Watch-Items

| # | Item | Risk | Observed | Note |
|---|---|---|---|---|
| G28 | `configctl interface newip wg0 force` | version-specific | RC 0, IP preserved (10.193.11.119) | works in 26.7 |
| G29 | `netstat -rWnf inet` (Netif column) | FreeBSD netstat format | Parses clean; `default→vtnet1`, `10.193.0.1→wg0` present | OK |
| G30 | alias / route gateway dict shapes | OPNsense API schema | aliases=[], 3 routes (all `HeadScaleGW`); shapes match what script expects | OK |
| G31 | version-specific hardcoding | path drift on upgrades | shebang `/usr/local/bin/python3` (→python3.13); `configctl` hardcoded path present; `ca-root-nss.crt` (DIP path) present | OK |

**Real fragilities worth a note:**
1. **Shebang is `/usr/local/bin/python3`** — fine now, but if a future OPNsense ships Python 3.14 to a different path, the shebang breaks. (Low; OPNsense has kept this symlink for years.)
2. **`configctl` hardcoded** to `/usr/local/sbin/configctl` — a path that *could* move on a major FreeBSD/OPNsense bump. (Low-moderate.)
3. **Two config copies** (`/usr/local/etc/` and `/conf/`) can drift if one is edited without the other (currently data-identical, formatting-divergent). Editing `/conf/` is the "survives upgrade" copy; the script reads `/usr/local/etc/`. Worth keeping them in lockstep.
4. **`dhcrelay` not in `rc.conf`/`sysrc`** — it's managed by OPNsense's `<DHCRelay>` block instead, so a naive `rc.conf` inspection would falsely suggest it's not configured. Not a bug, just a documentation trap.

## Drift-vs-Baseline Summary
- **Confirmed drift:** OPNsense appliance **25.10.2 → 26.7** (FreeBSD base 15.1 unchanged). Cosmetic; no functional regression found in A–G.
- **Cosmetic-only:** `.bak` config indentation differs (data identical); router-side .242/.243 DNS timeout.
- **Unchanged:** Python 3.13, requests/urllib3, script MD5+linecount, config sha256, wg0 endpoint, 1/1 instance count, dhcrelay target, client uplink DNS, split-tunnel routing.

## Final State
```
Tunnel:  wg0 UP  endpoint=193.56.117.153:1337  handshake=fresh  recv ~798 MiB
Instances: 1 server (PIA-WG) + 1 client (PIA-WG-server)  — no orphans
Config:  sha256 35894ead…ec050  (== baseline, byte-identical)
Router:  172.16.1.1  OPNsense 26.7  up 19h49m  load 1.28  disk 29%
DNS box: 172.16.1.2  technitium+nginx up  dhcrelay →.2  DNS ~17ms
Client:  172.16.1.101  uplink=172.16.1.2  resolves ~18ms  split-tunnel OK
/tmp:    clean on all three boxes (state files + config intact)
```

## Overall Verdict
**HEALTHY — all sections A–G pass.** The stack is functionally identical to the expected baseline. The single substantive change is the **OPNsense 25.10.2→26.7** minor-version bump, which introduced **no functional regression** in this re-audit (config, tunnel, DNS/DHCP, split-tunnel, migration, and both failure modes all behave as specified). Recommended follow-ups (none urgent): keep the two config copies in lockstep, and re-verify the `/usr/local/sbin/configctl` + `/usr/local/bin/python3` paths on the next major OPNsense release.
