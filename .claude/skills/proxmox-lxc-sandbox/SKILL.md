---
name: proxmox-lxc-sandbox
description: Throwaway LXC containers on Proxmox for the isolated installation and security review of third-party tools when Docker is not enough (full system, systemd, services, longer operation, network behavior over time). Covers - host criteria (concrete hosts in private/infra.md, the choice is the owner's), VMID range and naming scheme (proposal), unprivileged CTs, template, network separation (bridge without uplink, guest firewall against LAN, outgoing only for the installation), snapshot before installation, resource limits, deletion after the review, access only via SSH with a fixed host key and pct exec, production guests that are never touched, and the procedure as a command sequence with placeholders. Every creation only after explicit approval. Use when - (1) a target needs a whole system, systemd or network services, (2) a tool is to be observed over time or with a real network, (3) docker-sandbox reaches its limits, (4) a sandbox LXC on Proxmox is discussed.
---

# proxmox-lxc-sandbox - throwaway LXC for third-party tools

⛔⛔ **Every creation, every network change and every deletion only after explicit approval by
the owner** - per sandbox CT, with host, VMID, purpose and duration. If an agent classifier
rejects infrastructure write access, that is intended and is not worked around.

Operation-specific details (hosts, production guests, networks, access path, references to the
infrastructure documentation): **if present, read `private/infra.md` first** - it is
authoritative; this skill only describes the procedure.

## When LXC instead of Docker

- The target needs **systemd**, installs services, timers, users, packages system-wide.
- It is supposed to run for **hours to days** (observe self-update, telemetry, background jobs).
- Its **network behavior** is to be measured (capture on the host, egress rules).
- It brings its own Docker stacks (Docker in an LXC - only with `nesting=1`, deliberately and
  noted in the record).

Not LXC: Windows behavior (-> Windows VM, open decision, see `docker-sandbox`), kernel modules,
anything that would need a **privileged** container (-> VM).

## Which host

A sandbox CT belongs on a host that carries **nothing critical** (no credential vaults, no domain
controllers, no backups, no perimeter/router, no customer systems) and has enough free storage and
RAM. If there is no such host, a small dedicated sandbox host is the clean solution. The owner
makes the choice; until then no sandbox LXCs are created.

Concrete hosts, their roles and the trade-offs: **if present, read `private/infra.md`.**

## ⛔ Production guests - never touch

No `pct`/`qm` command with a write effect (stop, set, snapshot, rollback, destroy, restore onto
this ID, exec with changes) on production guests. The list per host is in `private/infra.md` (if
present); it ages - read `pct list` / `qm list` of the host before every creation. Equally off
limits: the hosts themselves (network, storage, firewall cluster rules, backup jobs) except for
the sandbox CT steps named below, and reserved VMID ranges.

## VMID, name, network (proposal, to be fixed per operation)

| Item | Proposal | Reason |
|---|---|---|
| VMID | an own, otherwise unused range (e.g. `8000-8099`) | stands out from production and restore tests; deletion protection via the range |
| host name | `sandbox-<tool>-<YYMMDD>` | recognisable as throwaway at once, date for cleanup |
| tag | `ujc-sandbox` | safety check before every deletion (below) |
| description | `ujc-security-checker, record repos/<name>, created <date>, approval <date>` | origin on the guest |
| isolated bridge | an own bridge **without** uplink (`<sandbox-bridge>`, own subnet, free of collisions with other networks) | disconnect the network completely after the installation |
| installation network | default bridge with guest firewall (below) and a fixed IP from a range **approved by the owner** | only for the installation phase |

Creating a new bridge is a host network change -> its own approval. Without it, only
`link_down=1` after the installation remains. The concrete values of the operation:
`private/infra.md`.

## Principles for a sandbox CT

- **unprivileged** (`--unprivileged 1`), `nesting` only if needed; no `keyctl`, no raw `lxc.*`
  lines, no devices (`dev*`), no iGPU.
- **No bind mounts** (`mp*` onto host paths) - neither storage pools nor host directories. Data
  goes in via `pct push`, results come out via `pct pull`.
- **Not on data pools**, but on the host's guest storage (`local-zfs` or similar) - ZFS, so that
  snapshots work.
- **No management access inside the CT**: no service user, no keys, no monitoring agent, no
  inventory/backup enrolment, because the CT is not trustworthy. Access exclusively from the outside via `pct exec`.
- **Not in backup jobs**: check `/etc/pve/jobs.cfg` - a job with `all 1` takes every new guest
  (then add an `exclude`, its own approval), otherwise third-party code lands in the backup server.
- **Resources**: `--cores 2 --cpulimit 2 --memory 4096 --swap 0 --rootfs <storage>:16`;
  `onboot 0`. OOM kills inside an LXC are invisible - read `memory.events` before and after the
  run. CPU values inside an LXC show the host load - measure via cgroup.
- **Template** from the official Proxmox catalogue (`pveam`), `pveam` checks the checksum; **no**
  community scripts for sandbox CTs - a `curl | bash` on the host would itself be unreviewed code.

## Guest firewall for the installation phase

Prerequisite: PVE firewall active at datacenter level **and** on the guest NIC (`firewall=1`) -
otherwise guest rules have no effect. Check before the creation (`pve-firewall status`), do not
assume it.

`/etc/pve/firewall/<VMID>.fw` (template, placeholders):

```text
[OPTIONS]
enable: 1
policy_in: DROP
policy_out: DROP

[RULES]
OUT ACCEPT -dest <gateway-ip> -p udp -dport 53
OUT ACCEPT -dest <gateway-ip> -p tcp -dport 53
OUT DROP -dest 10.0.0.0/8
OUT DROP -dest 172.16.0.0/12
OUT DROP -dest 192.168.0.0/16
OUT DROP -dest 100.64.0.0/10
OUT ACCEPT -p tcp -dport 443
OUT ACCEPT -p tcp -dport 80
```

Rules apply from top to bottom. Treat IPv6 separately (perimeter v4 **and** v6): no IPv6
configuration on the guest, negative test for v6 as well. **The negative test is mandatory**: from
the CT a connection to a LAN target (`<lan-target>:<port>`, a real service in the own network -
the same value as `UJC_EGRESS_LAN_TARGET` in `private/egress.conf`) and to the host's web
interface (`:8006`) must fail before anything is installed. An answer from a private IP proves
nothing about its owner.

After the installation: network off (`link_down=1` or move to `<sandbox-bridge>`), repeat the probe.

## Access

- From the work machine only to the **PVE host**, via SSH with an own key and a **fixed host key**
  (`StrictHostKeyChecking=yes`, entry in `known_hosts`; never accept automatically). Inside the
  CT then `sudo pct exec <VMID> -- ...`. User, key and tooling of the operation:
  `private/infra.md`.
- **One** SSH connection per host for the whole block of work (fail2ban). No loops with retries.
- Transfer commands as a file or base64-encoded (`echo <b64> | base64 -d | bash`); never send
  `sed` or regex through `ssh ... sudo bash -c "..."` (escaping breaks); data via stdin in binary
  mode (CRLF pitfall on Windows).
- Start long runs in the CT with `systemd-run` or `nohup ... > /root/out/<file> 2>&1 &` and check
  with short polls - no SSH session open for hours.
- Large transfers outside working hours or throttled.
- Never put secrets into the CT; if the target needs credentials, they are throwaway values
  created for the purpose, without relation to real accounts.

## Procedure (placeholders in `<...>`, every block after approval)

```bash
# --- 0. Read the situation (read only, on the host) --------------------------------
pct list; qm list                                   # VMID free? not a production ID?
pvesm status                                        # guest storage with ZFS?
pve-firewall status; cat /etc/pve/firewall/cluster.fw
grep -n "all 1\|exclude" /etc/pve/jobs.cfg          # does a backup job take new guests?
pveam list <template-storage>                       # template present?

# --- 1. Template (only if missing) -------------------------------------------------
pveam update
pveam available --section system | grep debian
pveam download <template-storage> <debian-template>.tar.zst

# --- 2. Create (does NOT start) ----------------------------------------------------
pct create <VMID> <template-storage>:vztmpl/<debian-template>.tar.zst \
  --hostname sandbox-<tool>-<YYMMDD> --tags ujc-sandbox \
  --description "ujc-security-checker, record repos/<name>, approval <date>" \
  --unprivileged 1 --onboot 0 \
  --cores 2 --cpulimit 2 --memory 4096 --swap 0 \
  --rootfs <guest-storage>:16 \
  --net0 name=eth0,bridge=vmbr0,firewall=1,ip=<sandbox-ip>/24,gw=<gateway-ip> \
  --nameserver <gateway-ip>
# create the guest firewall /etc/pve/firewall/<VMID>.fw as above
pct config <VMID>                                   # no mp*, dev*, lxc.*; unprivileged 1

# --- 3. Snapshot before the installation -------------------------------------------
pct snapshot <VMID> before-install --description "empty, before <tool>"

# --- 4. Start, negative test, installation ------------------------------------------
pct start <VMID>
cat /sys/fs/cgroup/lxc/<VMID>/memory.events            # baseline on the host (counters) ...
pct exec <VMID> -- cat /proc/1/stat                     # ... plus start time of the CT
pct exec <VMID> -- mkdir -p /root/sandbox /root/out
pct exec <VMID> -- sh -c 'timeout 5 bash -c "</dev/tcp/<lan-target>/<port>" && echo LAN_OPEN || echo lan_closed'
# expected: lan_closed -- otherwise abort
pct push <VMID> <archive-on-the-host>.tar /root/sandbox/source.tar   # git archive of the reviewed revision
pct exec <VMID> -- sh -c '<installation> > /root/out/install.txt 2>&1; echo "exit=$?" >> /root/out/install.txt'

# --- 5. Disconnect the network, snapshot after the installation ----------------------
pct set <VMID> --net0 name=eth0,bridge=vmbr0,firewall=1,link_down=1,ip=<sandbox-ip>/24,gw=<gateway-ip>
# or (if the sandbox bridge exists): --net0 name=eth0,bridge=<sandbox-bridge>,ip=<sandbox-net>.<n>/24
pct exec <VMID> -- sh -c 'timeout 5 bash -c "</dev/tcp/<internet-target>/443" && echo NETWORK_STILL_UP || echo network_disconnected'
pct snapshot <VMID> after-install

# --- 6. Review / observation ---------------------------------------------------------
pct exec <VMID> -- systemctl list-units --type=service --state=running
pct exec <VMID> -- ss -tulpn
pct exec <VMID> -- sh -c '<test> > /root/out/test.txt 2>&1; echo "exit=$?" >> /root/out/test.txt'
pct pull <VMID> /root/out/test.txt /root/ujc-sandbox-<VMID>-test.txt
# reset for another run: pct rollback <VMID> after-install

# --- 7. Delete (safety check first) --------------------------------------------------
pct config <VMID> | grep -E '^(tags|hostname):'     # must show ujc-sandbox and sandbox-<tool>-...
# VMID inside the sandbox range? otherwise STOP
pct stop <VMID>
pct destroy <VMID> --purge 1 --destroy-unreferenced-disks 1
ls /etc/pve/firewall/<VMID>.fw 2>/dev/null          # guest firewall left over? then delete it
rm -f /root/ujc-sandbox-<VMID>-*                    # pickup leftovers on the host
```

Afterwards: fetch the results from the host (over the same connection, SFTP), delete the pickup
leftovers, record the finding as a round in `private/records/<name>/reviews/` (host, VMID, template,
snapshot names, exit codes, negative tests). Whether a sandbox CT is noted in the operation's infrastructure documentation is
decided by the owner (`private/infra.md`).

## Abort

- VMID taken, host not as expected, firewall not active, negative test fails -> stop, report,
  nothing "anyway".
- The target tries to break out of the CT (access to `/proc/sys`, mount attempts, kernel
  modules) -> `pct stop` at once, finding, do not keep observing.
- The run needs more privileges (privileged, `nesting`, devices) -> ask the owner; usually a VM is
  then the right place.
