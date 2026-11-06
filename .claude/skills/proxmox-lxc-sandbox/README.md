<!-- source: SKILL.md sha256:56db302798f96c5320c18f28dd041957e7300ed089e98732b9d1f144e5c39666 -->
[English](README.md) | [Deutsch](README_de.md)

# proxmox-lxc-sandbox

Short human documentation. The agents load [`SKILL.md`](SKILL.md), which is authoritative.

## Purpose

Throwaway, unprivileged LXC containers on Proxmox for installing and reviewing third-party tools
when Docker is not enough. **Every creation, network change and deletion only after explicit
approval** - per container, with host, VMID, purpose and duration. Concrete hosts and production
guests are operation-specific and live in the private `private/infra.md`.

## When to use

- the target needs systemd, installs services, users or packages system-wide;
- it should run for hours or days (self-update, telemetry, background jobs);
- its network behavior is to be measured;
- `docker-sandbox` reaches its limits.

Not for Windows behavior (Windows VM) or anything that would need a privileged container (VM).

## Flow

0. Read the host situation (free VMID, storage, firewall active, backup jobs) - read only.
1. Template from the official Proxmox catalogue, if missing.
2. Create the container (unprivileged, no bind mounts, resource limits, tag `ujc-sandbox`) with a
   guest firewall: outgoing only DNS to the gateway and HTTP(S), private ranges dropped.
3. Snapshot before the installation.
4. Start, **negative test** (LAN and host must be unreachable), installation.
5. Disconnect the network, probe again, snapshot after the installation.
6. Review and observation; reset with a rollback for further runs.
7. Delete after a safety check (tag, host name, VMID range).

## Commands

Proxmox CLI on the host, e.g. `pct create`, `pct snapshot`, `pct exec`, `pct set ... link_down=1`,
`pct destroy`; the full sequence with placeholders is in [`SKILL.md`](SKILL.md). Access only via SSH
to the Proxmox host with a fixed host key, one connection per block of work.

## Example

A tool that installs a systemd service and phones home once a day: approved sandbox container for
three days, installation through the guest firewall, then network down; the run shows the timer,
the service and one blocked connection attempt per day - recorded as a round with host, VMID,
snapshots and the negative tests.

## See also

[`docker-sandbox`](../docker-sandbox/README.md), [`tool-review`](../tool-review/README.md),
[`docs/SKILLS.md`](../../../docs/SKILLS.md).
