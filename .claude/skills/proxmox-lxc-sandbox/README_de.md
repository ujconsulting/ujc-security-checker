<!-- source: README.md sha256:76d56e610a6f1440be09e067cba806b027a6fa0ec66ec60b52e4596c01c5564a -->
[English](README.md) | [Deutsch](README_de.md)

# proxmox-lxc-sandbox

Kurze Doku für Menschen. Die Agenten laden [`SKILL.md`](SKILL.md) (englisch), das maßgeblich ist.

## Zweck

Unprivilegierte Wegwerf-LXC auf Proxmox, um fremde Werkzeuge zu installieren und zu prüfen, wenn
Docker nicht reicht. **Jedes Anlegen, jede Netzänderung und jedes Löschen nur nach ausdrücklicher
Freigabe** - je Container, mit Host, VMID, Zweck und Dauer. Konkrete Hosts und Produktivgäste sind
betriebsspezifisch und stehen im privaten `private/infra.md`.

## Wann

- das Prüfobjekt braucht systemd, installiert Dienste, Benutzer oder Pakete systemweit;
- es soll Stunden oder Tage laufen (Selbst-Update, Telemetrie, Hintergrundjobs);
- sein Netzverhalten soll gemessen werden;
- `docker-sandbox` stößt an seine Grenzen.

Nicht für Windows-Verhalten (Windows-VM) und nichts, was einen privilegierten Container bräuchte
(VM).

## Ablauf

0. Lage auf dem Host lesen (freie VMID, Speicher, Firewall aktiv, Backup-Jobs) - nur lesend.
1. Vorlage aus dem offiziellen Proxmox-Katalog, falls sie fehlt.
2. Container anlegen (unprivilegiert, keine Bind-Mounts, Ressourcengrenzen, Tag `ujc-sandbox`) mit
   Gast-Firewall: ausgehend nur DNS zum Gateway und HTTP(S), private Bereiche verworfen.
3. Snapshot vor der Installation.
4. Starten, **Negativtest** (LAN und Host müssen unerreichbar sein), Installation.
5. Netz trennen, erneut prüfen, Snapshot nach der Installation.
6. Prüfung und Beobachtung; für weitere Läufe per Rollback zurücksetzen.
7. Löschen nach Sicherheitsprüfung (Tag, Hostname, VMID-Bereich).

## Befehle

Proxmox-CLI auf dem Host, z. B. `pct create`, `pct snapshot`, `pct exec`, `pct set ... link_down=1`,
`pct destroy`; die vollständige Folge mit Platzhaltern steht in [`SKILL.md`](SKILL.md). Zugriff nur
per SSH auf den Proxmox-Host mit festem Host-Schlüssel, eine Verbindung je Arbeitsblock.

## Beispiel

Ein Werkzeug, das einen systemd-Dienst installiert und einmal am Tag nach Hause telefoniert:
freigegebener Sandbox-Container für drei Tage, Installation durch die Gast-Firewall, danach Netz
aus; der Lauf zeigt den Timer, den Dienst und einen geblockten Verbindungsversuch pro Tag -
festgehalten als Runde mit Host, VMID, Snapshots und den Negativtests.

## Siehe auch

[`docker-sandbox`](../docker-sandbox/README_de.md), [`tool-review`](../tool-review/README_de.md),
[`docs/SKILLS_de.md`](../../../docs/SKILLS_de.md).
