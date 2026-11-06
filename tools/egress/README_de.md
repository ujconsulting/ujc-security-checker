<!-- source: README.md sha256:e071f544891cbb89b6df31259584f4a5fe9a3058ef122f8a6605157ee9f619f7 -->
[English](README.md) | [Deutsch](README_de.md)

# egress — kontrollierter Ausgang für Sandbox-Container

## Zweck

Ein Sandbox-Container braucht Netzwerkzugang, um Pakete zu installieren — und genau in dieser Phase laufen fremde
Installationsskripte (npm `preinstall`/`postinstall`, sdist-Builds). Im Default-Bridge-Netzwerk von Docker erreichen sie das
ganze LAN, den Docker-Host und andere Container. Deshalb (verbindliche Regel
in `CLAUDE.md`):

- Sandbox-Container laufen **nie** im Default-Bridge-Netzwerk.
- Die Installationsphase läuft **nur** im internen Netzwerk `ujc-sandbox-net`; der einzige Ausgang ist der
  Proxy `ujc-sandbox-proxy:3128`, der ausschließlich Domains der Allowlist durchlässt.
- Danach wird das Netzwerk vollständig getrennt und die Trennung geprüft.
- Das Proxy-Log jedes Laufs wird in die Ergebnisse kopiert; **blockierte Versuche sind ein Befund**
  (wohin wollte das Tool, und warum?).

## Aufbau

```text
 sandbox container ──(ujc-sandbox-net, --internal: no route to the outside)──┐
                                                                             │ :3128
                                                     ujc-sandbox-proxy (Squid)
                                                     ├─ leg in ujc-sandbox-net
                                                     └─ leg in the bridge network ──> internet
```

| Datei | Inhalt |
|---|---|
| `setup.sh` | legt Netzwerk und Proxy an (idempotent), stellt die aktive Liste zusammen und lädt sie ohne Neustart (`squid -k reconfigure`) |
| `check.sh` | prüft beide Richtungen; Exit 0 nur, wenn alles zutrifft |
| `squid.conf` | Regeln: Clients nur aus dem Subnetz von `ujc-sandbox-net` (`clients.txt`, von `setup.sh` geschrieben); private/lokale Netze sind **immer** gesperrt; nur Ports 80/443, nur GET/HEAD/CONNECT; sonst nur die aktive Liste; jede Anfrage wird protokolliert |
| `allowlist.txt` | Liste `standard`: Paketquellen (PyPI, npm, GitHub-Downloads) |
| `allowlist-scanner.txt` | Liste `scanner`: Schwachstellendatenbanken für `tools/scan.sh` (OSV-API, trivy-DB, grype-DB) |

Squid-Image per Digest fixiert (`setup.sh`), Container ohne unnötige Capabilities,
`no-new-privileges`, 256 MB, 200 Prozesse.

## Verwendung

```bash
tools/egress/setup.sh                   # list standard (default)
tools/egress/setup.sh scanner           # list scanner
tools/egress/setup.sh standard scanner  # union
tools/egress/setup.sh --rebuild         # recreate the proxy (after changing squid.conf)
tools/egress/check.sh [<lan-ip>:<port>]
```

Normalerweise wird keines von beiden direkt aufgerufen: `tools/setup.sh` richtet ein und prüft, und
`container_test_*.sh`, `scan.sh`, `behavior_probe.sh` rufen `setup.sh` + `check.sh` als
Voraussetzung auf und brechen ab, wenn `check.sh` nicht besteht.

Sandbox-Container erhalten:

```bash
docker run --network ujc-sandbox-net \
  -e HTTP_PROXY=http://ujc-sandbox-proxy:3128 -e HTTPS_PROXY=http://ujc-sandbox-proxy:3128 \
  -e http_proxy=http://ujc-sandbox-proxy:3128 -e https_proxy=http://ujc-sandbox-proxy:3128 \
  -e NO_PROXY=localhost,127.0.0.1 ...
# npm additionally: -e npm_config_proxy=... -e npm_config_https_proxy=...
# afterwards:       docker network disconnect ujc-sandbox-net <container>  + disconnection probe
```

**Was `check.sh` prüft** (alles muss zutreffen):

| Prüfung | erwartet |
|---|---|
| Paketquelle über den Proxy (pypi, npm) — mit Liste `standard` | erreichbar |
| OSV-API über den Proxy — mit Liste `scanner` | erreichbar |
| pypi über den Proxy, wenn die Liste `standard` nicht aktiv ist | blockiert |
| direkter Ausgang ohne Proxy | blockiert (kein DNS, keine Route) |
| LAN-Ziel direkt und über den Proxy | blockiert |
| Docker-Host (`host.docker.internal`) über den Proxy | blockiert |
| Domain außerhalb der Allowlist (`example.com`) | blockiert |
| unverschlüsseltes HTTP auf einen anderen Port (`pypi.org:8080`) | blockiert |
| Host ohne Adresse auf `ujc-sandbox-net` (`gateway_mode_ipv4=isolated`); erste Subnetzadresse geprüft (alle TCP-Ports), sofern dort nicht der Proxy sitzt | Pflicht / nichts antwortet |
| Proxy-Container direkt, alle 65535 TCP-Ports | nur 3128 antwortet |

„Über den Proxy blockiert“ zählt nur, wenn die Antwort nachweislich von Squid selbst kommt (Header
`X-Squid-Error` oder ein abgewiesener CONNECT-Tunnel). Ein bloßer Statuscode wie 403 oder 404 kann
von einem Ziel stammen, das die Anfrage erreicht hat, und gilt als Fehlschlag.

**LAN-Ziel:** Parameter, sonst `UJC_EGRESS_LAN_TARGET`, sonst `private/egress.conf`
(von git ignoriert, Zeile `UJC_EGRESS_LAN_TARGET=<ip>:<port>` — ein echter Dienst im eigenen Netzwerk). Ist
keines gesetzt, prüft `check.sh` generisch das Gateway des Docker-Bridge-Netzwerks (= Docker-Host)
und weist darauf hin.

**Log:** `${UJC_EGRESS_LOG:-$TEMP/ujc-egress-log}/access.log`, Format
`<time> <client-ip> <result>/<status> <method> <target> <server-ip>`. Die Skripte kopieren den Auszug
ihres Laufs nach `<output>/egress.log` (bei Containertests auf die IP des Containers gefiltert) und die
blockierten Zeilen nach `egress.log.blocked`.

**Allowlist erweitern:** nur bewusst, eine Domain je Zeile (führender Punkt = einschließlich
Subdomains), mit der Begründung in der Commit-Nachricht. Ein blockierter Versuch im Log ist zuerst ein Befund
und erst nach Prüfung ein Kandidat für die Liste. Für Tools, die mehr Netzwerk brauchen (beliebige
Downloads, eigene Dienste, Dauerbetrieb): ein Sandbox-LXC in einem abgetrennten Netzwerk (Skill
`proxmox-lxc-sandbox`), die Liste nicht aufweiten.

**Eine Liste für alle:** der Proxy wird gemeinsam genutzt. `setup.sh` schaltet die Liste nicht um, solange andere
Sandbox-Container am internen Netzwerk hängen (Exit 4) — erst deren Läufe abwarten.

## Grenzen

- **Squid prüft die Ziel-IP nach der DNS-Auflösung.** Die Sperre privater Netze gilt deshalb
  auch dann, wenn eine erlaubte Domain auf eine private Adresse zeigt (DNS-Rebinding) — der Proxy
  verbindet sich nie ins LAN.
- **HTTPS ist ein Tunnel** (`CONNECT`): der Proxy sieht Domain und Port, nicht Inhalt, Pfad oder Header.
  Eine erlaubte Domain (z. B. `github.com`, `raw.githubusercontent.com`) lässt sich auch zur
  Exfiltration oder zum Nachladen weiteren Codes nutzen — die Liste begrenzt die Ziele, nicht die Daten.
- Kein Schutz gegen das, was im Container **nach** der Installation geschieht, es sei denn, das Netzwerk
  wird getrennt — daher Trennung plus Prüfung.
- Erlaubte Paketquellen liefern beliebige Pakete; die Lieferkette prüft das Lockfile,
  nicht der Proxy.
- DNS läuft über den Proxy (der Container löst selbst nichts auf) — DNS-Tunnel aus dem
  Container sind damit ebenfalls blockiert.
- IPv6: `squid.conf` sperrt private/lokale v6-Bereiche; das interne Docker-Netzwerk hat kein v6.
- **Der Host hat keine Adresse auf der Sandbox-Bridge.** Mit `--internal` allein ist das Gateway der
  Bridge der Docker-Host (unter Docker Desktop seine VM, die auch die Windows-Laufwerke einbindet), und
  jeder Dienst, der dort auf `0.0.0.0` lauscht, ist aus der Sandbox am Proxy vorbei erreichbar -
  gemessen am 12.10.2026: rpcbind (111) und rpc.statd. `setup.sh` legt das Netz deshalb mit
  `com.docker.network.bridge.gateway_mode_ipv4=isolated` an (Docker Engine 28+) und erzeugt ein älteres
  Netz einmal neu; `check.sh` verlangt diesen Modus und prüft alle TCP-Ports des Proxys (nur 3128).
- `setup.sh --rebuild` verweigert, solange andere Container am Netzwerk hängen (Exit 4).
