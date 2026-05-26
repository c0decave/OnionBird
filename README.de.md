# OnionBird

**Sprachen:** [English](README.md) · **Deutsch** · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **BETA — leakdicht auf Tor-DNS-fähigen Systemen in unserer Testumgebung; noch keine produktive User-Basis. Lies [die Voraussetzungen](#bevor-du-installierst) vor der Installation.**

> Lies das [Threat Model](docs/threat-model.md) und die
> [Follow-up-Liste](docs/follow-up.md), bevor du das Addon für
> anonymitätskritische Anwendungen einsetzt.

OnionBird ist ein Thunderbird-Add-on, das IMAP/SMTP durch einen lokalen
Tor-Proxy routet und Mail-Header normalisiert oder entfernt, die
historisch zur Deanonymisierung von Absendern verwendet wurden.
Unterstützt Thunderbird **128+** (Manifest `strict_min_version:
128.0`); primäres Integrations-Ziel ist die **Thunderbird-140-ESR**-
Schiene. Geplant als der moderne Nachfolger der nicht mehr gepflegten
TorBirdy-Erweiterung (letzte Version v0.2.6 in 2018, von Mozilla durch
Entfernung von Legacy-XUL in TB 78 abgewürgt).

Aktuelle Add-on-Version: **0.1.4**.

---

## 100% Privacy- & Security-Policy

Der Projektauftrag von OnionBird ist binär: **jeder beobachtbare
Code-Pfad, der die Identität, echte IP, den Hostnamen, das Locale, die
Zeitzone oder die Tatsache, dass der User Mail-Hardening verwendet,
nach außen leakt, gilt als P0-Defekt und blockiert ein Release.**
"Funktioniert meistens", "fast leak-frei" oder "gut genug" sind keine
akzeptablen Zustände.

Konkret heißt das:

- **Fail-closed by default.** `network.proxy.failover_direct = false`
  wird erzwungen — wenn der konfigurierte Tor-Proxy nicht erreichbar
  ist, scheitert der Send. Das Addon downgradet **NIEMALS** still auf
  Clearnet.
- **DNS ausschließlich über Tor.** `network.proxy.socks_remote_dns =
  true`, `network.trr.mode = 5` (kein paralleles DoH),
  `network.dns.disablePrefetch = true`. Empirisch verifiziert: null
  DNS-Anfragen am lokalen Resolver während realer Tor-Sends.
- **OCSP aus.** Andernfalls feuert jeder TLS-Handshake eine clearnet
  HTTP-Anfrage an die CA.
- **Kein Update-phone-home.** App + Extensions + GMP-Manager-URLs
  gelöscht.
- **Keine Telemetrie, kein Safebrowsing, keine Captive-Portal-Probes,
  kein Remote-Content-Rendering.**
- **Kein WebRTC, keine Geolocation, kein DNS-Prefetch, kein
  Predictor.**
- **Mid-Session-Schutz.** Prefs werden bei jedem TB-Startup und
  periodisch während aktiver Härtung re-asserted. Wenn ein Dritter
  eine gehärtete Pref kippt, repariert das Addon sie, ohne den
  erkannten SOCKS-Endpunkt zu überschreiben.
- **Hardening ist reversibel.** Snapshot vor dem ersten Enable
  gespeichert, wiederherstellbar via Disable-Button auf der
  Options-Seite oder `disable-hardening`-Message.
- **Self-Test-Canary** beim Startup und während aktiver Härtung
  vergleicht SOCKS5-RESOLVE (über 3 stream-isolierte Tor-Circuits) mit
  dem vollständigen Antwort-Set des System-Resolvers. Jede öffentliche
  System-IP muss entweder über Tor gesehen oder per PTR-via-Tor als
  exakter Canary-Host oder Subdomain bestätigt werden; gemeinsame
  Public Suffixes wie `co.uk` zählen nie als Beweis.
- **Privacy-sichere Diagnose.** Command-Logs auf der Options-Seite und
  Hintergrund-Konsolenmeldungen zeigen Zähler, maskierte IPs und
  Fehlerklassen statt roher Canary-IPs, PTR-Namen, Account-Origins,
  SMTP-Hostnamen oder Message-ID-Domains.
- **Pref-Write-Allowlist** in der Experiment-API. Die Parent-Process-
  Surface des Addons kann **keine** beliebigen Prefs schreiben
  (`browser.startup.*`, `devtools.*` etc. werden abgelehnt) — begrenzt
  den Blast-Radius künftiger Message-Handler-Regressions.

**Inhärente Grenzen — OnionBird KANN folgendes NICHT fixen:**

1. **`Authentication-Results: ... smtp.auth=<deine-Mailbox>@<Provider>`**
   wird vom Provider-MTA auf ausgehende Mails gesetzt. Es offenbart
   deine authentifizierte Mailbox jedem Empfänger. Eigenschaft des
   authentifizierten SMTP, von Addon-Seite nicht entfernbar.
   *Workaround:* nutze eine Throwaway-/Pseudonym-Mailbox für sensible
   Korrespondenz.
2. **Die Tor-Exit-IP erscheint in der `Received:`-Kette des Empfängers.**
   Provider-MTAs machen Reverse-DNS auf die verbindende IP und emittieren
   Namen wie `tor-exit-107.digitalcourage.de`. Der Empfänger erkennt
   "dieser User hat über Tor gesendet". Inhärent zum SMTP-Transport.
3. **OS-Level-Leaks** — Hostname-Disclosure durch andere Apps, NTP-
   Leaks, Swap-Files, Filesystem-Timestamps. Stacke OnionBird mit
   einem Tor-gehärteten OS, um diese zu schließen — siehe
   [die Tails / Whonix Stacking-Notiz](#stacking-mit-einem-tor-gehärteten-os).
4. **Netzwerk-Korrelation** — Beobachter beider Enden eines
   Tor-Circuits. Nicht durch Header-Hygiene zu verteidigen.
5. **TB-UI-Locale wird auf en-US gezwungen, sobald Hardening aktiv ist.**
   `privacy.resistFingerprinting=true` steht aus Netzwerk-Fingerprint-
   Gründen in `HARDENING_PREFS` (erzwingt UTC-`Date`-Header, unterdrückt
   Navigator-Locale-Disclosure, pinnt einige Header). Mozilla koppelt
   die UI-Locale-Spoofing-Logik unglücklicherweise an dieselbe Pref —
   ein deutscher User bekommt also unmittelbar beim Enable seine TB-UI
   auf Englisch. Das ist eine bekannte Querschnitts-Nebenwirkung des
   globalen `resistFingerprinting`-Schalters; saubere Lösung sind
   per-Feature-Ersätze (UTC-`Date`-Hook + Per-Compose-Locale-Rewrite)
   und ist in `docs/follow-up.md` F-018 getrackt. *Workaround heute:*
   en-US-UI hinnehmen ODER Hardening deaktivieren, wenn das Lesen in
   der nativen UI-Sprache nötig ist (im selben Fenster verliert man die
   Netzwerk-Fingerprint-Defense).

Alles außerhalb dieser fünf Buckets ist **in scope** der Policy. Reiche
einen P0-Bug ein, wenn du ein Gegenbeispiel findest.

---

## Tor-Mail-Landschaft — Alternativen auf derselben Schicht

OnionBird sitzt auf der **Mail-Client-Schicht** — es härtet das
Netzwerk- und Header-Verhalten von Thunderbird selbst. Tails und
Whonix arbeiten eine Schicht tiefer (Betriebssystem); sie gehören
in den [Defense-in-Depth-Stack](#stacking-mit-einem-tor-gehärteten-os)
unten, nicht in einen Feature-Vergleich mit einem einzelnen
MUA-Addon.

Auf der Mail-Client-Schicht sind OnionBirds direkte Nachbarn:

| Projekt | Schicht | Tor-Routing | Header-Hygiene | Maintained? |
|---|---|---|---|---|
| **OnionBird** (dies) | Thunderbird-Add-on | ja (SOCKS5 + remoteDNS) | ja (alle bekannten historischen Leak-Vektoren geschlossen; Canary detektiert neue) | ja (2026-) |
| TorBirdy | TB-Extension | ja | ja (historisch) | **nein** — letzte Version 2018, kaputt seit TB 78 (Legacy-XUL-Removal) |
| Tor Mail (legacy, `.onion`) | Webmail-Provider auf .onion | n/a | n/a | Stillgelegt 2013 (Freedom-Hosting-Bust) |
| Mailpile (Tor-Modus) | lokaler Mail-Client | optional | partiell | letztes Release 2020 (effektiv aufgegeben) |
| ProtonMail via Tor | Webmail | ja (`.onion` v3) | Provider-kontrollierte Header, keine Client-seitige Hygiene | ja (nur im Browser) |
| Riseup / Disroot / Cock.li | Mail-Provider mit .onion | ja (du routest via Tor) | Client-abhängig | ja (hängt vom MUA ab, den du draufzeigst) |

Für einen Feature-für-Feature-Vergleich mit dem Projekt, dessen
Nachfolge OnionBird antritt — TorBirdy — siehe
[den nächsten Abschnitt](#onionbird-vs-torbirdy--feature-für-feature).

### Stacking mit einem Tor-gehärteten OS

OnionBird ist absichtlich *kein* Betriebssystem. Um OS-Level-Leaks zu
schließen (DNS anderer Apps, NTP-Zeitstempel, Hostname-Disclosure
durch Nicht-Mail-Prozesse, Swap-Files, Filesystem-mtimes) solltest du
OnionBird **innerhalb** eines Tor-gehärteten OS betreiben:

- **[Tails](https://tails.net/)** — Debian-basiertes Live-System, das
  *allen* Netzwerk-Traffic durch Tor zwingt und vom USB-Stick läuft,
  optional mit persistentem Speicher. Nutze Thunderbird aus dem
  persistenten Tails-Storage mit installiertem OnionBird; du bekommst
  Mail-Client-Hardening + OS-weites Routing in einem Stack.
- **[Whonix](https://www.whonix.org/)** — zwei VMs (Gateway +
  Workstation), wobei das Gateway die Workstation transparent
  torifiziert. Installiere Thunderbird + OnionBird in der Workstation;
  Whonix übernimmt die OS-Isolation, OnionBird die Mail-spezifischen
  Fingerprinting-Vektoren, die Whonix nicht sehen kann.

Die zwei Schichten sind komplementär: ein OS kann kein `Message-ID:
<uuid@localhost.localdomain>` aus einem Mail-Body entfernen, und ein
Addon kann nicht verhindern, dass ein System-NTP-Daemon die echte
Zeit des Hosts leakt. Nutze beides.

---

## OnionBird vs TorBirdy — Feature für Feature

TorBirdy war von ~2012 bis 2018 der Goldstandard und wird heute noch
als das Referenz-Tor-Mail-Addon zitiert. Es ist seit 2018 nicht mehr
veröffentlicht und **inkompatibel mit Thunderbird 78 und neuer**
(Mozilla hat die Legacy-XUL-Extension-Surface entfernt, von der
TorBirdy abhing). Die Tabelle unten ist bewusst ehrlich: wo OnionBird
TorBirdy verbessert, wo beide gleichwertig sind, und wo TorBirdy
Dinge gemacht hat, die OnionBird nicht reimplementiert (meistens
weil der zugrundeliegende TB-Code sich verändert hat und der Fix
nicht mehr nötig ist).

### Wo OnionBird substantiell besser ist

| Feature | TorBirdy | OnionBird |
|---|---|---|
| **Kompatibel mit aktuellem Thunderbird** | kaputt seit TB 78 (2020) — Legacy XUL weg | ja, zielt auf TB 128+ / 140 ESR via WebExtension + Experiments API |
| **Aktive Pflege** | aufgegeben 2018 | aktiv 2026- |
| **Kontinuierlicher Leak-Canary** | keiner — Prefs setzen und beten | läuft beim Startup und alle 10 Min, 3 stream-isolierte SOCKS5-RESOLVE-Circuits cross-checked gegen System-Resolver + PTR-via-Tor-Verifikation |
| **PTR-via-Tor-Verifikation** | keine | jede abweichende System-IP muss via Tor zum Canary-Host oder einer echten Subdomain PTR-auflösen; gemeinsame Public Suffixes (`co.uk`) explizit zurückgewiesen |
| **Message-ID-FQDN-Strategie** | hardgecodet `localhost.localdomain` — jeder TorBirdy-User teilte denselben Supercluster-Fingerprint | 4 Modi: `from_domain` (Default, blendet mit normalen Provider-Usern ein), `localhost`, `localhost.localdomain` (TorBirdy-kompatibel), oder `custom`. Per-Install-Random `m<hex>.invalid`-Fallback wenn keine brauchbare Domain |
| **Stream-Isolation pro Probe** | n/a | jeder Canary-Circuit verwendet ein frisches Crypto-RNG-SOCKS5-Isolation-Token; User-Traffic SMTP/IMAP auch über Isolation geroutet |
| **DoH (DNS-over-HTTPS) unterdrückt** | Pre-DoH-Ära — nicht adressiert | `network.trr.mode=5` plus `trr.uri / custom_uri / bootstrapAddress / confirmationNS` geleert |
| **ECH (Encrypted Client Hello) unterdrückt** | Pre-ECH-Ära — nicht adressiert | `network.dns.echconfig.enabled=false`, `use_https_rr_as_altsvc=false` — schließt den Out-of-Band-DNS-Pfad, den SOCKS-remote-DNS nicht abdeckt |
| **WebRTC Defense-in-Depth** | hat `media.peerconnection.enabled` deaktiviert | dito + `ice.no_host`, `default_address_only`, `proxy_only_if_behind_proxy` gepinnt, sodass ein künftiges Re-Enable keine Host-Candidates leaken kann |
| **Crash-Reporter-URL kastriert** | partiell (Reporter deaktiviert) | Reporter aus + `breakpad.reportURL` + `toolkit.crashreporter.submitURL` geleert, `include_extensions=false` |
| **Pref-Write-Allowlist** | kein solches Konzept | die privilegierte Experiments-API-Surface des Addons kann **keine** beliebigen Prefs schreiben — `browser.startup.*`, `devtools.*`, `xpinstall.signatures.required` etc. am Gate abgelehnt |
| **Empirische End-to-end-Test-Suite** | manuelle Smoke-Tests | container-gesteuerte Integration-Suite (aktuell 177+ Tests, der genaue Wert wird von CI per `pytest --co -q` injiziert; neue Audit-Findings landen als `xfail(strict=True)` statt gelöscht zu werden) + 6 Real-Tor-Szenarien gegen `undisclose.de` mit byteweisem Header-Audit (H1–H15) auf erfassten Mails |
| **Mid-Session-Re-Assertion** | statisch beim Startup | re-applied bei jedem Account-Create / Account-Modify-Event plus periodisch (10 Min); kaputte Hardening-Pref wird repariert ohne den erkannten SOCKS-Endpoint zu überschreiben |
| **Per-Install-Random-Fallback** | geteiltes `localhost.localdomain` | persistentes `m<10hex>.invalid` pro Installation — verschiedene Installs haben verschiedene Message-ID-FQDNs |
| **Default-Identity-Branch** | nur per-Identity | schreibt auch `mail.identity.default.*`, sodass eine nach Enable erstellte Identity nicht den echten Hostname erben kann |
| **Application-Layer Send-Block bei Leak** | keiner — verließ sich komplett auf `failover_direct=false` im Proxy-Layer | `compose.onBeforeSend`-Listener bricht ausgehende Sends mit einer sichtbaren Compose-Window-Notification ab, sobald das letzte Canary-Verdict etwas anderes als `clean` ist; fängt langsame DNS-Poisoning-Szenarien ab, die das Transport-Layer-Safety-Net nicht triggern |
| **Mitgelieferte UI-Locales** | EN + eine Handvoll Community-Übersetzungen, kein recent Update | 30 Locale-Bundles für den Großteil der UI — Westliche Latein/Slawisch/Türkisch (EN, DE, FR, PT, ES, PL, UK, RU, BE, TR) · RTL Arabische Schrift (FA, AR, HE, KU, UR, PS, UG) · Südasiatisch (HI, BN) · Ostasiatisch (ZH-CN, BO) · Südostasiatisch (VI, TH, MY, ID) · Afrikanisch (AF, SW, AM, TI) · Kaukasisch (KA). PS/UG/BO/MY/BN/SW/AM/TI/KA zielen auf Repression-/Zensur-Hotspots; KI-übersetzt, native-speaker-Review per PR willkommen. Neu hinzugefügte Feature-Strings (z.B. F-168 SOCKS-Override-UI) shippen handübersetzt in EN + DE und mit Englisch-Fallback in den anderen 28 Locales bis zum nächsten Translation-Pass — `browser.i18n.getMessage` liefert den englischen Text in den nicht-übersetzten Locales, die UI bleibt funktional |

### Wo beide gleichwertig sind

Sowohl TorBirdy (als es funktionierte) als auch OnionBird machen
folgendes gleich, weil es nur eine richtige Antwort gibt:

- **SOCKS5-Proxy** mit `network.proxy.type=1`, `socks_version=5`
- **`socks_remote_dns=true`**, damit DNS-Resolution am Tor-Exit
  passiert, nicht auf der User-Maschine
- **`failover_direct=false`**, sodass ein kaputter Proxy den Send
  scheitern lässt statt auf Clearnet zurückzufallen
- **HELO/EHLO-Override auf `[127.0.0.1]`**, sodass SMTP nicht den
  echten Hostname leakt
- **User-Agent / X-Mailer unterdrückt**
  (`mailnews.headers.sendUserAgent=false`)
- **`intl.accept_languages=en-US, en`**, sodass Accept-Language-Header
  nicht das Locale des Users fingerprinten
- **Telemetrie / Health-Report / Safebrowsing / Captive-Portal-Probes**
  deaktiviert
- **Address-Book-Auto-Collect** aus, sodass Tor-geroutete Empfänger
  nicht in einer dauerhaften lokalen "Collected Addresses"-Liste
  landen
- **Update-Phone-Home-URLs geleert** (App, Extensions, GMP-Manager)
- **IPv6 deaktiviert** by default (TBs SOCKS-Handling hatte
  IPv6-Edge-Cases)

### Wo TorBirdy Dinge gemacht hat, die OnionBird absichtlich NICHT macht

TorBirdy war für ein älteres Thunderbird. Manche seiner Prefs
zielten auf Features, die nicht mehr existieren oder ersetzt wurden:

- **Enigmail-Debug-Log-Scrubbing** — Enigmail ist seit TB 78
  (Juli 2020) nicht mehr ladbar, weil das alte XUL-Addon-Format
  entfernt wurde, auf dem Enigmail aufbaute; sein Maintainer hat
  bei der RNP-basierten nativen OpenPGP-Integration in TB 78+
  selbst mitgebaut, einen MailExtension-Port gibt es nicht. Das
  Enigmail-v2.x-Archiv lässt sich noch in TB ≤ 68 installieren,
  aber diese Versionen bekommen seit 2020 keine Security-Updates
  und sind in einem Tor-Threat-Model nicht haltbar. OnionBird
  zielt auf TB 128+, daher ist das Scrubbing irrelevant.
- **Lightning-Calendar-Disable** — Lightning ist eingebaut und
  always-on in modernem TB; via Prefs zu deaktivieren funktioniert
  nicht mehr. OnionBirds Lücke bei Calendar-Leaks (iTIP/iMIP,
  `PRODID`, `DTSTAMP`, `UID@hostname`) ist anerkannt und in der
  Roadmap getrackt.
- **HTTPS-Everywhere-Style-URL-Rewriting** — war ein TorBirdy-
  Sibling, nie im Scope des Addons selbst; modernes Web nutzt
  HTTPS by default.

### Wo beide noch nicht ausreichen

Ehrlich zu offenem Boden:

- **iTIP / iMIP Calendar-Einladungen** leaken `PRODID:`,
  `DTSTAMP:`, `UID@hostname` — weder TorBirdy noch OnionBird
  hooked den Compose-Pfad, um sie zu sanitisieren. Im
  OnionBird-Roadmap getrackt.
- **OpenPGP-Signature-Creation-Time** (beim Signieren) offenbart
  die lokale Uhr und kann Sends korrelieren. Keines der Addons
  adressiert es.
- **`Authentication-Results` vom Provider-MTA** offenbart die
  authentifizierte Mailbox jedem Empfänger. Inhärent zu
  authentifiziertem SMTP, addon-seitig nicht fixbar. Workaround:
  Throwaway- / Pseudonym-Mailbox.
- **Tor-Exit-IP in der `Received:`-Kette** — der Empfänger
  erfährt "dieser User hat über Tor gesendet". Inhärent zum
  SMTP-Transport.

### TL;DR

Wenn du TorBirdy 2018 vertraut hast, solltest du OnionBird jetzt
in Betracht ziehen: dasselbe Threat Model, dieselbe
Pref-Hardening-Philosophie, aber auf einem Thunderbird, das seit
TorBirdys Tod acht Major-Versionen weitergewandert ist. Plus
empirische Canary-Verifikation, moderne DoH/ECH-Abdeckung und eine
Pref-Write-Allowlist, die den Blast-Radius künftiger Regressionen
begrenzt.

Wenn du TorBirdy *und* ein Tor-gehärtetes OS verwendet hast, mach
das mit OnionBird weiter — siehe
[Stacking mit Tails / Whonix](#stacking-mit-einem-tor-gehärteten-os)
oben.

---

## Bevor du installierst

Das Addon härtet, was **innerhalb** von Thunderbird läuft. Für 100%
Tor-Abdeckung muss auch der **OS-Resolver** durch Tor laufen. Wähle
den Pfad, der zu deinem Setup passt:

- **Tails / Whonix Workstation** — System-DNS ist schon Tor.
  Installiere die `.xpi`, fertig.
- **Stock Linux mit System-Tor** — füge `DNSPort 5353` zu deiner
  `/etc/tor/torrc` hinzu und stelle sicher, dass `/etc/resolv.conf`
  ihn erreicht (lokales `dnsmasq`/`unbound`-Forwarding auf
  `127.0.0.1:5353` ist der Standard).
- **Nur Tor-Browser-Bundle** — Tor lauscht auf `9150`, nicht `9050`;
  das Addon probt vorhandene Prefs plus die üblichen lokalen Ports
  `9050` und `9150`, bevor es Proxy-Prefs schreibt. Spätere
  Re-asserts bewahren diesen Endpunkt.
- **Remote-Tor/Whonix-SOCKS** — nutze ein IP-Literal wie
  `10.152.152.10:9050`, keinen Hostnamen. Das Addon ignoriert
  SOCKS-Endpunkte mit Hostnamen absichtlich, weil schon die Auflösung
  des Proxy-Hostnamens ein lokaler DNS-Lookup vor Tor wäre.
- **Stock-Desktop ohne System-DNS via Tor** — Installation auf eigene
  Verantwortung. Der Startup-Canary flaggt die Konfiguration auf der
  Options-Seite und in der Browser-Konsole.

---

## Was es heute kann

- Routet IMAP/SMTP durch einen lokalen SOCKS5-Proxy (default
  `127.0.0.1:9050`, konfigurierbar) mit `socks_remote_dns=true` und
  `failover_direct=false`. Enable probt vorhandene SOCKS-Prefs,
  System-Tor `9050` und Tor Browser `9150`; Startup/periodischer
  Re-assert bewahrt den aktuellen Endpunkt nur, wenn er Loopback oder
  ein IP-Literal ist.
- Normalisiert identifizierende Header auf ausgehender Mail:
  `User-Agent` / `X-Mailer` unterdrückt, `Message-ID`-FQDN
  konfigurierbar (default = deine From-Domain), SMTP `HELO`/`EHLO`
  umgeschrieben zu `[127.0.0.1]`, `Date` UTC via
  `privacy.resistFingerprinting`, kein `format=flowed`.
- Defense-in-Depth-Pref-Hardening: TRR=5, OCSP aus, kein WebRTC,
  kein DNS-Prefetch, kein Predictor, kein Update-phone-home, keine
  Telemetrie, kein Safebrowsing, keine Captive-Portal-Probes, kein
  Remote-Content-Rendering.
- **SOCKS5-RESOLVE-vs-System-DNS-Canary** beim Startup und
  periodisch während aktiver Härtung: vergleicht alle öffentlichen
  System-IPs mit stream-isolierten Tor-Circuits und nutzt PTR-via-Tor
  nur als strikten Exakt-Host/Subdomain-Fallback.
- Privacy-sicheres Logging: Command-Logs und Hintergrund-Diagnose
  redigieren rohe Canary-IP/PTR-Daten und Account-Identifier per
  Default.
- **Tor-Testmodus** auf der Options-Seite prüft, ob ein lokaler
  Tor-SOCKS-Endpunkt erreichbar ist, ohne Mail zu senden, Prefs zu
  ändern oder System-DNS für den Zielhost-Probe zu verwenden.
- Die Options-Seite unterstützt System-/Hell-/Dunkel-Theme, ist in
  **21 UI-Locales** verfügbar (EN, DE, ES, FR, PT, PL, UK, RU, BE, TR,
  FA, AR, HE, KU, UR, HI, ZH-CN, VI, TH, ID, AF) und enthält eine
  eingebaute Hilfe mit TL;DR plus Nerd-Modus zu Scope, Grenzen,
  TorBirdy-Kompatibilität und der nötigen Experiments-API.
- Aktiviert sich automatisch bei erster Installation. **Disable-
  Button** auf der Options-Seite stellt den Snapshot wieder her.
- Standardmäßig werden nur **Onion- + Loopback**-SMTP-Server gehärtet
  (B-003): deine vorhandenen Clearnet-Accounts laufen weiter.
- Companion-`user.js` für Pre-Startup-Hardening + ein Skript, das
  deine vorhandenen Accounts in `prefs.js` enumeriert und passende
  Per-Server-Zeilen emittiert.

---

## Quick Start

```sh
# Baue die .xpi (MV2, kanonisch)
make build

# Optional: paralleler MV3-Build für Forward-Compat-Smoke
make build-mv3

# Test-Pod hochfahren (Tor+DNSPort + aiosmtpd + DNS-Forwarder +
# Xvfb+TB + Runner)
make COMPOSE_ENGINE=docker test-up

# Integration-Suite laufen lassen (aktueller Test-Count: `pytest --co -q | wc -l`; null Skips im Standard-Pod-Env)
make COMPOSE_ENGINE=docker test-integration

# Herunterfahren
make COMPOSE_ENGINE=docker test-down
```

# Oder einen Provider explizit für einen fokussierten Lauf wählen
set -a; source test/external/secrets.env; set +a
PYTHONPATH=test pytest -v -s test/external/ --provider=POSTEO
```

`T0R_TEST_PROVIDER` wählt den Default-Provider für `make
test-external`. `--provider=...` überschreibt ihn bei direkten
pytest-Läufen. Wenn `T0R_RECV_USER` gesetzt ist, muss der Empfänger
eine eigene Mailbox sein: `T0R_RECV_EMAIL` muss eine valide
Empfängeradresse sein, verschieden vom Sender, und `T0R_RECV_PASS`
darf nicht leer sein.

### Signieren für ATN

Siehe [docs/atn-signing.md](docs/atn-signing.md) — erfordert
Mozilla-Developer-Credentials.

---

## Architektur

OnionBird ist ein Hybrid: ein MailExtension-Background-Skript stellt
die öffentliche API bereit (Options-Seite, Auto-Enable-Handler beim
Install, Message-Bus für Enable/Disable, periodischer Startup-
Self-Test), während ein Experiments-API-Modul im Parent-Process läuft
und `Services.prefs`, `MailServices.outgoingServer`,
`MailServices.accounts`, rohes SOCKS5 RESOLVE / RESOLVE_PTR und
`nsIDNSService.clearCache`-Manipulation exponiert. Die beiden Hälften
kommunizieren über den Custom-Namespace `browser.onionbird.*`.

Siehe [docs/architecture.md](docs/architecture.md) für ein Diagramm
und [docs/audit-2026-05-21-bug-report.md](docs/audit-2026-05-21-bug-report.md)
für die Audit-Findings, die das aktuelle Design geformt haben.

---

## Roadmap / bekannte Limitationen

Siehe [docs/follow-up.md](docs/follow-up.md) für die vollständige
ranked Liste. Highlights für künftige Iterationen:

- Mixed-Mode-UI-Toggle für User, die explizit alle SMTP-Server härten
  wollen, nicht nur Onion/Loopback-Server.
- Network-Link-/Resolver-Change-Event zusätzlich zum periodischen
  Canary.
- Multi-Circuit-PTR-Retry, um False Positives zu reduzieren, wenn ein
  Tor-Exit PTR verweigert.
- Saved-Login-Tagging für vom Add-on angelegte Tor-Accounts; Disable
  bietet bereits einen Löschpfad für erkannte Onion-/Loopback-Mail-Logins.
- First-Run-Wizard mit SOCKS-Port-Auto-Detect.
- Bridges / Pluggable Transports für zensierte ISPs.
- Tor-Control-Port-Integration (NEWNYM pro Send).
- Paketierte Cross-Platform-Installer-UX über das aktuelle Skript hinaus.
- Native-Speaker-Review der frisch hinzugefügten Repressions-/Zensur-
  Hotspot-Locales (`my`, `ug`, `bo`, `am`, `ti`, `ps`, `bn`, `ka`,
  `sw`) — aktuell KI-übersetzt; PRs von Native-Speakern, die
  Terminologie, Idiomatik und insbesondere die sicherheitskritischen
  Strings schärfen, sind priorisiert. `prs` (Dari) wurde bewusst
  weggelassen, weil `fa` für ein MVP nahe genug liegt; ein separates
  `prs`-Locale ist willkommen, falls jemand die afghan-persische
  Wortwahl differenzieren möchte.

---

## Lizenz

MPL-2.0. Siehe [LICENSE](LICENSE) für den vollen Text.

Diese Software wird WIE BESEHEN ohne Gewährleistung jeder Art
bereitgestellt. Die Autoren haften nicht für Deanonymisierung oder
sonstigen Schaden, der aus der Nutzung entsteht. Siehe LICENSE für
den vollen Disclaimer.
