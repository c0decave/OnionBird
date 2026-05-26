# OnionBird

**Tale:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · **Afrikaans** · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **BETA — laat-alfa, lekdig op 'n bedryfstelsel met Tor-bewuste DNS. Lees [die voorvereistes](#voor-installasie) voor installasie.**

> Lees [die bedreigingsmodel](docs/threat-model.md) en die [follow-up-lys](docs/follow-up.md) voordat jy OnionBird vertrou vir gebruik wat krities is vir anonimiteit.

OnionBird is 'n Thunderbird-byvoegtoepassing wat IMAP/SMTP via 'n plaaslike Tor-proxy roeteer en boodskapopskrifte wat histories gebruik is om senders te de-anonimiseer, verwyder of normaliseer. Teiken: Thunderbird 140 ESR. Bedoel as moderne opvolger van die nie meer onderhoude TorBirdy-uitbreiding (laaste vrystelling v0.2.6 in 2018; dood weens die verwydering van Legacy XUL in TB 78).

Huidige weergawe: **0.1.4**.

---

## 100% Privaatheid- en Sekuriteitsbeleid

Die projek se mandaat is binêr: **enige waarneembare kodepad wat die gebruiker se identiteit, werklike IP, hostnaam, locale, tydsone, of die blote feit dat die gebruiker sy pos verhard, laat lek, is 'n P0-defek en blokkeer 'n vrystelling.** "Goed genoeg", "werk gewoonlik" of "amper sonder lek" is nie aanvaarbare uitkomste nie.

Konkreet:

- **Fail-closed by verstek.** `network.proxy.failover_direct = false` word afgedwing — as die geconfigureerde Tor-proxy onbereikbaar is, moet die stuur misluk. Die byvoegtoepassing val NOOIT stilweg terug op clearnet nie.
- **DNS slegs deur Tor.** `socks_remote_dns = true`, `network.trr.mode = 5` (geen parallelle DoH), `network.dns.disablePrefetch = true`. Empiries bevestig: nul DNS-navrae bereik die plaaslike resolver tydens 'n regte Tor-stuur.
- **OCSP af.** Anders sou intrekkingstoetse 'n clearnet HTTP-versoek na die CA stuur by elke TLS-handdruk.
- **Geen update phone-home nie.** URL'e vir app + uitbreidings + GMP-manager is leeggemaak.
- **Geen telemetrie, Safebrowsing, captive-portal-toetse of remote-content-rendering nie.**
- **Geen WebRTC, geolocation, DNS prefetch of predictor nie.**
- **Beskerming midde-sessie.** Prefs word weer bevestig by elke TB-begin en periodiek terwyl verharding aktief is.
- **Verharding is omkeerbaar.** 'n Snapshot word voor die eerste aktivering geneem en kan herstel word met die Disable-knoppie op die Options-bladsy of die `disable-hardening`-boodskap.
- **Self-test canary** by begin en gedurende aktiewe verharding: vergelyk SOCKS5-RESOLVE (3 stroom-geïsoleerde Tor circuits) met die volle antwoordstel van die stelsel-resolver.
- **Privaatheidsveilige diagnose.** Logs gee tellings, gemaskerde IP's en foutklasse — geen rou IP's of rekeningidentifiseerders nie.
- **Allowlist vir pref-skryfwerk** in die experiment API.

**Inherente grense — OnionBird kan dit nie regstel nie:**

1. **`Authentication-Results: ... smtp.auth=<jou-posbus>@<verskaffer>`** word deur die verskaffer se MTA bygevoeg — onthul die geverifieerde posbus aan elke ontvanger. *Omleiding:* gebruik 'n weggooi-/skuilnaam-posbus vir sensitiewe korrespondensie.
2. **Tor-uitgang-IP verskyn in die `Received:`-ketting van die ontvanger.** MTA's doen reverse-DNS en lewer name soos `tor-exit-107.digitalcourage.de`. Die ontvanger leer "hierdie gebruiker het via Tor gestuur".
3. **OS-vlak-leke** — hostname-onthulling deur ander apps, NTP, swap, lêerstelsel-tydstempels. Gebruik Tails of Whonix.
4. **Netwerkkorrelasie** — waarnemers van albei kante van 'n Tor-circuit. Word nie deur opskrifhigiëne verslaan nie.

Enigiets wat nie in hierdie vier kategorieë val nie, is **binne die omvang** van die beleid. Open 'n P0-bug as jy 'n teenvoorbeeld vind.

---

## mail-Tor-landskap

Volledige vergelyking sien [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature). Kortliks: OnionBird is **'n gewone Thunderbird-byvoegtoepassing** (nie 'n aparte OS soos Tails/Whonix nie), met **empiries bevestigde DNS-via-Tor-dekking**, **deurlopende canary** en **konfigureerbare Message-ID FQDN** (in plaas van TorBirdy se supercluster `localhost.localdomain`).

---


> ⚠️ **Stapel met 'n Tor-geharde OS** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## Voor installasie

Die byvoegtoepassing verhard wat **binne** Thunderbird loop. Vir 100% Tor-dekking moet die **OS-resolver** ook deur Tor gaan:

- **Tails / Whonix workstation** — stelsel-DNS gaan reeds deur Tor. Installeer die `.xpi`, klaar.
- **Standaard Linux met stelsel-Tor** — voeg `DNSPort 5353` by `/etc/tor/torrc` en maak seker `/etc/resolv.conf` bereik dit.
- **Net Tor Browser bundle** — Tor luister op `9150`, nie `9050` nie; die byvoegtoepassing toets bestaande prefs en albei algemene poorte voor dit proxy-prefs skryf.
- **Afgeleë Tor/Whonix SOCKS** — gebruik 'n IP-literaal (`10.152.152.10:9050`), nie 'n hostnaam nie.
- **Standaard tafelblad sonder OS-DNS deur Tor** — installeer op eie risiko. Die canary sal die konfigurasie merk op die Options-bladsy en in die konsole.

---

## Wat dit vandag doen

- Roeteer IMAP/SMTP deur 'n plaaslike SOCKS5-proxy (verstek `127.0.0.1:9050`, konfigureerbaar) met `socks_remote_dns=true` en `failover_direct=false`.
- Normaliseer identifiserende opskrifte: `User-Agent` / `X-Mailer` onderdruk, FQDN van `Message-ID` konfigureerbaar (verstek = jou From-domein), SMTP `HELO`/`EHLO` herskryf na `[127.0.0.1]`, `Date` UTC, geen `format=flowed`.
- Defense-in-depth: TRR=5, OCSP af, geen WebRTC, geen DNS prefetch, geen predictor, geen phone-home, geen telemetrie, geen Safebrowsing, geen captive-portal, geen remote-inhoud.
- **SOCKS5-RESOLVE vs stelsel-DNS canary** by begin en periodiek.
- **Tor test mode** op die Options-bladsy.
- Die Options-bladsy ondersteun stelsel-/lig-/donkertema, meertalige UI en ingeboude Help (TL;DR + Nerd-modus).
- Aktiveer outomaties by die eerste installasie. **Disable-knoppie** herstel die snapshot.
- Verstek verhard slegs **onion + loopback** SMTP-bedieners (B-003) — jou bestaande clearnet-rekeninge bly normaal werk.

---

## Argitektuur

OnionBird is hibried: 'n MailExtension-agtergrondskrip verskaf die publieke API-oppervlak, en 'n Experiments API-module loop in die parent-proses en stel `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, rou SOCKS5 RESOLVE / RESOLVE_PTR en `nsIDNSService.clearCache`-manipulasie bloot. Die twee helftes kommunikeer via die `browser.onionbird.*`-naamruimte. Sien [docs/architecture.md](docs/architecture.md).

---

## Padkaart / bekende beperkings

Sien [docs/follow-up.md](docs/follow-up.md). Uitgestel: mixed-mode UI-toggle, hook op netwerkskakel/resolver-verandering, multi-circuit PTR-retry, etikettering van logins wat deur die byvoegtoepassing geskep is, first-run wizard, bridges / pluggable-transports vir gesensorde ISP's, Tor control-port-integrasie (NEWNYM per stuur), gepakte cross-platform installer.

---

## Lisensie

MPL-2.0. Vir die volle teks sien [LICENSE](LICENSE).

Sagteware word soos dit is verskaf, sonder enige waarborg. Die outeurs is nie aanspreeklik vir de-anonimisering of ander skade wat uit gebruik voortspruit nie. Sien LICENSE vir die volle vrywaring.
