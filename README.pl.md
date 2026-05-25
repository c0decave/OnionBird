# OnionBird

**Języki:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · **Polski** · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **ALPHA — późna alpha, szczelna na systemach z DNS przez Tor. Przeczytaj [wymagania](#przed-instalacją) przed instalacją.**

> Przeczytaj [model zagrożeń](docs/threat-model.md) i [listę follow-up](docs/follow-up.md), zanim zaufasz OnionBirdowi w użyciu krytycznym dla anonimowości.

OnionBird to dodatek do Thunderbirda, który trasuje IMAP/SMTP przez lokalny proxy Tor i usuwa lub normalizuje nagłówki wiadomości historycznie używane do deanonimizacji nadawców. Cel: Thunderbird 140 ESR. Pomyślany jako współczesny następca nieutrzymywanego rozszerzenia TorBirdy (ostatnie wydanie v0.2.6 z 2018, zabite przez usunięcie Legacy XUL w TB 78).

Bieżąca wersja: **0.1.1**.

---

## Polityka 100% prywatności i bezpieczeństwa

Mandat projektu jest binarny: **każda obserwowalna ścieżka kodu, która przecieka tożsamość użytkownika, prawdziwy IP, hostname, locale, strefę czasową lub sam fakt utwardzania poczty, jest defektem P0 i blokuje wydanie.** „Dość dobrze", „zazwyczaj działa" lub „prawie bez wycieku" to niedopuszczalne wyniki.

W praktyce:

- **Fail closed domyślnie.** `network.proxy.failover_direct = false` jest wymuszane — jeśli skonfigurowane proxy Tor jest nieosiągalne, wysyłka się nie powiedzie. Dodatek NIGDY nie spada cicho do clearnetu.
- **DNS tylko przez Tor.** `socks_remote_dns = true`, `network.trr.mode = 5` (bez równoległego DoH), `network.dns.disablePrefetch = true`. Empirycznie zweryfikowane: zero zapytań DNS dociera do lokalnego resolvera podczas prawdziwej wysyłki przez Tor.
- **OCSP wyłączone.** W przeciwnym razie sprawdzenia odwołania wysyłałyby żądanie HTTP clearnet do CA przy każdym uścisku TLS.
- **Bez phone-home update.** URL-e aplikacji + rozszerzeń + GMP-managera wyczyszczone.
- **Bez telemetrii, Safebrowsing, captive-portal-probe, renderowania zdalnej treści.**
- **Bez WebRTC, geolokalizacji, DNS prefetch, predictora.**
- **Ochrona w trakcie sesji.** Prefs są ponownie afirmowane przy każdym starcie TB i okresowo, gdy hardening jest aktywny. Jeśli strona trzecia zmieni utwardzone prefs, dodatek naprawia bez nadpisania wykrytego endpointu SOCKS.
- **Hardening jest odwracalny.** Snapshot wzięty przed pierwszym włączeniem, możliwy do przywrócenia przyciskiem Wyłącz lub wiadomością `disable-hardening`.
- **Canary self-test** przy starcie i podczas aktywnego hardeningu: porównuje SOCKS5-RESOLVE (3 stream-izolowane circuity Tor) z pełnym zbiorem odpowiedzi systemowego resolvera.
- **Dziennikowanie chroniące prywatność.** Logi i komunikaty konsoli sumują liczniki, maskowane IP i klasy błędów — bez surowych IP czy identyfikatorów konta.
- **Allowlist zapisów prefs** w API experiment. Powierzchnia parent nie może zapisywać dowolnych prefs.

**Granice nieusuwalne — OnionBird NIE MOŻE tego naprawić:**

1. **`Authentication-Results: ... smtp.auth=<twoja-skrzynka>@<dostawca>`** jest dodawany przez MTA dostawcy — ujawnia każdemu odbiorcy uwierzytelnioną skrzynkę. Nieodłączne dla uwierzytelnionego SMTP. *Obejście:* skrzynka jednorazowa / pseudonimowa do wrażliwej korespondencji.
2. **IP wyjścia Tor pojawia się w łańcuchu `Received:` u odbiorcy.** MTA robi reverse-DNS i tworzy nazwy w stylu `tor-exit-107.digitalcourage.de`. Odbiorca dowiaduje się „ten użytkownik wysłał przez Tor".
3. **Wycieki na poziomie OS** — hostname od innych aplikacji, NTP, swap, znaczniki czasu plików. Użyj Tails lub Whonix.
4. **Korelacja sieciowa** — obserwator obu końców circuit Tora. Higiena nagłówków tego nie pokonuje.

Wszystko poza tymi czterema kategoriami jest **w zakresie** polityki. Zgłoś bug P0, jeśli znajdziesz kontrprzykład.

---

## Krajobraz mail-Tor

Pełne porównanie patrz [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature). Krótko: OnionBird to **normalny dodatek Thunderbirda** (nie osobny OS jak Tails/Whonix), z **empirycznie weryfikowanym pokryciem DNS przez Tor**, **ciągłym canary** oraz **konfigurowalnym FQDN Message-ID** (zamiast supercluster `localhost.localdomain` z TorBirdy).

---


> ⚠️ **Połącz z systemem operacyjnym utwardzonym pod Tor** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## Przed instalacją

Dodatek utwardza to, co działa **wewnątrz** Thunderbirda. Dla 100% pokrycia Torem **resolver OS** też musi iść przez Tor:

- **Tails / Whonix workstation** — DNS systemu już jest przez Tor. Zainstaluj `.xpi` i gotowe.
- **Standardowy Linux z systemowym Torem** — dodaj `DNSPort 5353` do `/etc/tor/torrc` i upewnij się, że `/etc/resolv.conf` tam dociera (lokalny `dnsmasq`/`unbound` przekazujący do `127.0.0.1:5353`).
- **Sam Tor Browser bundle** — Tor słucha na `9150`, nie `9050`; dodatek sonduje istniejące prefs i oba popularne porty przed zapisem prefs proxy.
- **Zdalny SOCKS Tor/Whonix** — użyj IP literalnego (`10.152.152.10:9050`), nie hostname.
- **Zwykły desktop bez DNS systemu przez Tor** — instalujesz na własne ryzyko. Canary oznaczy konfigurację na stronie Opcji i w konsoli.

---

## Co robi dziś

- Trasuje IMAP/SMTP przez lokalne proxy SOCKS5 (domyślnie `127.0.0.1:9050`, konfigurowalne) z `socks_remote_dns=true` i `failover_direct=false`.
- Normalizuje nagłówki identyfikujące: `User-Agent` / `X-Mailer` wyciszone, FQDN `Message-ID` konfigurowalny (domyślnie Twój From-domain), SMTP `HELO`/`EHLO` przepisany na `[127.0.0.1]`, `Date` UTC, bez `format=flowed`.
- Defense-in-depth: TRR=5, OCSP off, bez WebRTC, bez DNS prefetch, bez predictora, bez phone-home updatów, bez telemetrii, bez Safebrowsing, bez captive-portal, bez zdalnej treści.
- **Canary SOCKS5-RESOLVE vs DNS systemu** przy starcie i okresowo.
- **Tor test mode** na stronie Opcji.
- Strona Opcji obsługuje motyw system/jasny/ciemny, wielojęzyczne UI i wbudowaną Pomoc (TL;DR + tryb nerd).
- Auto-włącza się przy pierwszej instalacji. **Przycisk Wyłącz** przywraca snapshot.
- Domyślnie utwardzane są tylko serwery SMTP **onion + loopback** (B-003) — istniejące konta clearnet działają nadal.
- `user.js` do hardeningu przed startem + skrypt enumerujący istniejące konta z `prefs.js`.

---

## Szybki start

```sh
# Build .xpi (MV2, kanoniczny)
make build

# Opcjonalnie: równoległy build MV3
make build-mv3

# Uruchom pod testowy (Tor+DNSPort + aiosmtpd + DNS-forwarder + Xvfb+TB + runner)
make COMPOSE_ENGINE=docker test-up

# Uruchom suite integracyjną (148 testy w 0.1.1)
make COMPOSE_ENGINE=docker test-integration

# Zatrzymaj
make COMPOSE_ENGINE=docker test-down
```

## Architektura

OnionBird jest hybrydą: skrypt background MailExtension dostarcza publiczną powierzchnię API (strona opcji, auto-włączenie przy instalacji, magistrala wiadomości, periodyczny self-test), a moduł Experiments API działa w procesie parent i wystawia `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, surowe SOCKS5 RESOLVE / RESOLVE_PTR i `nsIDNSService.clearCache`. Obie połowy komunikują się przez przestrzeń `browser.onionbird.*`.

Patrz [docs/architecture.md](docs/architecture.md).

---

## Roadmap / znane ograniczenia

Patrz [docs/follow-up.md](docs/follow-up.md). Odroczone do przyszłych iteracji: tryb mixed-mode UI, hook na zmianę łącza sieciowego / resolvera, multi-circuit PTR retry, tagowanie loginów utworzonych przez dodatek, kreator first-run, bridges / pluggable-transports dla cenzurowanych ISP, integracja Tor control-port (NEWNYM przy wysyłce), spakowany cross-platform installer.

---

## Licencja

MPL-2.0. Patrz [LICENSE](LICENSE) dla pełnego tekstu.

Oprogramowanie dostarczane JAK JEST, bez żadnych gwarancji. Autorzy nie odpowiadają za deanonimizację ani inne szkody wynikające z używania. Patrz LICENSE.
