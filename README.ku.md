# OnionBird

**Ziman:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · **Kurdî** · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **ALFA — alfayek dereng, li ser OSên ku DNS bi Tor diçe bê lêkçûn e. Berî sazkirinê [pêwistiyan](#berî-sazkirinê) bixwîne.**

> Berî baweriya bi OnionBird ji bo karên krîtîk ên nepenîtiyê, [modela tehdîdê](docs/threat-model.md) û [lîsteya follow-up](docs/follow-up.md) bixwîne.

OnionBird pêvekek e ji bo Thunderbird ku IMAP/SMTP bi rêya proxyeke herêmî ya Tor dişîne û sernavên peyaman ên ku berê ji bo lêveçûna ji ya nepenîtiya şander hatibûn bikaranîn ji nav dibe an nasnav dike. Armanc: Thunderbird 140 ESR. Wek şûnşînê nûjen ê pêveka TorBirdy ya bê lênihêr (berdana dawî v0.2.6 di 2018an, bi rakirina Legacy XUL di TB 78an de mir).

Versiyona heyî: **0.1.1**.

---

## Polîtîkaya nepenîtî û ewlehiyê 100%

Erkê projeyê dudîn e: **her rêya kodê ya çavdêrî yê ku kîjayetiya bikarhêner, IP-ya rasteqîn, hostname, locale, kêliya demê, an rastiya ku bikarhêner posteyê xwe dihêre, eşkere bike, wek nekemasiya P0 tê hesibandin û berdanê asteng dike.** «Têrê dike», «bi gelemperî dixebite», an «hema bê lêkçûn» encamên qebûl in ne.

Bi şêwakî:

- **Fail-closed wek standard.** `network.proxy.failover_direct = false` bi zorê tê dayîn — heke Tor proxy ku hat avakirin negihîştbar be, şandin divê têk biçe. Pêvek qet ji nişka ve naçe clearnet.
- **DNS tenê bi rêya Tor.** `socks_remote_dns = true`, `network.trr.mode = 5` (bê DoH paralel), `network.dns.disablePrefetch = true`. Em emperîk pejirand: sifir lêpirsîna DNS digihîje resolverê herêmî di dema şandina rasteqîn a Tor.
- **OCSP girtî.** Wekî din, kontrolên qedandinê dê ji bo her TLS handshake daxwazek HTTP-ya clearnet bişînin CAyê.
- **Bê phone-home ji bo nûkirinan.** URLên sepan + pêvekan + GMP-manager hatin paqijkirin.
- **Bê telemetry, bê Safebrowsing, bê captive-portal, bê naveroka dûr.**
- **Bê WebRTC, bê geolocation, bê DNS prefetch, bê predictor.**
- **Parastina di nava sesyonê de.** Prefs di her destpêka TB de û periyodîk dema gartavkirin çalak e, ji nû ve tên piştrastkirin.
- **Gartavkirin dikare were vegerandin.** Snapshot berî çalakkirina yekem tê girtin û bi bişkojka Neçalakkirinê ya li ser rûpela Vebijêrkan an peyama `disable-hardening` tê vegerandin.
- **Canary ya self-test** li destpêkê û dema gartavkirin çalak e: SOCKS5-RESOLVE (sê Tor circuit yên stream-îzole) bi tev koma bersiva resolverê sîstemê dide ber hev.
- **Loga bi nepenîtî.** Lêvegirtin hijmaran, IPên maskedar û çînên çewtiyan kurt dikin — bê IP xav an nasnavan.
- **Allowlista nivîsandina prefsan** di experiment API de.

**Sînorên xwedînexşe — OnionBird nikare wan rast bike:**

1. **`Authentication-Results: ... smtp.auth=<sindoqê-te>@<pêşkêşkar>`** ji aliyê MTAya pêşkêşkar ve tê zêdekirin — sindoqa piştrastkirî ji her wergir re eşkere dike. *Çareyek bypass:* sindoqek yek-carî / nepênî ji bo nameyên hesas.
2. **IPya derketinê ya Tor di zincîra `Received:` ya wergir de xuya dibe.** MTA reverse-DNS dike û navên mîna `tor-exit-107.digitalcourage.de` çêdike. Wergir dizane ku bi Torê hat şandin.
3. **Lêkçûnên di asta OS de** — eşkerekirina hostname ji sepanên din, NTP, swap, demên dema dosyeyan. Tails an Whonix bi kar bîne.
4. **Korelasyona şebekeyê** — çavdêrê ku her du serê Tor circuit dibîne. Bi paqijiya sernavan nayê serketin.

Her tişta ku ne di van çar koman de ye, di nav **çarçoveya** polîtîkayê de ye. Heke nimûneyek dijber dît, baxa P0 vekin.

---

## Çavdêriya mail-Tor

Ji bo berhevdana tev binêre [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature). Bi kurtî: OnionBird **pêvekek asayî ya Thunderbird e** (ne OSeke cuda mîna Tails/Whonix), bi **veguhastina DNS bi rêya Tor a emperîk piştrastkirî**, **canary domdar** û **FQDN ya configurable ji bo Message-ID** (li şûna supercluster `localhost.localdomain` ya TorBirdy).

---


> ⚠️ **Bi OS-eke ji bo Tor hişk-kirî re bibîne** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## Berî sazkirinê

Pêvek tişta ku **di nav** Thunderbird de dixebite gartav dike. Ji bo veguhastina 100% ya Tor, divê **resolverê OS** jî bi rêya Tor here:

- **Tails / Whonix workstation** — DNSa sîstemê jixwe bi rêya Tor diçe. `.xpi` saz bike û tewş.
- **Linuxa standart bi Tor a sîstemê** — `DNSPort 5353` lê zêde bike li `/etc/tor/torrc` û pê ewle be ku `/etc/resolv.conf` digihîje wê.
- **Tenê Tor Browser bundle** — Tor li ser `9150` guhdarî dike, ne `9050`; pêvek prefên heyî û her du portan dijoise berî nivîsandina prefs.
- **SOCKS Tor/Whonix ji dûr ve** — bikar bîne IP-yek literal (`10.152.152.10:9050`), ne hostname.
- **Desktop standart bê DNSa sîstemê bi rêya Tor** — bi berpirsiyariya xwe saz bike. Canary konfîgurasyonê di rûpela Vebijêrkan û di konsolê de nîşan dide.

---

## Îro çi dike

- IMAP/SMTP bi rêya proxyeke herêmî ya SOCKS5 (default `127.0.0.1:9050`, configurable) bi `socks_remote_dns=true` û `failover_direct=false` dişîne.
- Sernavên kêşekirinê nasnav dike: `User-Agent` / `X-Mailer` tê tepsîkirin, FQDN ya `Message-ID` configurable e (default From-domain), `HELO`/`EHLO` ya SMTP ji nû ve dibe `[127.0.0.1]`, `Date` UTC, bê `format=flowed`.
- Defense-in-depth: TRR=5, OCSP off, bê WebRTC, bê DNS prefetch, bê predictor, bê phone-home, bê telemetry, bê Safebrowsing, bê captive-portal, bê naveroka dûr.
- **Canary ya SOCKS5-RESOLVE li hember DNSa sîstemê** li destpêkê û periyodîk.
- **Tor test mode** li ser rûpela Vebijêrkan.
- Rûpela Vebijêrkan piştgiriyê dide teamên sîstemî/sivik/tarî, UIya pirzimanî û Alîkariya têkçûyî (TL;DR + modê Nerd).
- Di sazkirina yekem de bixweber çalak dibe. **Bişkoja Neçalakkirinê** snapshot vedigerîne.
- Wek standard, tenê serverên SMTP yên **onion + loopback** gartav dibin (B-003) — hesabên clearnet ên heyî wek berê dixebitin.

---

## Mîmar

OnionBird hîbrîd e: skrîpteke background ya MailExtension rûyê API ya giştî pêşkêş dike, û modulek Experiments API di process parent de dixebite û `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, SOCKS5 RESOLVE / RESOLVE_PTR ya xav û manipulasyona `nsIDNSService.clearCache` vedike. Her du beş bi navenavê `browser.onionbird.*` ji hev re têkilî datînin. Binêre [docs/architecture.md](docs/architecture.md).

---

## Roadmap / sînorên zanîn

Binêre [docs/follow-up.md](docs/follow-up.md). Hatine paşxistin: UI toggle ya mixed-mode, hook li ser guherîna girêdana şebekeyê / resolver, multi-circuit PTR retry, tag kirina logînên ku pêvek çêkirine, first-run wizard, bridges / pluggable-transports ji bo ISPên sansurkirî, entegrasyona Tor control-port (NEWNYM bi her şandinê), installerê cross-platform yê pakêtkirî.

---

## Lîsans

MPL-2.0. Ji bo metnê tam: [LICENSE](LICENSE).

Ev nermalav wek tişt e tê pêşkêşkirin, bê tu garantiyê. Nivîskarên berpirsiyar nînin ji nepenîtiyê bişkênin an ji zererên din ên ji bikaranînê tên. Binêre LICENSE.
