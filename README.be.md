# OnionBird

**Мовы:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · **Беларуская** · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **АЛЬФА — позняя альфа, без уцечак на сістэмах з DNS праз Tor. Прачытайце [перадумовы](#перад-усталяваннем) перад усталяваннем.**

> Прачытайце [мадэль пагроз](docs/threat-model.md) і [спіс follow-up](docs/follow-up.md), перш чым давяраць OnionBird у крытычных для ананімнасці задачах.

OnionBird — гэта дадатак для Thunderbird, які маршрутызуе IMAP/SMTP праз лакальны Tor-проксі і выдаляе або нармалізуе загалоўкі паведамленняў, гістарычна выкарыстаныя для дэананімізацыі адпраўнікаў. Мэта: Thunderbird 140 ESR. Задуманы як сучасны пераемнік непадтрымванага TorBirdy (апошні рэліз v0.2.6 у 2018, спыніўся праз выдаленне Legacy XUL у TB 78).

Бягучая версія: **0.1.1**.

---

## Палітыка 100% прыватнасці і бяспекі

Мандат праекта бінарны: **любая назіральная галіна кода, якая выцякае асобу карыстальніка, рэальны IP, hostname, locale, часавы пояс або сам факт гартавання пошты, лічыцца дэфектам P0 і блакіруе рэліз.** «Дастаткова добра», «звычайна працуе» або «амаль без уцечкі» — недапушчальныя вынікі.

Канкрэтна:

- **Fail closed па змаўчанні.** `network.proxy.failover_direct = false` прымусова — калі настроены Tor-проксі недасяжны, адпраўка падае. Дадатак НІКОЛІ не падае ціха ў clearnet.
- **DNS толькі праз Tor.** `socks_remote_dns = true`, `network.trr.mode = 5` (без паралельнага DoH), `network.dns.disablePrefetch = true`.
- **OCSP выключана.** Інакш праверкі адклікання рабілі б clearnet-HTTP-запыт да CA пры кожным TLS-handshake.
- **Без phone-home абнаўленняў.** URL-ы прыкладання + пашырэнняў + GMP-manager ачышчаны.
- **Без тэлеметрыі, Safebrowsing, captive-portal, выдаленага кантэнту.**
- **Без WebRTC, геалакацыі, DNS prefetch, predictor.**
- **Абарона ў сярэдзіне сесіі.** Prefs паўторна сцвярджаюцца пры кожным запуску TB і перыядычна, пакуль гартаванне актыўна.
- **Гартаванне адваротнае.** Здымак узяты да першай актывацыі, аднаўляецца кнопкай Адключыць або паведамленнем `disable-hardening`.
- **Self-test канарэйка** пры старце і падчас актыўнага гартавання: параўноўвае SOCKS5-RESOLVE (3 stream-ізаляваныя Tor circuit) з поўным наборам адказаў сістэмнага рэзалвера.
- **Прыватна-бяспечнае дыягнаставанне.** Логі сумуюць лічыльнікі, маскіраваныя IP і класы памылак.
- **Allowlist запісаў prefs** у API experiment.

**Непераадольныя межы — OnionBird НЕ МОЖА выправіць:**

1. **`Authentication-Results: ... smtp.auth=<ваш-скрыня>@<правайдар>`** дадаецца MTA правайдара — раскрывае атрымальніку аўтэнтыфікаваную скрыню. *Абыход:* аднаразовая / псеўданімная скрыня для сензітыўнай перапіскі.
2. **IP выхаду Tor з’яўляецца ў ланцугу `Received:` атрымальніка.** MTA робіць reverse-DNS і стварае імёны накшталт `tor-exit-107.digitalcourage.de`. Атрымальнік даведваецца, што адпраўлена праз Tor.
3. **Уцечкі на ўзроўні АС** — hostname ад іншых праграм, NTP, swap, метачкі часу файлаў. Карыстайцеся Tails або Whonix.
4. **Сеткавая карэляцыя** — назіральнік абодвух канцоў Tor circuit. Не пераадольваецца гігіенай загалоўкаў.

Усё, што не ўпадае ў гэтыя чатыры катэгорыі, **у межах** палітыкі. Пададзіце баг P0 на контрпрыклад.

---

## Ландшафт mail-Tor

Поўнае параўнанне гл. у [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature). Сцісла: OnionBird — **звычайны дадатак Thunderbird** (не асобная АС як Tails/Whonix), з **эмпірычна правераным пакрыццём DNS праз Tor**, **пастаяннай канарэйкай** і **наладжвальным FQDN Message-ID** (замест supercluster `localhost.localdomain` з TorBirdy).

---


> ⚠️ **Стэкуйце з Tor-узмоцненай АС** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## Перад усталяваннем

Дадатак гартуе тое, што працуе **унутры** Thunderbird. Для 100% Tor-пакрыцця **рэзалвер АС** таксама павінен ісці праз Tor:

- **Tails / Whonix workstation** — DNS сістэмы ўжо праз Tor. Усталюйце `.xpi` — гатова.
- **Звычайны Linux з сістэмным Tor** — дадайце `DNSPort 5353` у `/etc/tor/torrc` і пераканайцеся, што `/etc/resolv.conf` дасягае яго.
- **Толькі Tor Browser bundle** — Tor слухае на `9150`, не `9050`; дадатак зандуе існуючыя prefs і абодва парты перад запісам.
- **Аддалены SOCKS Tor/Whonix** — карыстайцеся IP-літэралам (`10.152.152.10:9050`), а не hostname.
- **Звычайны desktop без сістэмнага DNS праз Tor** — усталёўвайце на свой страх. Канарэйка пазначыць канфігурацыю ў Параметрах і ў кансолі.

---

## Што робіць сёння

- Маршрутызуе IMAP/SMTP праз лакальны SOCKS5-проксі (па змаўчанні `127.0.0.1:9050`, наладжвальна) з `socks_remote_dns=true` і `failover_direct=false`.
- Нармалізуе ідэнтыфікуючыя загалоўкі: `User-Agent` / `X-Mailer` прыдушаны, FQDN `Message-ID` наладжваецца (стандартна — ваш From-domain), SMTP `HELO`/`EHLO` перапісаны на `[127.0.0.1]`, `Date` UTC, без `format=flowed`.
- Defense-in-depth: TRR=5, OCSP off, без WebRTC, без DNS prefetch, без predictor, без phone-home, без тэлеметрыі, без Safebrowsing, без captive-portal, без выдаленага кантэнту.
- **Канарэйка SOCKS5-RESOLVE vs DNS сістэмы** пры старце і перыядычна.
- **Tor test mode** на старонцы Параметры.
- Старонка Параметры падтрымлівае тэму сістэмная/светлая/цёмная, шматмоўны UI і ўбудаваную Даведку (TL;DR + nerd-рэжым).
- Аўта-актывуецца пры першай інсталяцыі. **Кнопка Адключыць** аднаўляе здымак.
- Па змаўчанні гартуюцца толькі SMTP-серверы **onion + loopback** (B-003) — наяўныя clearnet-уліковыя запісы працуюць як раней.

---

## Архітэктура

OnionBird — гібрыд: фонавы скрыпт MailExtension дае публічную паверхню API, а модуль Experiments API працуе ў parent-працэсе і адкрывае `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, сырыя SOCKS5 RESOLVE / RESOLVE_PTR і маніпуляцыі з `nsIDNSService.clearCache`. Гл. [docs/architecture.md](docs/architecture.md).

---

## Roadmap / вядомыя абмежаванні

Гл. [docs/follow-up.md](docs/follow-up.md). Адкладзена: UI-тогл mixed-mode, гук на змену сеткавай спасылкі / рэзалвера, multi-circuit PTR retry, тэгаванне ўваходаў створаных дадаткам, first-run wizard, bridges / pluggable-transports для цэнзураваных ISP, інтэграцыя Tor control-port, пакетны cross-platform installer.

---

## Ліцэнзія

MPL-2.0. Гл. [LICENSE](LICENSE).

ПЗ пастаўляецца ЯК ЁСЦЬ, без аніякіх гарантый. Аўтары не нясуць адказнасці за дэананімізацыю або іншыя страты ад выкарыстання. Гл. LICENSE.
