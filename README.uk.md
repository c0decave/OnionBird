# OnionBird

**Мови:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · **Українська** · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **АЛЬФА — пізня альфа, без витоків на системах із DNS через Tor. Прочитайте [передумови](#перед-встановленням) перед установкою.**

> Прочитайте [модель загроз](docs/threat-model.md) і [список follow-up](docs/follow-up.md), перш ніж покладатися на OnionBird у критичних для анонімності задачах.

OnionBird — це додаток для Thunderbird, який маршрутизує IMAP/SMTP через локальний Tor-проксі та видаляє чи нормалізує заголовки повідомлень, історично використовувані для деанонімізації відправників. Ціль: Thunderbird 140 ESR. Задуманий як сучасний наступник непідтримуваного TorBirdy (останній випуск v0.2.6 у 2018, припинено через видалення Legacy XUL у TB 78).

Поточна версія: **0.1.4**.

---

## Політика 100% приватності й безпеки

Мандат проєкту бінарний: **будь-який спостережний шлях коду, який витікає особистість користувача, реальний IP, hostname, locale, часовий пояс або сам факт гартування пошти, вважається дефектом P0 і блокує реліз.** «Достатньо добре», «зазвичай працює» чи «майже без витоку» — неприйнятні результати.

Конкретно:

- **Fail closed за замовчуванням.** `network.proxy.failover_direct = false` примусово — якщо налаштований Tor-проксі недосяжний, надсилання помиляється. Додаток НІКОЛИ не падає мовчки в clearnet.
- **DNS лише через Tor.** `socks_remote_dns = true`, `network.trr.mode = 5` (без паралельного DoH), `network.dns.disablePrefetch = true`. Емпірично перевірено: нуль DNS-запитів доходить до локального резолвера під час реального Tor-надсилання.
- **OCSP вимкнено.** Інакше перевірки відкликання робили б clearnet HTTP-запит до CA при кожному TLS-handshake.
- **Без phone-home для оновлень.** URL застосунку + розширень + GMP-manager очищені.
- **Без телеметрії, Safebrowsing, captive-portal, віддаленого контенту.**
- **Без WebRTC, геолокації, DNS prefetch, predictor.**
- **Захист посеред сесії.** Prefs повторно стверджуються при кожному запуску TB і періодично, поки гартування активне.
- **Гартування зворотне.** Знімок зроблено до першої активації, відновлюється кнопкою Вимкнути або повідомленням `disable-hardening`.
- **Self-test канарка** при старті та під час активного гартування: порівнює SOCKS5-RESOLVE (3 stream-ізольовані Tor circuit) з повним набором відповіді системного резолвера.
- **Безпечне для приватності діагностування.** Лог-повідомлення підсумовують лічильники, замасковані IP та класи помилок — без сирих IP чи ідентифікаторів облікових записів.
- **Allowlist записів prefs** в API experiment.

**Невід’ємні межі — OnionBird НЕ МОЖЕ виправити:**

1. **`Authentication-Results: ... smtp.auth=<ваша-скринька>@<провайдер>`** додається MTA провайдера — розкриває кожному отримувачу аутентифіковану скриньку. Невід’ємна частина SMTP-AUTH. *Обхід:* одноразова / псевдонімна скринька для чутливого листування.
2. **IP виходу Tor з’являється в ланцюгу `Received:` отримувача.** MTA робить reverse-DNS і створює імена на кшталт `tor-exit-107.digitalcourage.de`. Отримувач дізнається «цей користувач надіслав через Tor».
3. **Витоки на рівні ОС** — hostname від інших застосунків, NTP, swap, мітки часу файлів. Використовуйте Tails або Whonix.
4. **Мережева кореляція** — спостерігач обох кінців Tor circuit. Не долається гігієною заголовків.

Усе поза цими чотирма категоріями — **у межах** політики. Подайте баг P0 на контрприклад.

---

## Ландшафт mail-Tor

Повне порівняння див. [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature). Стисло: OnionBird — **звичайний додаток Thunderbird** (не окрема ОС як Tails/Whonix), з **емпірично перевіреним покриттям DNS через Tor**, **постійною канаркою** та **налаштовуваним FQDN Message-ID** (замість supercluster `localhost.localdomain` з TorBirdy).

---


> ⚠️ **Стек з Tor-зміцненою ОС** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## Перед встановленням

Додаток гартує те, що працює **всередині** Thunderbird. Для 100% покриття Tor **резолвер ОС** теж має йти через Tor:

- **Tails / Whonix workstation** — DNS системи вже через Tor. Встановіть `.xpi` і все.
- **Звичайний Linux із системним Tor** — додайте `DNSPort 5353` у `/etc/tor/torrc` і переконайтеся, що `/etc/resolv.conf` досягає його (локальний `dnsmasq`/`unbound`, що переадресує на `127.0.0.1:5353`).
- **Лише Tor Browser bundle** — Tor слухає на `9150`, не `9050`; додаток зондує існуючі prefs та обидва порти перед записом prefs proxy.
- **Віддалений SOCKS Tor/Whonix** — використовуйте IP-літерал (`10.152.152.10:9050`), а не hostname.
- **Звичайний desktop без системного DNS через Tor** — встановлюйте на свій ризик. Канарка позначить конфігурацію в Опціях та консолі.

---

## Що робить сьогодні

- Маршрутизує IMAP/SMTP через локальний SOCKS5-проксі (за замовчуванням `127.0.0.1:9050`, налаштовуваний) з `socks_remote_dns=true` і `failover_direct=false`.
- Нормалізує ідентифікуючі заголовки: `User-Agent` / `X-Mailer` придушені, FQDN `Message-ID` налаштовується (стандартно — ваш From-domain), SMTP `HELO`/`EHLO` переписано на `[127.0.0.1]`, `Date` UTC, без `format=flowed`.
- Defense-in-depth: TRR=5, OCSP off, без WebRTC, без DNS prefetch, без predictor, без phone-home, без телеметрії, без Safebrowsing, без captive-portal, без віддаленого контенту.
- **Канарка SOCKS5-RESOLVE vs DNS системи** при старті та періодично.
- **Tor test mode** на сторінці Опцій.
- Сторінка Опцій підтримує тему системну/світлу/темну, багатомовний UI та вбудовану Довідку (TL;DR + nerd-режим).
- Автоматично активується при першій інсталяції. **Кнопка Вимкнути** відновлює знімок.
- За замовчуванням гартуються лише SMTP-сервери **onion + loopback** (B-003) — наявні clearnet-облікові записи працюють як раніше.
- `user.js` для pre-startup гартування + скрипт, що енумерує існуючі облікові записи з `prefs.js`.

---

## Швидкий старт

```sh
# Build .xpi (MV2, канонічний)
make build

# Опціонально: паралельний MV3
make build-mv3

# Підняти test pod (Tor+DNSPort + aiosmtpd + DNS-forwarder + Xvfb+TB + runner)
make COMPOSE_ENGINE=docker test-up

# Запустити інтеграційну suite (148 тести у 0.1.4)
make COMPOSE_ENGINE=docker test-integration

# Згорнути
make COMPOSE_ENGINE=docker test-down
```

### Підписання для ATN

Див. [docs/atn-signing.md](docs/atn-signing.md) — потребує облікових даних Mozilla developer.

---

## Архітектура

OnionBird — гібрид: фоновий скрипт MailExtension дає публічну поверхню API (сторінка опцій, авто-активація при встановленні, шина повідомлень enable/disable, періодичний self-test), а модуль Experiments API працює в parent-процесі та відкриває `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, сирі SOCKS5 RESOLVE / RESOLVE_PTR і маніпуляції з `nsIDNSService.clearCache`. Дві половини спілкуються через простір імен `browser.onionbird.*`.

Див. [docs/architecture.md](docs/architecture.md).

---

## Roadmap / відомі обмеження

Див. [docs/follow-up.md](docs/follow-up.md). Відкладено: UI-тоглер mixed-mode, гук на зміну мережевого лінку / резолвера, multi-circuit PTR retry, тегування логінів, створених додатком, first-run wizard, bridges / pluggable-transports для цензурованих ISP, інтеграція з Tor control-port (NEWNYM на надсилання), пакетний cross-platform installer.

---

## Ліцензія

MPL-2.0. Див. [LICENSE](LICENSE) для повного тексту.

ПЗ постачається ЯК Є, без жодних гарантій. Автори не несуть відповідальності за деанонімізацію чи інші збитки внаслідок використання. Див. LICENSE.
