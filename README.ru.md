# OnionBird

**Языки:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · **Русский** · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **АЛЬФА — поздняя альфа, без утечек на ОС с DNS через Tor. Прочитайте [предусловия](#перед-установкой) перед установкой.**

> Прочитайте [модель угроз](docs/threat-model.md) и [список follow-up](docs/follow-up.md), прежде чем доверять OnionBird критичным для анонимности задачам.

OnionBird — расширение Thunderbird, которое маршрутизирует IMAP/SMTP через локальный Tor-прокси и удаляет или нормализует заголовки сообщения, исторически использовавшиеся для деанонимизации отправителей. Цель: Thunderbird 140 ESR. Задумано как современный преемник неподдерживаемого TorBirdy (последний релиз v0.2.6 в 2018, погиб от удаления Legacy XUL в TB 78).

Текущая версия: **0.1.4**.

---

## Политика 100% приватности и безопасности

Мандат проекта бинарный: **любая наблюдаемая ветка кода, которая утечёт личность пользователя, реальный IP, hostname, локаль, часовой пояс или сам факт укрепления почты, считается дефектом P0 и блокирует релиз.** «Достаточно хорошо», «обычно работает» или «почти без утечки» — недопустимые исходы.

Конкретно:

- **Fail closed по умолчанию.** `network.proxy.failover_direct = false` принудительно — если настроенный Tor-прокси недостижим, отправка падает. Расширение НИКОГДА не падает молча в clearnet.
- **DNS только через Tor.** `socks_remote_dns = true`, `network.trr.mode = 5` (без параллельного DoH), `network.dns.disablePrefetch = true`. Эмпирически проверено: ноль DNS-запросов достигает локального резолвера во время реальной отправки через Tor.
- **OCSP отключён.** Иначе проверки отзыва генерировали бы clearnet-HTTP-запрос к CA при каждом TLS-handshake.
- **Без phone-home апдейтов.** URL-ы приложения + расширений + GMP-manager очищены.
- **Без телеметрии, Safebrowsing, captive-portal, удалённого контента.**
- **Без WebRTC, геолокации, DNS prefetch, predictor.**
- **Защита в середине сессии.** Prefs повторно утверждаются при каждом запуске TB и периодически, пока укрепление активно.
- **Укрепление обратимо.** Снимок снят до первой активации, восстанавливается кнопкой Отключить или сообщением `disable-hardening`.
- **Self-test канарейка** при старте и во время активного укрепления: сравнивает SOCKS5-RESOLVE (3 stream-изолированных Tor circuit) с полным ответом системного резолвера.
- **Приватность-безопасное диагностирование.** Логи и сообщения консоли суммируют счётчики, маскированные IP и классы ошибок — без сырых IP или идентификаторов аккаунта.
- **Allowlist записей prefs** в API experiment.

**Неустранимые границы — OnionBird НЕ МОЖЕТ исправить:**

1. **`Authentication-Results: ... smtp.auth=<ваш-ящик>@<провайдер>`** добавляется MTA провайдера — раскрывает получателю аутентифицированный ящик. Свойство аутентифицированного SMTP. *Обходной путь:* одноразовый / псевдонимный ящик для чувствительной переписки.
2. **IP выхода Tor появляется в цепочке `Received:` у получателя.** MTA делает reverse-DNS и создаёт имена вроде `tor-exit-107.digitalcourage.de`. Получатель узнаёт «этот пользователь отправил через Tor».
3. **Утечки на уровне ОС** — hostname от других приложений, NTP, swap, метки времени файлов. Используйте Tails или Whonix.
4. **Сетевая корреляция** — наблюдатель обоих концов Tor circuit. Не побеждается гигиеной заголовков.

Всё, что не попадает в эти четыре категории, **входит в область** политики. Подавайте баг P0 на контрпример.

---

## Ландшафт mail-Tor

Полное сравнение см. в [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature). Кратко: OnionBird — **обычное расширение Thunderbird** (не отдельная ОС как Tails/Whonix), с **эмпирически проверенным покрытием DNS через Tor**, **постоянной канарейкой** и **настраиваемым FQDN Message-ID** (вместо supercluster `localhost.localdomain` из TorBirdy).

---


> ⚠️ **Стэк с ОС, усиленной под Tor** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## Перед установкой

Расширение укрепляет то, что работает **внутри** Thunderbird. Для 100% Tor-покрытия **резолвер ОС** тоже должен идти через Tor:

- **Tails / Whonix workstation** — DNS системы уже через Tor. Установите `.xpi` — готово.
- **Обычный Linux с системным Tor** — добавьте `DNSPort 5353` в `/etc/tor/torrc` и убедитесь, что `/etc/resolv.conf` его достигает (локальный `dnsmasq`/`unbound`, перенаправляющий на `127.0.0.1:5353`).
- **Только Tor Browser bundle** — Tor слушает на `9150`, не `9050`; расширение зондирует существующие prefs и оба распространённых порта перед записью прокси-prefs.
- **Удалённый SOCKS Tor/Whonix** — используйте IP-литерал (`10.152.152.10:9050`), а не hostname.
- **Обычный desktop без системного DNS через Tor** — устанавливайте на свой риск. Канарейка отметит конфигурацию в Опциях и в консоли.

---

## Что делает сегодня

- Маршрутизирует IMAP/SMTP через локальный SOCKS5-прокси (по умолчанию `127.0.0.1:9050`, настраивается) с `socks_remote_dns=true` и `failover_direct=false`.
- Нормализует идентифицирующие заголовки: `User-Agent` / `X-Mailer` подавлены, FQDN `Message-ID` настраивается (по умолчанию ваш From-domain), SMTP `HELO`/`EHLO` переписан на `[127.0.0.1]`, `Date` UTC, без `format=flowed`.
- Defense-in-depth: TRR=5, OCSP off, без WebRTC, без DNS prefetch, без predictor, без phone-home, без телеметрии, без Safebrowsing, без captive-portal, без удалённого контента.
- **Канарейка SOCKS5-RESOLVE vs DNS системы** при старте и периодически.
- **Tor test mode** на странице Опций.
- Страница Опций поддерживает тему система/светлая/тёмная, многоязычный UI и встроенную Справку (TL;DR + nerd-режим).
- Авто-активируется при первой установке. **Кнопка Отключить** восстанавливает снимок.
- По умолчанию укрепляются только SMTP-серверы **onion + loopback** (B-003) — существующие clearnet-аккаунты продолжают работать.
- `user.js` для pre-startup укрепления + скрипт, перечисляющий существующие аккаунты в `prefs.js`.

---

## Быстрый старт

```sh
# Build .xpi (MV2, канонический)
make build

# Опционально: параллельный MV3
make build-mv3

# Поднять тестовый pod (Tor+DNSPort + aiosmtpd + DNS-forwarder + Xvfb+TB + runner)
make COMPOSE_ENGINE=docker test-up

# Запустить интеграционную suite (148 теста в 0.1.4)
make COMPOSE_ENGINE=docker test-integration

# Свернуть
make COMPOSE_ENGINE=docker test-down
```

### Подпись для ATN

См. [docs/atn-signing.md](docs/atn-signing.md) — требует учётных данных Mozilla developer.

---

## Архитектура

OnionBird — гибрид: фоновый скрипт MailExtension обеспечивает публичную поверхность API (страница опций, авто-активация при установке, шина сообщений enable/disable, периодический self-test), а модуль Experiments API работает в parent-процессе и открывает `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, сырые SOCKS5 RESOLVE / RESOLVE_PTR и манипуляции с `nsIDNSService.clearCache`. Половины общаются через namespace `browser.onionbird.*`.

См. [docs/architecture.md](docs/architecture.md).

---

## Roadmap / известные ограничения

См. [docs/follow-up.md](docs/follow-up.md). Отложено: UI-тоглер mixed-mode, hook на смену сетевой ссылки / резолвера, multi-circuit PTR retry, тегирование логинов созданных расширением, first-run wizard, bridges / pluggable-transports для цензурированных ISP, интеграция Tor control-port (NEWNYM на отправку), упакованный cross-platform installer.

---

## Лицензия

MPL-2.0. См. [LICENSE](LICENSE) для полного текста.

ПО предоставляется КАК ЕСТЬ, без каких-либо гарантий. Авторы не несут ответственности за деанонимизацию или иной вред от использования. См. LICENSE.
