# OnionBird

**زبان‌ها:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · **فارسی** · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **ALPHA — آلفای دیر، بدون نشت بر OS هایی که DNS را از Tor عبور می‌دهند. پیش از نصب، [پیش‌نیازها](#پیش-از-نصب) را بخوانید.**

> پیش از اعتماد به OnionBird برای کاربردهای حساس به ناشناسی، [مدل تهدید](docs/threat-model.md) و [فهرست follow-up](docs/follow-up.md) را بخوانید.

OnionBird افزونه‌ای برای Thunderbird است که IMAP/SMTP را از طریق یک پروکسی محلی Tor عبور می‌دهد و هدرهای پیام را که تاریخاً برای از بین بردن ناشناسی فرستندگان استفاده می‌شدند حذف یا نرمال می‌کند. هدف: Thunderbird 140 ESR. به‌عنوان جانشین مدرنِ افزونه‌ی نگهداری‌نشده‌ی TorBirdy (آخرین نسخه v0.2.6 در ۲۰۱۸، با حذف Legacy XUL در TB 78 از کار افتاد) طراحی شده.

نسخه‌ی فعلی: **0.1.1**.

---

## سیاست ۱۰۰٪ حریم خصوصی و امنیت

ماموریت پروژه دودویی است: **هر مسیر کد قابل مشاهده‌ای که هویت کاربر، IP واقعی، hostname، locale، منطقه‌ی زمانی یا حتی این واقعیت را که کاربر در حال سخت‌سازی پست است افشا کند، نقص P0 محسوب می‌شود و انتشار را مسدود می‌کند.** «به اندازه‌ی کافی خوب» یا «معمولاً کار می‌کند» نتایج قابل قبول نیستند.

به‌طور مشخص:

- **Fail-closed به‌صورت پیش‌فرض.** `network.proxy.failover_direct = false` اجباری است — اگر پروکسی Tor در دسترس نباشد، ارسال باید خطا بدهد. افزونه هرگز بی‌صدا به clearnet نمی‌افتد.
- **DNS فقط از طریق Tor.** `socks_remote_dns = true`, `network.trr.mode = 5` (بدون DoH موازی)، `network.dns.disablePrefetch = true`. تجربه‌گرایانه تایید شده: صفر کوئری DNS در ارسال واقعی Tor به resolver محلی می‌رسد.
- **OCSP خاموش.** در غیر این صورت بررسی‌های لغو، در هر TLS handshake یک درخواست HTTP clearnet به CA می‌فرستند.
- **بدون phone-home بروزرسانی.** URLهای برنامه + افزونه‌ها + GMP-manager پاک شده‌اند.
- **بدون تله‌متری، Safebrowsing، captive-portal، رندر محتوای راه دور.**
- **بدون WebRTC، geolocation، DNS prefetch، predictor.**
- **حفاظت در میانه‌ی نشست.** Prefs در هر بار راه‌اندازی TB و به‌صورت دوره‌ای در زمان فعال بودن سخت‌سازی، تأیید مجدد می‌شوند.
- **سخت‌سازی برگشت‌پذیر است.** نمای فوری پیش از فعال‌سازی اول، با دکمه‌ی غیرفعال‌سازی در صفحه‌ی گزینه‌ها یا پیام `disable-hardening` بازگردانده می‌شود.
- **canary خودآزمون** هنگام راه‌اندازی و در طول سخت‌سازی فعال: SOCKS5-RESOLVE (سه circuit جداسازی‌شده‌ی Tor) را با پاسخ کامل resolver سیستم مقایسه می‌کند.
- **ثبت لاگ حافظ حریم خصوصی.** گزارش‌ها شمارش‌ها، IPهای ماسک‌شده و کلاس خطا را خلاصه می‌کنند — بدون IP خام یا شناسه‌ی حساب.
- **Allowlist نوشتن prefs** در experiment API.

**محدودیت‌های ذاتی — OnionBird نمی‌تواند این‌ها را رفع کند:**

1. **`Authentication-Results: ... smtp.auth=<صندوق-شما>@<ارائه‌دهنده>`** را MTA ارائه‌دهنده می‌افزاید — صندوق احراز هویت‌شده را به گیرنده افشا می‌کند. *دور زدن:* صندوق یک‌بار مصرف / مستعار برای مکاتبات حساس.
2. **IP خروجی Tor در زنجیره‌ی `Received:` گیرنده ظاهر می‌شود.** MTA reverse-DNS انجام می‌دهد و نام‌هایی مانند `tor-exit-107.digitalcourage.de` تولید می‌کند. گیرنده می‌فهمد که از طریق Tor ارسال شده.
3. **نشت‌های سطح OS** — افشای hostname از سایر برنامه‌ها، NTP، swap، timestamp فایل‌ها. از Tails یا Whonix استفاده کنید.
4. **همبستگی شبکه** — ناظری که دو سر circuit Tor را می‌بیند. بهداشت هدرها این را شکست نمی‌دهد.

هر چه در این چهار دسته نیست، **در حوزه‌ی** سیاست قرار دارد. اگر مثال نقضی یافتید، باگ P0 ثبت کنید.

---

## چشم‌انداز mail-Tor

مقایسه‌ی کامل را در [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature) ببینید. به‌اختصار: OnionBird یک **افزونه‌ی متعارف Thunderbird** است (نه یک OS جداگانه مانند Tails/Whonix)، با **پوشش DNS از Tor به‌صورت تجربی تأیید شده**، **canary پیوسته** و **FQDN قابل پیکربندی برای Message-ID** (به‌جای supercluster `localhost.localdomain` در TorBirdy).

---


> ⚠️ **ترکیب با OS سخت‌شده برای Tor** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## پیش از نصب

افزونه چیزی را که **داخل** Thunderbird اجرا می‌شود سخت می‌کند. برای پوشش ۱۰۰٪ Tor، **resolver OS** نیز باید از Tor عبور کند:

- **Tails / Whonix workstation** — DNS سیستم همین حالا روی Tor است. `.xpi` را نصب کنید، تمام.
- **لینوکس استاندارد با Tor سیستمی** — `DNSPort 5353` را به `/etc/tor/torrc` بیفزایید و مطمئن شوید `/etc/resolv.conf` به آن می‌رسد.
- **فقط Tor Browser bundle** — Tor به جای `9050` روی `9150` گوش می‌دهد؛ افزونه پیش از نوشتن prefs پروکسی، prefs موجود و هر دو پورت رایج محلی را probe می‌کند.
- **SOCKS Tor/Whonix راه‌دور** — به‌جای hostname از IP لفظی (`10.152.152.10:9050`) استفاده کنید.
- **دسکتاپ استاندارد بدون DNS سیستمی از Tor** — به مسئولیت خود نصب کنید. canary پیکربندی را در صفحه‌ی گزینه‌ها و کنسول علامت می‌زند.

---

## امروز چه می‌کند

- IMAP/SMTP را از یک پروکسی محلی SOCKS5 (پیش‌فرض `127.0.0.1:9050`، قابل پیکربندی) با `socks_remote_dns=true` و `failover_direct=false` عبور می‌دهد.
- هدرهای شناسایی‌کننده را نرمال می‌کند: `User-Agent` / `X-Mailer` سرکوب می‌شوند، FQDN `Message-ID` قابل پیکربندی است (پیش‌فرض دامنه‌ی From شما)، `HELO`/`EHLO` SMTP به `[127.0.0.1]` بازنویسی می‌شود، `Date` UTC، بدون `format=flowed`.
- Defense-in-depth: TRR=5، OCSP خاموش، بدون WebRTC، بدون DNS prefetch، بدون predictor، بدون phone-home، بدون تله‌متری، بدون Safebrowsing، بدون captive-portal، بدون محتوای راه دور.
- **canary SOCKS5-RESOLVE در برابر DNS سیستم** در راه‌اندازی و دوره‌ای.
- **حالت تست Tor** در صفحه‌ی گزینه‌ها.
- صفحه‌ی گزینه‌ها از تم سیستمی/روشن/تیره، UI چندزبانه و راهنمای داخلی (TL;DR + حالت Nerd) پشتیبانی می‌کند.
- در نصب اول خودکار فعال می‌شود. **دکمه‌ی غیرفعال‌سازی** نمای فوری را بازمی‌گرداند.
- به‌طور پیش‌فرض فقط سرورهای SMTP **onion + loopback** سخت می‌شوند (B-003) — حساب‌های clearnet موجودتان عادی کار می‌کنند.

---

## معماری

OnionBird هیبریدی است: یک اسکریپت پس‌زمینه‌ی MailExtension سطح API عمومی را فراهم می‌کند، و یک ماژول Experiments API در فرایند parent اجرا می‌شود و `Services.prefs`، `MailServices.outgoingServer`، `MailServices.accounts`، SOCKS5 RESOLVE / RESOLVE_PTR خام و دستکاری `nsIDNSService.clearCache` را در دسترس می‌گذارد. دو نیمه از طریق namespace سفارشی `browser.onionbird.*` ارتباط می‌گیرند. ببینید [docs/architecture.md](docs/architecture.md).

---

## نقشه‌ی راه / محدودیت‌های شناخته‌شده

ببینید [docs/follow-up.md](docs/follow-up.md). به تکرارهای بعدی موکول شده: UI mixed-mode toggle، hook روی تغییر لینک شبکه / resolver، multi-circuit PTR retry، تگ‌گذاری لاگین‌های ساخت افزونه، first-run wizard، bridges / pluggable-transports برای ISP سانسورشده، یکپارچگی Tor control-port (NEWNYM به ازای ارسال)، نصب‌کننده‌ی بسته‌بندی‌شده‌ی cross-platform.

---

## مجوز

MPL-2.0. برای متن کامل به [LICENSE](LICENSE).

این نرم‌افزار همان‌گونه که هست عرضه می‌شود، بدون هیچ ضمانت. نویسندگان مسئول از بین رفتن ناشناسی یا آسیب‌های دیگر ناشی از استفاده نیستند. به LICENSE مراجعه کنید.
