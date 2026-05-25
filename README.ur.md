# OnionBird

**زبانیں:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · **اردو** · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **الفا — دیر سے الفا، Tor-DNS سے واقف OS پر leak-tight۔ انسٹال کرنے سے پہلے [پیشگی شرائط](#انسٹال-کرنے-سے-پہلے) پڑھیں۔**

> ناشناسی کے لیے اہم استعمال میں OnionBird پر بھروسہ کرنے سے پہلے [خطرہ ماڈل](docs/threat-model.md) اور [follow-up فہرست](docs/follow-up.md) پڑھیں۔

OnionBird ایک Thunderbird ایڈ-آن ہے جو IMAP/SMTP کو مقامی Tor پراکسی کے ذریعے روٹ کرتا ہے اور بھیجنے والوں کو deanonymize کرنے کے لیے تاریخی طور پر استعمال ہونے والے میسج ہیڈر ہٹاتا یا معیاری بناتا ہے۔ ہدف: Thunderbird 140 ESR۔ غیر برقرار TorBirdy ایکسٹینشن (آخری ریلیز v0.2.6 سن 2018 میں؛ TB 78 میں Legacy XUL کے ہٹائے جانے سے ختم) کے جدید جانشین کے طور پر منصوبہ بند۔

موجودہ ورژن: **0.1.1**۔

---

## 100% رازداری اور سیکیورٹی پالیسی

پراجیکٹ کا حکم بائنری ہے: **کوئی بھی قابل مشاہدہ کوڈ پاتھ جو صارف کی شناخت، حقیقی IP، hostname، locale، ٹائم زون یا اس بات کو لیک کرے کہ صارف اپنی ای میل کو سخت کر رہا ہے، P0 خرابی شمار ہوتا ہے اور ریلیز کو روکتا ہے۔** "کافی اچھا"، "عام طور پر کام کرتا ہے" یا "تقریباً کوئی لیک نہیں" قابل قبول نتائج نہیں۔

ٹھوس طور پر:

- **بنیادی طور پر fail-closed۔** `network.proxy.failover_direct = false` لازمی — اگر ترتیب شدہ Tor پراکسی ناقابل رسائی ہو تو ارسال ناکام ہونا چاہیے۔ ایڈ-آن کبھی بھی خاموشی سے clearnet پر نہیں گرتا۔
- **DNS صرف Tor کے ذریعے۔** `socks_remote_dns = true`, `network.trr.mode = 5` (متوازی DoH نہیں)، `network.dns.disablePrefetch = true`۔ تجرباتی طور پر تصدیق شدہ: حقیقی Tor ارسال کے دوران مقامی resolver تک صفر DNS queries پہنچتی ہیں۔
- **OCSP بند۔** ورنہ ہر TLS handshake پر CA کو ایک clearnet HTTP درخواست بھیجی جاتی۔
- **اپڈیٹ phone-home نہیں۔** ایپ + ایکسٹینشن + GMP-manager کے URLs صاف کر دیے گئے۔
- **کوئی ٹیلی میٹری، Safebrowsing، captive-portal چیک یا remote content رینڈرنگ نہیں۔**
- **کوئی WebRTC، geolocation، DNS prefetch یا predictor نہیں۔**
- **سیشن کے درمیان تحفظ۔** ہر TB اسٹارٹ پر اور سخت کاری کے فعال ہوتے ہوئے وقفے سے prefs دوبارہ تصدیق ہوتی ہیں۔
- **سخت کاری الٹنے کے قابل ہے۔** پہلی فعال کرنے سے پہلے snapshot لیا جاتا ہے؛ Options صفحے کے Disable بٹن یا `disable-hardening` پیغام سے بحال ہوتا ہے۔
- **Self-test canary** آغاز پر اور فعال سخت کاری کے دوران: SOCKS5-RESOLVE (3 stream-isolated Tor circuits) کا سسٹم resolver کے مکمل جواب سیٹ سے موازنہ کرتا ہے۔
- **رازداری-محفوظ تشخیص۔** لاگز شمار، ماسک شدہ IPs اور خرابی کے درجوں کا خلاصہ دیتے ہیں — خام IP یا اکاؤنٹ شناخت کنندہ نہیں۔
- **experiment API میں pref-write allowlist۔**

**موروثی حدود — OnionBird یہ ٹھیک نہیں کر سکتا:**

1. **`Authentication-Results: ... smtp.auth=<آپ-کا-بکس>@<فراہم-کنندہ>`** فراہم کنندہ کا MTA شامل کرتا ہے — تصدیق شدہ بکس وصول کنندے کو ظاہر کرتا ہے۔ *ٹال:* حساس خط و کتابت کے لیے ڈسپوزایبل / pseudonymous بکس استعمال کریں۔
2. **Tor exit IP وصول کنندے کی `Received:` چین میں ظاہر ہوتا ہے۔** MTA reverse-DNS کرتا ہے اور `tor-exit-107.digitalcourage.de` جیسے نام بناتا ہے۔ وصول کنندہ سیکھتا ہے "اس صارف نے Tor کے ذریعے بھیجا"۔
3. **OS سطح کے لیک** — دوسری ایپس سے hostname افشاء، NTP، swap، فائل ٹائم اسٹیمپس۔ Tails یا Whonix استعمال کریں۔
4. **نیٹ ورک کوریلیشن** — Tor circuit کے دونوں سروں کا مشاہدہ کرنے والے۔ ہیڈر صفائی سے شکست نہیں ہوتی۔

ان چار زمروں سے باہر ہر چیز پالیسی کے **دائرہ کار** میں ہے۔ متضاد مثال ملنے پر P0 بگ فائل کریں۔

---

## mail-Tor منظرنامہ

مکمل موازنہ کے لیے دیکھیں [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature)۔ مختصراً: OnionBird ایک **عام Thunderbird ایڈ-آن ہے** (Tails/Whonix کی طرح علیحدہ OS نہیں)، **تجرباتی طور پر تصدیق شدہ DNS-Tor کوریج**، **مسلسل canary** اور **قابل تشکیل Message-ID FQDN** (TorBirdy کے supercluster `localhost.localdomain` کی بجائے) کے ساتھ۔

---


> ⚠️ **Tor کے لیے سخت شدہ OS کے ساتھ اسٹیک کریں** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## انسٹال کرنے سے پہلے

ایڈ-آن Thunderbird کے **اندر** چلنے والی چیز کو سخت کرتا ہے۔ 100% Tor کوریج کے لیے **OS resolver** کو بھی Tor سے گزرنا چاہیے:

- **Tails / Whonix workstation** — سسٹم DNS پہلے ہی Tor ہے۔ `.xpi` انسٹال کریں، ہو گیا۔
- **سسٹم Tor کے ساتھ معیاری Linux** — اپنے `/etc/tor/torrc` میں `DNSPort 5353` شامل کریں اور یقینی بنائیں کہ `/etc/resolv.conf` اس تک پہنچتا ہے۔
- **صرف Tor Browser bundle** — Tor `9150` پر سنتا ہے، `9050` پر نہیں؛ ایڈ-آن proxy prefs لکھنے سے پہلے موجود pref اور دونوں عام پورٹس کی probe کرتا ہے۔
- **دور دراز Tor/Whonix SOCKS** — IP literal (`10.152.152.10:9050`) استعمال کریں، hostname نہیں۔
- **سسٹم DNS Tor کے بغیر معیاری ڈیسک ٹاپ** — اپنی ذمہ داری پر انسٹال کریں۔ canary تشکیل کو Options صفحے اور console میں جھنڈا لگائے گا۔

---

## آج کیا کرتا ہے

- IMAP/SMTP کو مقامی SOCKS5 proxy (پہلے سے طے شدہ `127.0.0.1:9050`، قابل تشکیل) کے ذریعے `socks_remote_dns=true` اور `failover_direct=false` کے ساتھ روٹ کرتا ہے۔
- شناختی ہیڈر معیاری کرتا ہے: `User-Agent` / `X-Mailer` دبائے جاتے ہیں، `Message-ID` کا FQDN قابل تشکیل ہے (پہلے سے طے شدہ آپ کا From-domain)، SMTP `HELO`/`EHLO` `[127.0.0.1]` پر دوبارہ لکھا جاتا ہے، `Date` UTC، `format=flowed` نہیں۔
- Defense-in-depth: TRR=5، OCSP off، WebRTC نہیں، DNS prefetch نہیں، predictor نہیں، phone-home نہیں، ٹیلی میٹری نہیں، Safebrowsing نہیں، captive-portal نہیں، remote content نہیں۔
- **SOCKS5-RESOLVE vs سسٹم DNS canary** آغاز پر اور وقفے سے۔
- Options صفحے پر **Tor test mode**۔
- Options صفحہ سسٹم/روشن/تاریک تھیم، کثیر لسانی UI اور بلٹ-ان Help (TL;DR + Nerd مود) کی حمایت کرتا ہے۔
- پہلی انسٹال پر خود کار طریقے سے فعال ہوتا ہے۔ **Disable بٹن** snapshot بحال کرتا ہے۔
- پہلے سے طے شدہ صرف **onion + loopback** SMTP سرور سخت ہوتے ہیں (B-003) — آپ کے موجودہ clearnet اکاؤنٹ معمول سے کام کرتے رہتے ہیں۔

---

## فن تعمیر

OnionBird ہائبرڈ ہے: MailExtension background script عوامی API سطح فراہم کرتا ہے، اور Experiments API ماڈیول parent process میں چلتا ہے اور `Services.prefs`، `MailServices.outgoingServer`، `MailServices.accounts`، خام SOCKS5 RESOLVE / RESOLVE_PTR اور `nsIDNSService.clearCache` ہیر پھیر کو ظاہر کرتا ہے۔ دونوں نصف `browser.onionbird.*` namespace کے ذریعے بات چیت کرتے ہیں۔ دیکھیں [docs/architecture.md](docs/architecture.md)۔

---

## روڈ میپ / معروف حدود

دیکھیں [docs/follow-up.md](docs/follow-up.md)۔ مؤخر: mixed-mode UI toggle، نیٹ ورک لنک / resolver تبدیلی hook، multi-circuit PTR retry، ایڈ-آن سے بنائے گئے logins کی ٹیگنگ، first-run wizard، سنسر شدہ ISPs کے لیے bridges / pluggable-transports، Tor control-port انضمام (NEWNYM فی ارسال)، پیک شدہ cross-platform installer۔

---

## لائسنس

MPL-2.0۔ مکمل متن کے لیے [LICENSE](LICENSE) دیکھیں۔

سافٹ ویئر جوں کا توں فراہم کیا جاتا ہے، بغیر کسی قسم کی ضمانت۔ مصنفین استعمال سے پیدا ہونے والی deanonymization یا کسی دوسرے نقصان کے ذمہ دار نہیں۔ مکمل دستبرداری کے لیے LICENSE دیکھیں۔
