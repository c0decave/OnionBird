# OnionBird

**اللغات:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · **العربية** · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **ألفا — ألفا متأخّرة، محكمة على نظام تشغيل يمرّر DNS عبر Tor. اقرأ [المتطلبات](#قبل-التثبيت) قبل التثبيت.**

> اقرأ [نموذج التهديد](docs/threat-model.md) و[قائمة follow-up](docs/follow-up.md) قبل الثقة بـ OnionBird في الاستخدام الحرج للهوية المجهولة.

OnionBird إضافة لـ Thunderbird تُمرِّر IMAP/SMTP عبر بروكسي Tor محلي وتُجرِّد أو تُطبِّع رؤوس الرسائل المستخدَمة تاريخيًا في كشف هوية المرسلين. الهدف: Thunderbird 140 ESR. مصمَّمة لتكون الخَلَف الحديث لإضافة TorBirdy غير المُعتنى بها (آخر إصدار v0.2.6 في 2018، توقف العمل بعد إزالة Legacy XUL في TB 78).

النسخة الحالية: **0.1.4**.

---

## سياسة خصوصية وأمان ١٠٠٪

تفويض المشروع ثنائي: **أيّ مسار كود قابل للملاحظة يُسرِّب هوية المستخدِم، أو IP الحقيقي، أو hostname، أو locale، أو المنطقة الزمنية، أو حتى حقيقة أنّ المستخدِم يُصلِّب بريده، يُعدّ خطأ من فئة P0 ويمنع الإصدار.** «كافٍ» أو «يعمل في الغالب» أو «بلا تسريب تقريبًا» نتائج غير مقبولة.

فعليًا:

- **Fail-closed افتراضًا.** `network.proxy.failover_direct = false` مفروض — إن لم يكن بروكسي Tor المضبوط قابلًا للوصول، يجب أن يفشل الإرسال. الإضافة لا تسقط أبدًا بصمت إلى clearnet.
- **DNS عبر Tor فقط.** `socks_remote_dns = true`, `network.trr.mode = 5` (بلا DoH موازٍ)، `network.dns.disablePrefetch = true`. مُتحقَّق تجريبيًا: صفر استعلام DNS يصل إلى resolver المحلي خلال إرسال حقيقي عبر Tor.
- **OCSP مُعطَّل.** وإلّا فحوصات الإبطال تطلق طلب HTTP clearnet إلى الـ CA في كل مصافحة TLS.
- **بلا phone-home للتحديثات.** عناوين التطبيق + الإضافات + GMP-manager مُسحت.
- **بلا تيلِمتري، ولا Safebrowsing، ولا فحوص captive-portal، ولا تَصْيير محتوى عن بُعد.**
- **بلا WebRTC، ولا geolocation، ولا DNS prefetch، ولا predictor.**
- **حماية في وسط الجلسة.** تُعاد تأكيدات prefs عند كل بدء لـ TB ودوريًا أثناء التصلّب.
- **التصلّب قابل للتراجع.** يُؤخذ snapshot قبل أوّل تفعيل، ويُستعاد بزرّ التعطيل في صفحة الخيارات أو برسالة `disable-hardening`.
- **canary للاختبار الذاتي** عند الإقلاع وأثناء التصلّب النشط: يقارن SOCKS5-RESOLVE (ثلاثة Tor circuits معزولة stream) مع المجموعة الكاملة لجواب resolver النظام.
- **تشخيص آمن للخصوصية.** السجلات تلخّص العدّادات والـIPs المُقنَّعة وفئات الأخطاء — بلا IPs خام أو معرّفات حسابات.
- **Allowlist لكتابات prefs** في experiment API.

**حدود متأصّلة — OnionBird لا يستطيع إصلاحها:**

1. **`Authentication-Results: ... smtp.auth=<صندوقك>@<المزود>`** يُضاف بواسطة MTA المزود — يكشف للمستلم الصندوق المُوثَّق. خاصية متأصّلة في SMTP المُوثَّق. *حلّ بديل:* صندوق مؤقت / مستعار للمراسلات الحساسة.
2. **IP مَخرج Tor يظهر في سلسلة `Received:` لدى المستلم.** الـ MTA يجري reverse-DNS وينتج أسماء مثل `tor-exit-107.digitalcourage.de`. يعلم المستلم بأنّ المستخدِم أرسل عبر Tor.
3. **تسريبات على مستوى النظام** — كشف hostname من تطبيقات أخرى، NTP، swap، أختام زمنية للملفات. استخدم Tails أو Whonix.
4. **ارتباط الشبكة** — مراقِب يَرى طرفَي circuit Tor. لا تهزمه نظافة الرؤوس.

كلّ ما لم يقع في هذه الفئات الأربع فهو **ضمن نطاق** السياسة. أبلِغ عن باغ P0 إن وجدت مثالًا مضادًا.

---

## مشهد mail-Tor

للمقارنة الكاملة، انظر [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature). باختصار: OnionBird **إضافة Thunderbird عادية** (لا نظام تشغيل منفصل مثل Tails/Whonix)، مع **تغطية DNS عبر Tor متحقَّق تجريبيًا**، **canary مستمر** و**FQDN قابل للتخصيص لـ Message-ID** (بدلًا من supercluster `localhost.localdomain` لدى TorBirdy).

---


> ⚠️ **كَدِّس مع OS مُحَصَّن لـ Tor** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## قبل التثبيت

الإضافة تُصلِّب ما يعمل **داخل** Thunderbird. للحصول على تغطية Tor كاملة، يجب أن يمرّ **resolver النظام** أيضًا عبر Tor:

- **Tails / محطة Whonix** — DNS النظام مُمرَّر أصلًا عبر Tor. ثبِّت `.xpi` وانتهيت.
- **Linux قياسي مع Tor نظامي** — أضف `DNSPort 5353` إلى `/etc/tor/torrc` وتأكَّد من أنّ `/etc/resolv.conf` يصل إليه.
- **Tor Browser bundle فقط** — Tor يستمع على `9150` لا `9050`؛ الإضافة تُسبر prefs الموجودة وكلا المنفذين قبل كتابة prefs البروكسي.
- **SOCKS Tor/Whonix بعيد** — استخدم IP حرفيًا (`10.152.152.10:9050`)، لا hostname.
- **سطح مكتب قياسي بدون DNS نظامي عبر Tor** — ثبِّت على مسؤوليتك. سيُعلِّم canary التكوينَ في صفحة الخيارات وفي الـ console.

---

## ماذا يفعل اليوم

- يُمرِّر IMAP/SMTP عبر بروكسي SOCKS5 محلي (افتراضيًا `127.0.0.1:9050`، قابل للضبط) مع `socks_remote_dns=true` و`failover_direct=false`.
- يُطبِّع الرؤوس الكاشفة للهوية: `User-Agent` / `X-Mailer` مكتومة، FQDN في `Message-ID` قابل للضبط (افتراضيًا نطاق From)، إعادة كتابة `HELO`/`EHLO` إلى `[127.0.0.1]`، `Date` UTC، بلا `format=flowed`.
- دفاع متعدد الطبقات: TRR=5، OCSP off، بلا WebRTC، بلا DNS prefetch، بلا predictor، بلا phone-home، بلا تيلِمتري، بلا Safebrowsing، بلا captive-portal، بلا محتوى بعيد.
- **canary SOCKS5-RESOLVE مقابل DNS النظام** عند البدء ودوريًا.
- **وضع اختبار Tor** في صفحة الخيارات.
- صفحة الخيارات تدعم سمة نظامي/فاتح/داكن، واجهة متعددة اللغات، ومساعدة مدمجة (TL;DR + وضع Nerd).
- تنشيط تلقائي عند أول تثبيت. **زرّ التعطيل** يُستعيد snapshot.
- افتراضيًا لا يُصلِّب إلّا خوادم SMTP من نوع **onion + loopback** (B-003) — حساباتك clearnet الموجودة تستمرّ بالعمل عاديًا.

---

## البنية

OnionBird هجين: سكربت خلفية MailExtension يوفّر السطح العام للـ API، وموديول Experiments API يعمل في عملية parent ويكشف `Services.prefs`، `MailServices.outgoingServer`، `MailServices.accounts`، SOCKS5 RESOLVE / RESOLVE_PTR الخام، ومناورة `nsIDNSService.clearCache`. يتواصل الجزآن عبر مساحة الأسماء `browser.onionbird.*`. انظر [docs/architecture.md](docs/architecture.md).

---

## خريطة الطريق / حدود معروفة

انظر [docs/follow-up.md](docs/follow-up.md). مؤجَّلة: مفتاح وضع UI mixed-mode، hook على تغيير رابط الشبكة / resolver، إعادة محاولة PTR متعدد circuit، وسم logins التي أنشأتها الإضافة، first-run wizard، bridges / pluggable-transports لـ ISP المراقَب، تكامل مع Tor control-port (NEWNYM لكل إرسال)، مُثبِّت موحَّد عبر المنصّات.

---

## الترخيص

MPL-2.0. للنصّ الكامل: [LICENSE](LICENSE).

البرنامج يُقدَّم كما هو، بلا ضمانات. لا يتحمّل المؤلِّفون مسؤولية أيّ كشف للهوية أو ضرر آخر ناتج من الاستخدام. انظر LICENSE.
