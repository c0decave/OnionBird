# OnionBird

**שפות:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · **עברית** · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **אלפא — אלפא מאוחרת, ללא דליפות על מערכת שמעבירה DNS דרך Tor. קראו את [הדרישות](#לפני-ההתקנה) לפני התקנה.**

> קראו את [מודל האיומים](docs/threat-model.md) ואת [רשימת ה־follow-up](docs/follow-up.md) לפני שתסמכו על OnionBird בשימוש קריטי לאנונימיות.

OnionBird הוא תוסף ל־Thunderbird שמנתב IMAP/SMTP דרך proxy Tor מקומי, ומסיר או מנרמל כותרות הודעה ששימשו היסטורית לזיהוי שולחים. יעד: Thunderbird 140 ESR. נועד להיות היורש המודרני של תוסף TorBirdy שאינו מתוחזק (שחרור אחרון v0.2.6 ב־2018, הפסיק לעבוד עם הסרת Legacy XUL ב־TB 78).

גרסה נוכחית: **0.1.4**.

---

## מדיניות פרטיות ואבטחה ב־100%

ייעוד הפרויקט בינארי: **כל מסלול קוד ניתן לצפייה שמדליף את זהות המשתמש, IP אמיתי, hostname, locale, אזור זמן או את עצם העובדה שהמשתמש מקשיח את הדואר שלו, נחשב פגם P0 ועוצר שחרור.** "מספיק טוב", "בדרך כלל עובד" או "כמעט בלי דליפה" אינן תוצאות קבילות.

באופן ממשי:

- **Fail-closed כברירת מחדל.** `network.proxy.failover_direct = false` נכפה — אם ה־proxy של Tor אינו נגיש, השליחה אמורה להיכשל. התוסף לעולם לא נופל בשקט ל־clearnet.
- **DNS רק דרך Tor.** `socks_remote_dns = true`, `network.trr.mode = 5` (ללא DoH מקביל), `network.dns.disablePrefetch = true`. אומת אמפירית: אפס שאילתות DNS מגיעות ל־resolver המקומי בזמן שליחה אמיתית דרך Tor.
- **OCSP כבוי.** אחרת בדיקות revocation היו שולחות בקשת HTTP clearnet ל־CA בכל TLS handshake.
- **ללא phone-home לעדכונים.** כתובות אפליקציה + תוספים + GMP-manager נוקו.
- **ללא טלמטריה, Safebrowsing, בדיקות captive-portal, רינדור תוכן מרוחק.**
- **ללא WebRTC, geolocation, DNS prefetch, predictor.**
- **הגנה באמצע הסשן.** prefs מאומתים מחדש בכל הפעלה של TB ומעת לעת בזמן שההקשחה פעילה.
- **ההקשחה הפיכה.** snapshot נלקח לפני ההפעלה הראשונה ומשוחזר באמצעות כפתור "בטל" בדף האפשרויות או הודעת `disable-hardening`.
- **canary לבדיקה עצמית** בעת ההפעלה ובמהלך הקשחה פעילה: משווה SOCKS5-RESOLVE (3 circuits של Tor במבודד stream) למלוא קבוצת התשובה של resolver המערכת.
- **דיווח מאבחן ידידותי לפרטיות.** יומנים מסכמים מונים, כתובות IP ממוסכות ומחלקות שגיאה — ללא IP גולמי או מזהי חשבון.
- **רשימת היתר לכתיבת prefs** ב־experiment API.

**מגבלות אינהרנטיות — OnionBird אינו יכול לתקן:**

1. **`Authentication-Results: ... smtp.auth=<תיבה-שלך>@<ספק>`** מתווסף ע"י ה־MTA של הספק — חושף לכל נמען את התיבה המאומתת. *עקיפה:* תיבה חד־פעמית / בשם בדוי להתכתבות רגישה.
2. **כתובת היציאה של Tor מופיעה בשרשרת `Received:` של הנמען.** MTA מבצע reverse-DNS ויוצר שמות כמו `tor-exit-107.digitalcourage.de`. הנמען לומד שהמשתמש שלח דרך Tor.
3. **דליפות ברמת מערכת ההפעלה** — חשיפת hostname מאפליקציות אחרות, NTP, swap, חותמות זמן בקבצים. השתמשו ב־Tails או Whonix.
4. **קורלציית רשת** — מתבונן שרואה את שני קצוות מעגל Tor. היגיינת כותרות לא מנצחת זאת.

כל מה שלא נופל לארבע קטגוריות אלה, **בתחום** המדיניות. הגישו באג P0 אם מצאתם דוגמה נגדית.

---

## נוף mail-Tor

להשוואה מלאה ראו [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature). בקיצור: OnionBird הוא **תוסף Thunderbird רגיל** (לא מערכת הפעלה נפרדת כמו Tails/Whonix), עם **כיסוי DNS דרך Tor שאומת אמפירית**, **canary רציף** ו**FQDN להגדרה ב־Message-ID** (במקום supercluster `localhost.localdomain` של TorBirdy).

---


> ⚠️ **ערום עם OS המוקשח עבור Tor** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## לפני ההתקנה

התוסף מקשיח את מה שרץ **בתוך** Thunderbird. לכיסוי Tor של 100% גם **resolver של מערכת ההפעלה** חייב לעבור דרך Tor:

- **Tails / תחנת Whonix** — DNS של המערכת כבר עובר דרך Tor. התקינו `.xpi` וסיימתם.
- **Linux רגיל עם Tor מערכתי** — הוסיפו `DNSPort 5353` ל־`/etc/tor/torrc` וודאו ש־`/etc/resolv.conf` מגיע לשם.
- **רק Tor Browser bundle** — Tor מאזין על `9150`, לא `9050`; התוסף מסקור prefs קיימים ושני הפורטים הנפוצים לפני שהוא כותב prefs ל־proxy.
- **SOCKS Tor/Whonix מרוחק** — השתמשו ב־IP מילולי (`10.152.152.10:9050`), לא hostname.
- **שולחן עבודה רגיל ללא DNS מערכת דרך Tor** — התקינו על אחריותכם. ה־canary יסמן את התצורה בדף האפשרויות ובקונסולת ה־browser.

---

## מה הוא עושה היום

- מנתב IMAP/SMTP דרך proxy SOCKS5 מקומי (ברירת מחדל `127.0.0.1:9050`, הניתן להגדרה) עם `socks_remote_dns=true` ו־`failover_direct=false`.
- מנרמל כותרות מזהות: `User-Agent` / `X-Mailer` מודחקים, FQDN של `Message-ID` הניתן להגדרה (ברירת מחדל From-domain), SMTP `HELO`/`EHLO` משוכתב ל־`[127.0.0.1]`, `Date` UTC, ללא `format=flowed`.
- Defense-in-depth: TRR=5, OCSP off, ללא WebRTC, ללא DNS prefetch, ללא predictor, ללא phone-home, ללא טלמטריה, ללא Safebrowsing, ללא captive-portal, ללא תוכן מרוחק.
- **canary של SOCKS5-RESOLVE מול DNS של המערכת** בהפעלה ובמחזורים.
- **Tor test mode** בדף האפשרויות.
- דף האפשרויות תומך בערכת נושא של המערכת/בהירה/כהה, UI רב־שפתי, ועזרה מובנית (TL;DR + מצב Nerd).
- מופעל אוטומטית בהתקנה הראשונה. **כפתור Disable** משחזר את ה־snapshot.
- ברירת המחדל מקשיחה רק שרתי SMTP מסוג **onion + loopback** (B-003) — חשבונות clearnet קיימים ממשיכים לעבוד.

---

## ארכיטקטורה

OnionBird הוא היברידי: סקריפט background של MailExtension מספק את שטח ה־API הציבורי, ומודול Experiments API רץ בתהליך parent וחושף `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, SOCKS5 RESOLVE / RESOLVE_PTR גולמי ומניפולציה של `nsIDNSService.clearCache`. שני החצאים מתקשרים דרך מרחב השמות `browser.onionbird.*`. ראו [docs/architecture.md](docs/architecture.md).

---

## מפת דרכים / מגבלות ידועות

ראו [docs/follow-up.md](docs/follow-up.md). נדחו: UI mixed-mode toggle, hook לשינוי קישור רשת / resolver, multi-circuit PTR retry, תיוג logins שנוצרו ע"י התוסף, first-run wizard, bridges / pluggable-transports ל־ISP מצונזרים, אינטגרציה עם Tor control-port (NEWNYM לכל שליחה), מתקין cross-platform ארוז.

---

## רישיון

MPL-2.0. לטקסט המלא ראו [LICENSE](LICENSE).

התוכנה ניתנת כפי שהיא, ללא שום אחריות. המחברים אינם אחראים לאיבוד אנונימיות או נזקים אחרים הנובעים מהשימוש. ראו LICENSE.
