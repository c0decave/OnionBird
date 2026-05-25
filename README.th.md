# OnionBird

**ภาษา:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · **ภาษาไทย** · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **ALPHA — อัลฟาช่วงปลาย กันรั่วบน OS ที่ส่ง DNS ผ่าน Tor อ่าน[ข้อกำหนดล่วงหน้า](#ก่อนติดตั้ง)ก่อนติดตั้ง**

> ก่อนที่จะไว้วางใจ OnionBird กับงานที่สำคัญต่อการไม่ระบุตัวตน โปรดอ่าน[โมเดลภัยคุกคาม](docs/threat-model.md)และ[รายการ follow-up](docs/follow-up.md)

OnionBird คือส่วนเสริมของ Thunderbird ที่ส่ง IMAP/SMTP ผ่าน proxy Tor ภายในเครื่อง และลบหรือมาตรฐานหัว message ที่เคยถูกใช้เพื่อเปิดเผยตัวผู้ส่ง เป้าหมาย: Thunderbird 140 ESR ออกแบบเป็นผู้สืบทอดสมัยใหม่ของส่วนเสริม TorBirdy ที่ไม่ได้บำรุงรักษา (รุ่นสุดท้าย v0.2.6 ปี 2018; หยุดทำงานเพราะการลบ Legacy XUL ใน TB 78)

เวอร์ชันปัจจุบัน: **0.1.1**

---

## นโยบายความเป็นส่วนตัวและความปลอดภัย 100%

อาณัติของโครงการเป็นแบบไบนารี: **เส้นทางโค้ดใดๆ ที่สังเกตได้ซึ่งรั่วตัวตนของผู้ใช้ IP จริง hostname locale เขตเวลา หรือแม้แต่ข้อเท็จจริงที่ผู้ใช้กำลังเสริมความแข็งของอีเมล ถือเป็นข้อบกพร่อง P0 และจะบล็อกการเผยแพร่** "ดีพอ" "ปกติทำงานได้" หรือ "เกือบไม่รั่ว" ไม่ใช่ผลลัพธ์ที่ยอมรับได้

อย่างเป็นรูปธรรม:

- **Fail-closed เป็นค่าเริ่มต้น** `network.proxy.failover_direct = false` ถูกบังคับ — ถ้า Tor proxy ที่ตั้งไว้ไปไม่ถึง การส่งต้องล้มเหลว ส่วนเสริมจะไม่ตกเข้า clearnet อย่างเงียบ ๆ
- **DNS ผ่าน Tor เท่านั้น** `socks_remote_dns = true`, `network.trr.mode = 5` (ไม่มี DoH คู่ขนาน), `network.dns.disablePrefetch = true` ทดสอบเชิงประจักษ์: ศูนย์ DNS query ถึง resolver ในเครื่องระหว่างการส่งจริงผ่าน Tor
- **OCSP ปิด** มิฉะนั้นการตรวจ revocation จะยิง HTTP clearnet ไปยัง CA ทุกครั้งที่ TLS handshake
- **ไม่มี phone-home ของอัปเดต** URL ของแอป + extensions + GMP-manager ถูกล้าง
- **ไม่มี telemetry, Safebrowsing, captive-portal probe, render เนื้อหาทางไกล**
- **ไม่มี WebRTC, geolocation, DNS prefetch, predictor**
- **การป้องกันกลางเซสชัน** prefs ถูกยืนยันซ้ำทุกครั้งที่ TB เริ่ม และเป็นระยะ ๆ ขณะที่การเสริมความแข็งทำงานอยู่
- **เสริมความแข็งย้อนกลับได้** snapshot ถูกถ่ายก่อนเปิดครั้งแรก คืนค่าได้ผ่านปุ่ม Disable ในหน้า Options หรือข้อความ `disable-hardening`
- **Self-test canary** ตอนเริ่มและขณะเสริมความแข็ง: เปรียบเทียบ SOCKS5-RESOLVE (3 Tor circuits แบบแยก stream) กับชุดคำตอบเต็มของ resolver ระบบ
- **การวินิจฉัยที่ปลอดภัยต่อความเป็นส่วนตัว** บันทึกสรุปนับ, IP ที่มาสก์ และคลาสของข้อผิดพลาด — ไม่มี IP ดิบหรือตัวระบุบัญชี
- **allowlist สำหรับการเขียน prefs** ใน experiment API

**ขีดจำกัดในตัว — OnionBird แก้ไม่ได้:**

1. **`Authentication-Results: ... smtp.auth=<กล่องของคุณ>@<ผู้ให้บริการ>`** ถูกเพิ่มโดย MTA ของผู้ให้บริการ — เปิดเผยกล่องที่ยืนยันตัวตนแก่ทุกผู้รับ *ทางเลี่ยง:* ใช้กล่องใช้ครั้งเดียว / นามแฝงสำหรับจดหมายอ่อนไหว
2. **IP ขาออกของ Tor จะปรากฏในห่วงโซ่ `Received:` ของผู้รับ** MTA ทำ reverse-DNS และสร้างชื่อแบบ `tor-exit-107.digitalcourage.de` ผู้รับรู้ว่า "ผู้ใช้นี้ส่งผ่าน Tor"
3. **การรั่วระดับ OS** — แอปอื่นเปิดเผย hostname, NTP, swap, timestamp ของไฟล์ ใช้ Tails หรือ Whonix
4. **การ correlation เชิงเครือข่าย** — ผู้สังเกตทั้งสองปลาย Tor circuit สุขอนามัย header เอาชนะไม่ได้

ทุกสิ่งที่ไม่ตกใน 4 หมวดนี้ ถือว่าอยู่ใน**ขอบเขต**ของนโยบาย หากพบตัวอย่างขัดแย้ง ให้ยื่นบั๊ก P0

---

## ภาพรวม mail-Tor

เปรียบเทียบฉบับเต็มที่ [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature) ใจความ: OnionBird เป็น **ส่วนเสริม Thunderbird ปกติ** (ไม่ใช่ OS แยกแบบ Tails/Whonix) มี **DNS-via-Tor coverage ที่ตรวจสอบเชิงประจักษ์**, **canary ต่อเนื่อง**, และ **FQDN ของ Message-ID ที่กำหนดเองได้** (แทน supercluster `localhost.localdomain` ของ TorBirdy)

---


> ⚠️ **วางซ้อนกับ OS ที่เข้มงวดสำหรับ Tor** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## ก่อนติดตั้ง

ส่วนเสริมเสริมความแข็งในสิ่งที่ทำงาน **ภายใน** Thunderbird เพื่อให้ครอบคลุม Tor 100% **resolver ของ OS** ก็ต้องผ่าน Tor ด้วย:

- **Tails / Whonix workstation** — DNS ระบบผ่าน Tor อยู่แล้ว ติดตั้ง `.xpi` เสร็จ
- **Linux มาตรฐานที่มี Tor ของระบบ** — เพิ่ม `DNSPort 5353` ใน `/etc/tor/torrc` และให้ `/etc/resolv.conf` ชี้ไปที่นั่น
- **Tor Browser bundle เท่านั้น** — Tor ฟังที่ `9150` ไม่ใช่ `9050`; ส่วนเสริม probe pref ที่มีและทั้งสองพอร์ตทั่วไปก่อนจะเขียน prefs proxy
- **SOCKS Tor/Whonix ระยะไกล** — ใช้ IP literal (`10.152.152.10:9050`) ไม่ใช่ hostname
- **เดสก์ท็อปทั่วไปที่ไม่ได้ส่ง DNS ระบบผ่าน Tor** — ติดตั้งตามความเสี่ยงของคุณเอง canary จะแจ้งการตั้งค่าในหน้า Options และคอนโซล

---

## ปัจจุบันทำอะไร

- ส่ง IMAP/SMTP ผ่าน proxy SOCKS5 ในเครื่อง (ค่าเริ่มต้น `127.0.0.1:9050` ปรับได้) ด้วย `socks_remote_dns=true` และ `failover_direct=false`
- มาตรฐาน header ที่ระบุตัวตน: `User-Agent` / `X-Mailer` ถูกกด, FQDN ของ `Message-ID` ปรับได้ (ค่าเริ่มต้น = From-domain ของคุณ), SMTP `HELO`/`EHLO` เขียนใหม่เป็น `[127.0.0.1]`, `Date` UTC, ไม่มี `format=flowed`
- Defense-in-depth: TRR=5, OCSP off, ไม่มี WebRTC, ไม่มี DNS prefetch, ไม่มี predictor, ไม่มี phone-home, ไม่มี telemetry, ไม่มี Safebrowsing, ไม่มี captive-portal, ไม่มี remote content
- **Canary SOCKS5-RESOLVE vs DNS ระบบ** ตอนเริ่มและเป็นระยะ
- **Tor test mode** ในหน้า Options
- หน้า Options รองรับธีมระบบ/สว่าง/มืด, UI หลายภาษา และ Help ในตัว (TL;DR + โหมด Nerd)
- เปิดอัตโนมัติเมื่อติดตั้งครั้งแรก **ปุ่ม Disable** คืนค่า snapshot
- ค่าเริ่มต้นจะเสริมความแข็งเฉพาะ SMTP **onion + loopback** (B-003) — บัญชี clearnet เดิมยังทำงานปกติ

---

## สถาปัตยกรรม

OnionBird เป็นไฮบริด: สคริปต์ background ของ MailExtension ให้พื้นผิว API สาธารณะ, และโมดูล Experiments API ทำงานใน parent process และเปิด `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, SOCKS5 RESOLVE / RESOLVE_PTR ดิบ และ `nsIDNSService.clearCache` ทั้งสองครึ่งสื่อสารผ่าน namespace `browser.onionbird.*` ดู [docs/architecture.md](docs/architecture.md)

---

## โรดแมป / ข้อจำกัดที่ทราบ

ดู [docs/follow-up.md](docs/follow-up.md) เลื่อนไว้รอบหลัง: toggle UI mixed-mode, hook เมื่อ link เครือข่าย / resolver เปลี่ยน, retry PTR หลาย circuit, ติดแท็ก login ที่ส่วนเสริมสร้าง, wizard ครั้งแรก, bridges / pluggable-transports สำหรับ ISP ที่ถูกเซ็นเซอร์, การเชื่อมต่อ Tor control-port (NEWNYM ต่อการส่ง), installer ข้ามแพลตฟอร์มที่แพ็กไว้

---

## ใบอนุญาต

MPL-2.0 ข้อความเต็มที่ [LICENSE](LICENSE)

ซอฟต์แวร์มาตามที่เป็น โดยไม่มีการรับประกันใดๆ ผู้เขียนไม่รับผิดชอบต่อการสูญเสียความไม่ระบุตัวตนหรือความเสียหายอื่นใดจากการใช้งาน ดู LICENSE สำหรับข้อปฏิเสธความรับผิดทั้งหมด
