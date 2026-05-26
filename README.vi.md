# OnionBird

**Ngôn ngữ:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · **Tiếng Việt** · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **BETA — alpha cuối, không rò rỉ trên OS có DNS đi qua Tor. Đọc [yêu cầu trước](#trước-khi-cài-đặt) trước khi cài.**

> Đọc [mô hình mối đe dọa](docs/threat-model.md) và [danh sách follow-up](docs/follow-up.md) trước khi tin cậy OnionBird cho các tác vụ quan trọng về ẩn danh.

OnionBird là một tiện ích Thunderbird định tuyến IMAP/SMTP qua proxy Tor cục bộ và loại bỏ hoặc chuẩn hoá các header email từng được dùng để vạch danh tính người gửi. Mục tiêu: Thunderbird 140 ESR. Được thiết kế như người kế tục hiện đại cho tiện ích TorBirdy không còn được duy trì (bản cuối v0.2.6 năm 2018; bị diệt do TB 78 loại Legacy XUL).

Phiên bản hiện tại: **0.1.4**.

---

## Chính sách 100% riêng tư và bảo mật

Phạm vi dự án mang tính nhị phân: **bất kỳ đường mã quan sát được nào làm rò rỉ danh tính người dùng, IP thực, hostname, locale, múi giờ, hoặc chỉ là sự kiện người dùng đang gia cố thư, đều bị xem là lỗi P0 và chặn release.** "Đủ tốt", "thường thì chạy" hay "gần như không rò" đều không phải là kết quả chấp nhận được.

Cụ thể:

- **Mặc định fail-closed.** `network.proxy.failover_direct = false` được ép — nếu proxy Tor đã cấu hình không thể truy cập, việc gửi phải thất bại. Tiện ích KHÔNG bao giờ âm thầm rơi về clearnet.
- **DNS chỉ qua Tor.** `socks_remote_dns = true`, `network.trr.mode = 5` (không DoH song song), `network.dns.disablePrefetch = true`. Kiểm chứng thực nghiệm: 0 truy vấn DNS đến resolver cục bộ trong khi gửi qua Tor thực.
- **OCSP tắt.** Nếu không, kiểm tra revocation sẽ gửi HTTP clearnet tới CA mỗi lần handshake TLS.
- **Không phone-home update.** URL của app + extensions + GMP-manager đã xoá.
- **Không telemetry, Safebrowsing, captive-portal, render nội dung từ xa.**
- **Không WebRTC, geolocation, DNS prefetch, predictor.**
- **Bảo vệ giữa phiên.** Prefs được tái khẳng định mỗi lần TB khởi động và định kỳ khi gia cố đang bật.
- **Gia cố có thể hoàn tác.** Snapshot lấy trước lần bật đầu tiên, khôi phục bằng nút Disable trên trang Options hoặc thông điệp `disable-hardening`.
- **Canary self-test** lúc khởi động và khi gia cố đang chạy: so sánh SOCKS5-RESOLVE (3 circuit Tor cô lập stream) với toàn bộ tập câu trả lời của resolver hệ thống.
- **Chẩn đoán an toàn cho riêng tư.** Log tổng kết bộ đếm, IP che mặt và lớp lỗi — không IP thô hay định danh tài khoản.
- **Allowlist ghi prefs** trong experiment API.

**Giới hạn cố hữu — OnionBird KHÔNG thể khắc phục:**

1. **`Authentication-Results: ... smtp.auth=<hộp-thư-của-bạn>@<nhà-cung-cấp>`** được MTA của nhà cung cấp thêm — tiết lộ hộp đã xác thực cho mọi người nhận. *Giải pháp tránh:* dùng hộp thư dùng một lần / bí danh cho thư nhạy cảm.
2. **IP exit của Tor xuất hiện trong chuỗi `Received:` của người nhận.** MTA thực hiện reverse-DNS, tạo ra tên kiểu `tor-exit-107.digitalcourage.de`. Người nhận biết người dùng đã gửi qua Tor.
3. **Rò rỉ ở tầng OS** — hostname từ ứng dụng khác, NTP, swap, dấu thời gian tệp. Dùng Tails hoặc Whonix.
4. **Tương quan mạng** — bên quan sát cả hai đầu circuit Tor. Vệ sinh header không thắng được.

Mọi thứ không thuộc bốn nhóm trên đều **trong phạm vi** của chính sách. Mở bug P0 nếu bạn tìm thấy phản ví dụ.

---

## Bức tranh mail-Tor

So sánh đầy đủ xem [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature). Tóm tắt: OnionBird là **một tiện ích Thunderbird bình thường** (không phải OS riêng như Tails/Whonix), có **độ phủ DNS-via-Tor kiểm chứng thực nghiệm**, **canary liên tục** và **FQDN Message-ID có thể cấu hình** (thay vì supercluster `localhost.localdomain` của TorBirdy).

---


> ⚠️ **Xếp chồng với OS đã được làm cứng cho Tor** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## Trước khi cài đặt

Tiện ích gia cố thứ chạy **bên trong** Thunderbird. Để đạt 100% phủ Tor, **resolver của OS** cũng phải đi qua Tor:

- **Tails / Whonix workstation** — DNS hệ thống đã đi qua Tor. Cài `.xpi` là xong.
- **Linux thường có Tor hệ thống** — thêm `DNSPort 5353` vào `/etc/tor/torrc` và đảm bảo `/etc/resolv.conf` tới được nó.
- **Chỉ Tor Browser bundle** — Tor lắng nghe `9150`, không phải `9050`; tiện ích sẽ dò pref hiện hữu và cả hai cổng phổ biến trước khi ghi prefs proxy.
- **SOCKS Tor/Whonix từ xa** — dùng IP literal (`10.152.152.10:9050`), không dùng hostname.
- **Desktop thường không có DNS hệ thống qua Tor** — cài trên rủi ro của bạn. Canary sẽ gắn cờ cấu hình ở trang Options và console.

---

## Hôm nay làm được gì

- Định tuyến IMAP/SMTP qua proxy SOCKS5 cục bộ (mặc định `127.0.0.1:9050`, có thể cấu hình) với `socks_remote_dns=true` và `failover_direct=false`.
- Chuẩn hoá các header nhận diện: `User-Agent` / `X-Mailer` bị nén, FQDN của `Message-ID` cấu hình được (mặc định = From-domain của bạn), SMTP `HELO`/`EHLO` viết lại thành `[127.0.0.1]`, `Date` UTC, không `format=flowed`.
- Defense-in-depth: TRR=5, OCSP off, không WebRTC, không DNS prefetch, không predictor, không phone-home, không telemetry, không Safebrowsing, không captive-portal, không nội dung từ xa.
- **Canary SOCKS5-RESOLVE vs DNS hệ thống** lúc khởi động và định kỳ.
- **Tor test mode** trên trang Options.
- Trang Options hỗ trợ theme hệ thống/sáng/tối, UI đa ngôn ngữ và Help tích hợp (TL;DR + chế độ Nerd).
- Tự bật khi cài lần đầu. **Nút Disable** khôi phục snapshot.
- Mặc định chỉ gia cố các SMTP **onion + loopback** (B-003) — tài khoản clearnet hiện có vẫn hoạt động bình thường.

---

## Kiến trúc

OnionBird là hybrid: một script nền MailExtension cung cấp bề mặt API công khai, và một module Experiments API chạy trong tiến trình parent, mở `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, SOCKS5 RESOLVE / RESOLVE_PTR thô và thao tác `nsIDNSService.clearCache`. Hai nửa giao tiếp qua namespace `browser.onionbird.*`. Xem [docs/architecture.md](docs/architecture.md).

---

## Lộ trình / giới hạn đã biết

Xem [docs/follow-up.md](docs/follow-up.md). Hoãn cho các bản sau: toggle UI mixed-mode, hook trên sự kiện đổi link mạng / resolver, retry PTR đa circuit, gắn nhãn login do tiện ích tạo, wizard chạy lần đầu, bridges / pluggable-transports cho ISP bị kiểm duyệt, tích hợp Tor control-port (NEWNYM mỗi lần gửi), trình cài đa nền tảng được đóng gói.

---

## Giấy phép

MPL-2.0. Toàn văn xem [LICENSE](LICENSE).

Phần mềm cung cấp theo nguyên trạng, không bảo đảm dưới bất kỳ hình thức nào. Tác giả không chịu trách nhiệm về việc mất ẩn danh hoặc thiệt hại khác phát sinh từ việc sử dụng. Xem LICENSE để có miễn trừ trách nhiệm đầy đủ.
