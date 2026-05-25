# OnionBird

**Bahasa:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · **Bahasa Indonesia** · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **ALPHA — alpha akhir, kedap bocor pada OS yang sadar Tor-DNS. Baca [prasyarat](#sebelum-instalasi) sebelum memasang.**

> Baca [model ancaman](docs/threat-model.md) dan [daftar follow-up](docs/follow-up.md) sebelum mempercayakan OnionBird untuk pemakaian yang kritikal bagi anonimitas.

OnionBird adalah add-on Thunderbird yang merutekan IMAP/SMTP melalui proxy Tor lokal dan membuang atau menormalkan header pesan yang secara historis digunakan untuk membuka identitas pengirim. Target: Thunderbird 140 ESR. Dirancang sebagai penerus modern bagi ekstensi TorBirdy yang tidak lagi dipelihara (rilis terakhir v0.2.6 pada 2018; mati karena Legacy XUL dihapus di TB 78).

Versi saat ini: **0.1.1**.

---

## Kebijakan privasi dan keamanan 100%

Mandat proyek bersifat biner: **setiap jalur kode yang dapat diamati yang membocorkan identitas pengguna, IP nyata, hostname, locale, zona waktu, atau bahkan fakta bahwa pengguna sedang menguatkan email-nya, dianggap cacat P0 dan memblokir rilis.** "Cukup bagus", "biasanya jalan", atau "hampir tanpa bocor" bukan hasil yang dapat diterima.

Konkretnya:

- **Default fail-closed.** `network.proxy.failover_direct = false` dipaksa — bila proxy Tor yang dikonfigurasi tidak terjangkau, pengiriman harus gagal. Add-on TIDAK PERNAH jatuh diam-diam ke clearnet.
- **DNS hanya lewat Tor.** `socks_remote_dns = true`, `network.trr.mode = 5` (tanpa DoH paralel), `network.dns.disablePrefetch = true`. Diverifikasi empiris: nol query DNS mencapai resolver lokal selama pengiriman nyata via Tor.
- **OCSP mati.** Kalau tidak, pemeriksaan revocation akan menembakkan permintaan HTTP clearnet ke CA pada setiap TLS handshake.
- **Tanpa phone-home update.** URL app + extensions + GMP-manager dikosongkan.
- **Tanpa telemetri, Safebrowsing, captive-portal probe, render konten remote.**
- **Tanpa WebRTC, geolocation, DNS prefetch, predictor.**
- **Perlindungan tengah-sesi.** Prefs diafirmasi ulang setiap TB startup dan periodik selama hardening aktif.
- **Hardening reversibel.** Snapshot diambil sebelum aktivasi pertama; dipulihkan via tombol Disable di halaman Options atau pesan `disable-hardening`.
- **Canary self-test** saat startup dan selama hardening aktif: membandingkan SOCKS5-RESOLVE (3 circuit Tor terisolasi stream) dengan set jawaban lengkap resolver sistem.
- **Diagnostik aman-privasi.** Log meringkas hitungan, IP termask, dan kelas error — tanpa IP mentah atau pengenal akun.
- **Allowlist tulis prefs** di experiment API.

**Batas inheren — OnionBird TIDAK BISA memperbaikinya:**

1. **`Authentication-Results: ... smtp.auth=<kotak-anda>@<penyedia>`** ditambahkan oleh MTA penyedia — membongkar kotak terotentikasi kepada setiap penerima. *Workaround:* gunakan kotak sekali pakai / pseudonim untuk korespondensi sensitif.
2. **IP exit Tor muncul di rantai `Received:` penerima.** MTA melakukan reverse-DNS dan menghasilkan nama seperti `tor-exit-107.digitalcourage.de`. Penerima tahu "pengguna ini mengirim via Tor".
3. **Kebocoran tingkat OS** — pengungkapan hostname oleh aplikasi lain, NTP, swap, timestamp filesystem. Pakai Tails atau Whonix.
4. **Korelasi jaringan** — pengamat dua ujung circuit Tor. Higiene header tidak mengalahkannya.

Semua yang tidak masuk dalam empat kategori itu **berada dalam ruang lingkup** kebijakan. Buka bug P0 bila Anda menemukan contoh-tandingan.

---

## Lanskap mail-Tor

Perbandingan lengkap lihat [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature). Singkatnya: OnionBird adalah **ekstensi Thunderbird biasa** (bukan OS terpisah seperti Tails/Whonix), dengan **cakupan DNS-via-Tor yang diverifikasi empiris**, **canary berkelanjutan**, dan **FQDN Message-ID yang dapat dikonfigurasi** (bukan supercluster `localhost.localdomain` ala TorBirdy).

---


> ⚠️ **Tumpuk dengan OS yang dikeraskan untuk Tor** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## Sebelum instalasi

Add-on menguatkan apa yang berjalan **di dalam** Thunderbird. Untuk cakupan Tor 100%, **resolver OS** juga harus melalui Tor:

- **Tails / Whonix workstation** — DNS sistem sudah lewat Tor. Pasang `.xpi`, selesai.
- **Linux standar dengan Tor sistem** — tambahkan `DNSPort 5353` ke `/etc/tor/torrc` dan pastikan `/etc/resolv.conf` menuju ke sana.
- **Hanya Tor Browser bundle** — Tor mendengarkan di `9150`, bukan `9050`; add-on memprobe pref yang ada dan kedua port lokal yang umum sebelum menulis prefs proxy.
- **SOCKS Tor/Whonix jauh** — gunakan IP literal (`10.152.152.10:9050`), bukan hostname.
- **Desktop standar tanpa DNS sistem via Tor** — pasang atas risiko Anda. Canary akan menandai konfigurasi di halaman Options dan di konsol.

---

## Apa yang dilakukannya hari ini

- Merutekan IMAP/SMTP lewat proxy SOCKS5 lokal (default `127.0.0.1:9050`, dapat dikonfigurasi) dengan `socks_remote_dns=true` dan `failover_direct=false`.
- Menormalkan header pengenal: `User-Agent` / `X-Mailer` ditekan, FQDN `Message-ID` dapat dikonfigurasi (default = From-domain Anda), SMTP `HELO`/`EHLO` ditulis ulang menjadi `[127.0.0.1]`, `Date` UTC, tanpa `format=flowed`.
- Defense-in-depth: TRR=5, OCSP off, tanpa WebRTC, tanpa DNS prefetch, tanpa predictor, tanpa phone-home, tanpa telemetri, tanpa Safebrowsing, tanpa captive-portal, tanpa konten remote.
- **Canary SOCKS5-RESOLVE vs DNS sistem** saat startup dan periodik.
- **Tor test mode** di halaman Options.
- Halaman Options mendukung tema sistem/terang/gelap, UI multi-bahasa, dan Help bawaan (TL;DR + mode Nerd).
- Mengaktifkan otomatis pada instalasi pertama. **Tombol Disable** memulihkan snapshot.
- Default hanya server SMTP **onion + loopback** yang dikeraskan (B-003) — akun clearnet Anda yang ada tetap berfungsi normal.

---

## Arsitektur

OnionBird hibrida: skrip background MailExtension menyediakan permukaan API publik, dan modul Experiments API berjalan di proses parent dan mengekspos `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, SOCKS5 RESOLVE / RESOLVE_PTR mentah, dan manipulasi `nsIDNSService.clearCache`. Kedua paruh berkomunikasi melalui namespace `browser.onionbird.*`. Lihat [docs/architecture.md](docs/architecture.md).

---

## Roadmap / batasan yang diketahui

Lihat [docs/follow-up.md](docs/follow-up.md). Ditunda ke iterasi berikutnya: toggle UI mixed-mode, hook ketika tautan jaringan / resolver berubah, retry PTR multi-circuit, penandaan login yang dibuat add-on, wizard first-run, bridges / pluggable-transports untuk ISP yang disensor, integrasi Tor control-port (NEWNYM per kirim), installer cross-platform yang dipaketkan.

---

## Lisensi

MPL-2.0. Teks lengkap lihat [LICENSE](LICENSE).

Perangkat lunak disediakan apa adanya, tanpa jaminan apa pun. Penulis tidak bertanggung jawab atas hilangnya anonimitas atau kerugian lain akibat penggunaan. Lihat LICENSE untuk disclaimer penuh.
