# OnionBird

**Diller:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · **Türkçe** · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **ALFA — geç alfa; Tor DNS'inden farkında bir OS üzerinde sızdırmaz. Yüklemeden önce [önkoşulları](#yüklemeden-önce) okuyun.**

> Anonimlik için kritik kullanımda OnionBird'a güvenmeden önce [tehdit modelini](docs/threat-model.md) ve [follow-up listesini](docs/follow-up.md) okuyun.

OnionBird, IMAP/SMTP'yi yerel bir Tor proxy üzerinden yönlendiren ve gönderenleri deanonymize etmek için tarihsel olarak kullanılmış mesaj başlıklarını kaldıran/normalize eden bir Thunderbird eklentisidir. Hedef: Thunderbird 140 ESR. Bakımı bırakılmış TorBirdy eklentisinin modern halefi olarak tasarlandı (son sürüm v0.2.6, 2018'de; TB 78'deki Legacy XUL kaldırılmasıyla öldü).

Mevcut sürüm: **0.1.1**.

---

## %100 Gizlilik ve Güvenlik Politikası

Proje şartı ikili: **gözlemlenebilir herhangi bir kod yolu kullanıcı kimliğini, gerçek IP'yi, hostname'i, locale'i, saat dilimini veya kullanıcının posta sertleştirdiği gerçeğini sızdırırsa, P0 hatası kabul edilir ve sürümü engeller.** "Yeterince iyi", "genellikle çalışır" veya "neredeyse sızdırmıyor" kabul edilebilir sonuçlar değildir.

Somut olarak:

- **Varsayılan olarak fail-closed.** `network.proxy.failover_direct = false` zorlanır — yapılandırılmış Tor proxy erişilemezse gönderim başarısız olmalı. Eklenti ASLA sessizce clearnet'e düşmez.
- **DNS yalnızca Tor üzerinden.** `socks_remote_dns = true`, `network.trr.mode = 5` (paralel DoH yok), `network.dns.disablePrefetch = true`. Ampirik olarak doğrulandı: gerçek Tor gönderimi sırasında yerel resolver'a sıfır DNS sorgusu ulaşır.
- **OCSP kapalı.** Aksi halde iptal denetimleri her TLS el sıkışmasında CA'ya clearnet HTTP isteği gönderirdi.
- **Update phone-home yok.** Uygulama + uzantı + GMP-manager URL'leri temizlendi.
- **Telemetri yok, Safebrowsing yok, captive-portal denetimi yok, remote content render yok.**
- **WebRTC yok, geolocation yok, DNS prefetch yok, predictor yok.**
- **Oturum-ortası koruma.** Prefler her TB başlangıcında ve sertleştirme aktifken periyodik olarak yeniden onaylanır. Üçüncü taraf bir sertleştirilmiş prefi değiştirirse, eklenti SOCKS endpoint'i bozmadan onarır.
- **Sertleştirme geri alınabilir.** İlk aktivasyondan önce snapshot alınır; Seçenekler sayfasındaki Devre Dışı Bırak düğmesi veya `disable-hardening` mesajı ile geri yüklenir.
- **Self-test canary** başlangıçta ve aktif sertleştirme sırasında: SOCKS5-RESOLVE (3 stream-izole Tor circuit) ile sistem resolver'ının tam yanıt kümesini karşılaştırır.
- **Gizliliği koruyan tanılama.** Loglar sayaçları, maskelenmiş IP'leri ve hata sınıflarını özetler — ham IP veya hesap tanımlayıcısı yok.
- **Pref-write allowlist** experiment API'de. Parent süreç keyfi pref yazamaz.

**Doğal sınırlar — OnionBird BUNU düzeltemez:**

1. **`Authentication-Results: ... smtp.auth=<sandığınız>@<sağlayıcı>`** sağlayıcının MTA'sı tarafından eklenir — kimlik doğrulamalı SMTP'nin doğal özelliği. *Geçici çözüm:* hassas yazışmalar için tek kullanımlık / takma adlı bir kutu kullanın.
2. **Tor exit IP'si alıcının `Received:` zincirinde görünür.** MTA'lar reverse-DNS yapar ve `tor-exit-107.digitalcourage.de` gibi isimler üretir. Alıcı "bu kullanıcı Tor üzerinden gönderdi" bilgisini öğrenir.
3. **OS düzeyinde sızıntılar** — diğer uygulamalardan hostname, NTP, swap, dosya sistemi zaman damgaları. Tails veya Whonix kullanın.
4. **Ağ korelasyonu** — Tor circuit'inin her iki ucunu gözleyen biri. Başlık hijyeni bunu yenmez.

Bu dört kategoriye girmeyen her şey politikanın **kapsamındadır**. Karşı örnek bulursanız P0 bug açın.

---

## mail-Tor manzarası

Tam karşılaştırma için [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature). Kısaca: OnionBird **normal bir Thunderbird eklentisidir** (Tails/Whonix gibi ayrı OS değil), **ampirik olarak doğrulanmış Tor DNS kapsaması**, **sürekli canary** ve **yapılandırılabilir Message-ID FQDN** ile (TorBirdy'deki supercluster `localhost.localdomain` yerine).

---


> ⚠️ **Tor için sertleştirilmiş bir OS ile yığınlayın** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## Yüklemeden önce

Eklenti Thunderbird **içinde** çalışanı sertleştirir. %100 Tor kapsamı için **OS resolver'ı** da Tor üzerinden gitmelidir:

- **Tails / Whonix workstation** — sistem DNS'i zaten Tor. `.xpi`'yi kurun, hazır.
- **Sistem Tor'lu standart Linux** — `/etc/tor/torrc`'a `DNSPort 5353` ekleyin ve `/etc/resolv.conf`'un ona ulaştığından emin olun.
- **Yalnızca Tor Browser bundle** — Tor `9050`'de değil `9150`'de dinler; eklenti proxy preflerini yazmadan önce mevcut prefi ve her iki yaygın yerel portu sondalar.
- **Uzak Tor/Whonix SOCKS** — hostname yerine IP literal kullanın (`10.152.152.10:9050`).
- **Sistem DNS'i Tor üzerinden olmayan standart masaüstü** — kendi sorumluluğunuzda kurun. Canary, yapılandırmayı Seçenekler sayfasında ve konsolda işaretler.

---

## Bugün ne yapıyor

- IMAP/SMTP'yi yerel SOCKS5 proxy üzerinden yönlendirir (varsayılan `127.0.0.1:9050`, yapılandırılabilir), `socks_remote_dns=true` ve `failover_direct=false` ile.
- Tanımlayıcı başlıkları normalize eder: `User-Agent` / `X-Mailer` bastırılır, `Message-ID` FQDN yapılandırılabilir (varsayılan From-domain), SMTP `HELO`/`EHLO` `[127.0.0.1]` olarak yeniden yazılır, `Date` UTC, `format=flowed` yok.
- Defense-in-depth: TRR=5, OCSP off, WebRTC yok, DNS prefetch yok, predictor yok, phone-home yok, telemetri yok, Safebrowsing yok, captive-portal yok, remote content yok.
- **SOCKS5-RESOLVE vs sistem DNS canary** başlangıçta ve periyodik.
- **Tor test mode** Seçenekler sayfasında.
- Seçenekler sayfası sistem/açık/koyu temayı, çok dilli UI'yi ve yerleşik Yardım'ı (TL;DR + nerd modu) destekler.
- İlk kurulumda otomatik etkinleşir. **Devre Dışı Bırak düğmesi** snapshot'ı geri yükler.
- Varsayılan olarak yalnızca **onion + loopback** SMTP sunucuları sertleştirilir (B-003) — mevcut clearnet hesaplarınız çalışmaya devam eder.
- Pre-startup sertleştirme için tamamlayıcı `user.js` + `prefs.js`'teki mevcut hesapları numaralandıran bir script.

---

## Mimari

OnionBird hibrittir: bir MailExtension background scripti UI ve message bus'ı sağlar, bir Experiments API modülü parent süreçte çalışır ve `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, ham SOCKS5 RESOLVE / RESOLVE_PTR ve `nsIDNSService.clearCache` manipülasyonunu açar. İki yarım `browser.onionbird.*` namespace üzerinden iletişir. Bkz. [docs/architecture.md](docs/architecture.md).

---

## Yol haritası / bilinen sınırlamalar

Bkz. [docs/follow-up.md](docs/follow-up.md). Sonraki yinelemelere ertelendi: mixed-mode UI toggle, ağ bağlantısı / resolver değişikliği hook, multi-circuit PTR retry, eklenti tarafından oluşturulan login etiketleme, first-run sihirbazı, sansürlenen ISP'ler için bridges / pluggable-transports, Tor control-port (gönderim başına NEWNYM), paketlenmiş cross-platform installer.

---

## Lisans

MPL-2.0. Tam metin için [LICENSE](LICENSE).

Yazılım OLDUĞU GİBİ sunulur, hiçbir garanti olmaksızın. Yazarlar, kullanımdan doğan deanonimizasyon veya başka zarardan sorumlu değildir. Tam feragatname için LICENSE.
