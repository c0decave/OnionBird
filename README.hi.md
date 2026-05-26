# OnionBird

**भाषाएँ:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · **हिन्दी** · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **अल्फा — देर का अल्फा, Tor-DNS-जागरूक OS पर leak-tight। इंस्टॉल करने से पहले [पूर्वापेक्षाएँ](#इंस्टॉल-करने-से-पहले) पढ़ें।**

> गुमनामी-महत्वपूर्ण उपयोग के लिए OnionBird पर भरोसा करने से पहले [खतरा मॉडल](docs/threat-model.md) और [follow-up सूची](docs/follow-up.md) पढ़ें।

OnionBird एक Thunderbird ऐड-ऑन है जो IMAP/SMTP को स्थानीय Tor प्रॉक्सी के माध्यम से रूट करता है और प्रेषकों को deanonymize करने के लिए ऐतिहासिक रूप से उपयोग किए गए मैसेज हेडर्स को हटाता या सामान्य करता है। लक्ष्य: Thunderbird 140 ESR। अनुरक्षित न रहे TorBirdy एक्सटेंशन (अंतिम रिलीज़ v0.2.6 2018 में; TB 78 में Legacy XUL हटाए जाने से बंद) के आधुनिक उत्तराधिकारी के रूप में बनाया गया।

वर्तमान संस्करण: **0.1.4**।

---

## 100% गोपनीयता और सुरक्षा नीति

प्रोजेक्ट का अधिदेश बाइनरी है: **कोई भी अवलोकनीय कोड पथ जो उपयोगकर्ता की पहचान, असली IP, hostname, locale, टाइम ज़ोन या यह तथ्य कि उपयोगकर्ता अपने मेल को हार्डन कर रहा है, को लीक करे, P0 दोष माना जाता है और रिलीज़ रोकता है।** "पर्याप्त अच्छा", "आमतौर पर काम करता है" या "लगभग कोई रिसाव नहीं" स्वीकार्य परिणाम नहीं हैं।

ठोस रूप से:

- **डिफ़ॉल्ट रूप से fail-closed।** `network.proxy.failover_direct = false` अनिवार्य — यदि कॉन्फ़िगर किया गया Tor प्रॉक्सी अप्राप्य हो तो भेजना विफल होना चाहिए। ऐड-ऑन कभी भी चुपचाप clearnet पर नहीं गिरता।
- **DNS केवल Tor के माध्यम से।** `socks_remote_dns = true`, `network.trr.mode = 5` (कोई समानांतर DoH नहीं), `network.dns.disablePrefetch = true`। प्रयोगात्मक रूप से सत्यापित: वास्तविक Tor-रूटेड भेजने के दौरान शून्य DNS queries स्थानीय resolver तक पहुँचती हैं।
- **OCSP बंद।** अन्यथा निरस्तीकरण जाँचें हर TLS handshake पर CA को एक clearnet HTTP अनुरोध भेजेंगी।
- **कोई अपडेट phone-home नहीं।** ऐप + एक्सटेंशन + GMP-manager URLs साफ़।
- **कोई टेलीमेट्री, Safebrowsing, captive-portal probe, remote content रेंडरिंग नहीं।**
- **कोई WebRTC, geolocation, DNS prefetch, predictor नहीं।**
- **मध्य-सत्र सुरक्षा।** हर TB स्टार्टअप पर और हार्डनिंग सक्रिय रहने पर समय-समय पर prefs पुनः-पुष्ट होती हैं।
- **हार्डनिंग प्रतिवर्ती है।** पहली बार सक्षम करने से पहले snapshot लिया जाता है; Options पेज के Disable बटन या `disable-hardening` संदेश के माध्यम से बहाल किया जा सकता है।
- **Self-test canary** स्टार्टअप पर और सक्रिय हार्डनिंग के दौरान: SOCKS5-RESOLVE (3 stream-isolated Tor circuits) की पूरी सिस्टम-resolver उत्तर सेट से तुलना करता है।
- **गोपनीयता-सुरक्षित निदान।** लॉग संख्याओं, मास्क की गई IPs और त्रुटि वर्गों का सारांश देते हैं — कोई कच्ची IP या खाता पहचानकर्ता नहीं।
- **experiment API में pref-write allowlist।**

**अंतर्निहित सीमाएँ — OnionBird इन्हें ठीक नहीं कर सकता:**

1. **`Authentication-Results: ... smtp.auth=<आपका-मेलबॉक्स>@<प्रदाता>`** प्रदाता के MTA द्वारा जोड़ा जाता है — प्रत्येक प्राप्तकर्ता को प्रमाणित मेलबॉक्स प्रकट करता है। *समाधान:* संवेदनशील पत्राचार के लिए डिस्पोज़ेबल / pseudonymous मेलबॉक्स उपयोग करें।
2. **Tor exit IP प्राप्तकर्ता की `Received:` श्रृंखला में दिखाई देता है।** MTA reverse-DNS करता है और `tor-exit-107.digitalcourage.de` जैसे नाम बनाता है। प्राप्तकर्ता सीखता है "इस उपयोगकर्ता ने Tor से भेजा"।
3. **OS-स्तर लीक** — अन्य ऐप्स से hostname प्रकटन, NTP, swap, फ़ाइलसिस्टम टाइमस्टैम्प। Tails या Whonix उपयोग करें।
4. **नेटवर्क-सहसंबंध** — Tor circuit के दोनों छोर देखने वाला। हेडर स्वच्छता द्वारा पराजित नहीं।

इन चार श्रेणियों में नहीं आने वाली सब कुछ नीति के **दायरे में** है। यदि प्रति-उदाहरण मिले तो P0 बग दर्ज करें।

---

## mail-Tor परिदृश्य

पूर्ण तुलना के लिए देखें [README.md (EN)](README.md#onionbird-vs-torbirdy--feature-by-feature)। संक्षेप में: OnionBird एक **सामान्य Thunderbird ऐड-ऑन है** (Tails/Whonix जैसा अलग OS नहीं), **प्रयोगात्मक रूप से सत्यापित DNS-via-Tor कवरेज**, **निरंतर canary** और **कॉन्फ़िगर करने योग्य Message-ID FQDN** (TorBirdy के supercluster `localhost.localdomain` के बजाय) के साथ।

---


> ⚠️ **Tor-कठोर OS के साथ स्टैक करें** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

## इंस्टॉल करने से पहले

ऐड-ऑन Thunderbird के **अंदर** चलने वाली चीज़ को हार्डन करता है। 100% Tor कवरेज के लिए **OS resolver** को भी Tor से होकर जाना चाहिए:

- **Tails / Whonix workstation** — सिस्टम DNS पहले से Tor है। `.xpi` इंस्टॉल करें, बस।
- **सिस्टम Tor के साथ मानक Linux** — अपनी `/etc/tor/torrc` में `DNSPort 5353` जोड़ें और सुनिश्चित करें कि `/etc/resolv.conf` उस तक पहुँचता है।
- **केवल Tor Browser bundle** — Tor `9150` पर सुनता है, `9050` पर नहीं; ऐड-ऑन proxy prefs लिखने से पहले मौजूदा pref और दोनों सामान्य पोर्ट probe करता है।
- **दूरस्थ Tor/Whonix SOCKS** — IP literal (`10.152.152.10:9050`) उपयोग करें, hostname नहीं।
- **सिस्टम DNS via Tor के बिना मानक डेस्कटॉप** — अपने जोखिम पर इंस्टॉल करें। canary कॉन्फ़िगरेशन को Options पेज और कंसोल में फ़्लैग करेगा।

---

## आज क्या करता है

- IMAP/SMTP को स्थानीय SOCKS5 प्रॉक्सी (डिफ़ॉल्ट `127.0.0.1:9050`, कॉन्फ़िगर करने योग्य) के माध्यम से `socks_remote_dns=true` और `failover_direct=false` के साथ रूट करता है।
- पहचान वाले हेडर्स को सामान्य करता है: `User-Agent` / `X-Mailer` दबाए, `Message-ID` का FQDN कॉन्फ़िगर करने योग्य (डिफ़ॉल्ट = आपका From-domain), SMTP `HELO`/`EHLO` को `[127.0.0.1]` के रूप में पुनः लिखा, `Date` UTC, कोई `format=flowed` नहीं।
- Defense-in-depth: TRR=5, OCSP off, कोई WebRTC नहीं, कोई DNS prefetch नहीं, कोई predictor नहीं, कोई phone-home नहीं, कोई टेलीमेट्री नहीं, कोई Safebrowsing नहीं, कोई captive-portal नहीं, कोई remote content नहीं।
- **SOCKS5-RESOLVE vs सिस्टम DNS canary** स्टार्टअप पर और समय-समय पर।
- Options पेज पर **Tor test mode**।
- Options पेज सिस्टम/लाइट/डार्क थीम, बहुभाषी UI और बिल्ट-इन Help (TL;DR + Nerd मोड) का समर्थन करता है।
- पहली इंस्टॉल पर ऑटो-सक्षम। **Disable बटन** snapshot बहाल करता है।
- डिफ़ॉल्ट रूप से केवल **onion + loopback** SMTP सर्वर हार्डन होते हैं (B-003) — आपके मौजूदा clearnet खाते सामान्य रूप से काम करते रहते हैं।

---

## आर्किटेक्चर

OnionBird हाइब्रिड है: एक MailExtension background script सार्वजनिक API सतह प्रदान करता है, और एक Experiments API मॉड्यूल parent प्रक्रिया में चलता है और `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, कच्चा SOCKS5 RESOLVE / RESOLVE_PTR और `nsIDNSService.clearCache` हेरफेर को उजागर करता है। दोनों आधे `browser.onionbird.*` namespace के माध्यम से संवाद करते हैं। देखें [docs/architecture.md](docs/architecture.md)।

---

## रोडमैप / ज्ञात सीमाएँ

देखें [docs/follow-up.md](docs/follow-up.md)। स्थगित: mixed-mode UI toggle, नेटवर्क-लिंक / resolver परिवर्तन hook, multi-circuit PTR retry, ऐड-ऑन द्वारा बनाए logins की टैगिंग, first-run wizard, सेंसर वाले ISPs के लिए bridges / pluggable-transports, Tor control-port एकीकरण (प्रति-भेज NEWNYM), पैक किया गया क्रॉस-प्लेटफ़ॉर्म installer।

---

## लाइसेंस

MPL-2.0। पूर्ण पाठ के लिए [LICENSE](LICENSE) देखें।

सॉफ़्टवेयर जैसा है, किसी भी प्रकार की वारंटी के बिना प्रदान किया जाता है। लेखक उपयोग से उत्पन्न deanonymization या अन्य नुकसान के लिए ज़िम्मेदार नहीं हैं। पूर्ण अस्वीकरण के लिए LICENSE देखें।
