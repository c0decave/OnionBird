# OnionBird

**Idiomas:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · **Português** · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **ALPHA — alfa tardia, à prova de vazamentos em SO com DNS por Tor. Leia [os pré-requisitos](#antes-de-instalar) antes de instalar.**

> Leia [o modelo de ameaça](docs/threat-model.md) e a [lista de follow-up](docs/follow-up.md) antes de confiar em OnionBird para uso crítico para anonimato.

OnionBird é uma extensão do Thunderbird que encaminha IMAP/SMTP por um proxy Tor local e remove ou normaliza cabeçalhos de mensagem historicamente usados para desanonimizar remetentes. Alvo: Thunderbird 140 ESR. Pensado como sucessor moderno da extensão TorBirdy não mantida (último lançamento v0.2.6 em 2018, morta pela remoção do Legacy XUL no TB 78).

Versão atual da extensão: **0.1.4**.

---

## Política 100% de privacidade e segurança

O mandato do projeto é binário: **qualquer caminho de código observável que vaze identidade do utilizador, IP real, hostname, locale, fuso horário, ou o facto de o utilizador estar a endurecer o seu correio é considerado defeito P0 e bloqueia o lançamento.** "Bom o suficiente", "geralmente funciona" ou "quase sem fuga" não são resultados aceitáveis.

Concretamente:

- **Fail closed por padrão.** `network.proxy.failover_direct = false` é forçado — se o proxy Tor configurado estiver inacessível, o envio falha. A extensão NUNCA recai silenciosamente para clearnet.
- **DNS apenas por Tor.** `socks_remote_dns = true`, `network.trr.mode = 5` (sem DoH paralelo), `network.dns.disablePrefetch = true`. Verificado empiricamente: zero queries DNS chegam ao resolver local durante um envio real via Tor.
- **OCSP desligado.** Verificações de revogação fariam senão um pedido HTTP clearnet à CA em cada TLS handshake.
- **Sem phone-home de updates.** URLs de app + extensões + GMP-manager limpas.
- **Sem telemetria, sem Safebrowsing, sem sondas de captive-portal, sem renderização de conteúdo remoto.**
- **Sem WebRTC, sem geolocalização, sem DNS prefetch, sem predictor.**
- **Proteção mid-session.** As prefs são reafirmadas a cada arranque do TB e periodicamente enquanto o endurecimento está ativo. Se um terceiro mudar uma pref endurecida, a extensão repara sem sobrescrever o endpoint SOCKS detetado.
- **O endurecimento é reversível.** Snapshot tirado antes da primeira ativação, restaurável via botão Desativar da página Opções ou mensagem `disable-hardening`.
- **Self-test canary** no arranque e durante o endurecimento ativo: compara SOCKS5-RESOLVE (3 circuitos Tor isolados por stream) com o conjunto completo da resposta do resolver do sistema. Cada IP pública do sistema deve ser vista via Tor ou confirmada por PTR via Tor como sendo exatamente o host canary ou um subdomínio; sufixos públicos partilhados como `co.uk` nunca são aceites como prova.
- **Diagnóstico que respeita a privacidade.** Logs e mensagens da consola resumem contagens, IPs mascarados e classes de erro — sem IPs brutos nem identificadores de conta.
- **Allowlist de escritas de prefs** na API experiment. A superfície parent não pode escrever prefs arbitrárias (`browser.startup.*`, `devtools.*`, etc. recusadas) — limita o raio de uma futura regressão de handler.

**Limites inerentes — OnionBird NÃO PODE corrigir:**

1. **`Authentication-Results: ... smtp.auth=<sua-caixa>@<provedor>`** é adicionado pelo MTA do provedor na saída — revela a cada destinatário a caixa autenticada. Inerente ao SMTP autenticado. *Contorno:* use uma caixa descartável / pseudónima para correspondência sensível.
2. **O IP de saída Tor aparece na cadeia `Received:` do destinatário.** Os MTAs fazem reverse-DNS do IP de origem e emitem nomes como `tor-exit-107.digitalcourage.de`. O destinatário aprende "este utilizador enviou via Tor". Inerente ao transporte SMTP.
3. **Fugas ao nível do SO** — divulgação de hostname por outras apps, fugas NTP, swap files, timestamps no filesystem. Use Tails ou Whonix.
4. **Correlação de rede** — observadores em ambas as pontas de um circuito Tor. Não é derrotado por higiene de cabeçalhos.

Tudo o que não cair nestas quatro categorias está **no âmbito**. Abra um bug P0 se encontrar um contraexemplo.

---

## Paisagem de mail-Tor — como OnionBird se compara

Não existe um único projeto "mail-Tor". Vários esforços sobrepõem-se a OnionBird em camadas diferentes; aqui está o que partilham e o que distingue OnionBird.

| Projeto | Camada | Routing Tor | Higiene de headers | Mantido? | Mesmo SO? |
|---|---|---|---|---|---|
| **OnionBird** (este) | extensão Thunderbird | sim (SOCKS5 + remoteDNS) | sim (todos os vetores históricos fechados; canary deteta novos) | sim (2026-) | sim |
| TorBirdy | extensão TB | sim | sim | não (último 2018, partido desde TB 78) | sim |
| Tor Mail (legacy) | webmail .onion | n/a | n/a | encerrado 2013 (saída FH) | n/a |
| Mailpile (modo Tor) | cliente local | opcional | parcial | última versão 2020 | sim |
| ProtonMail via Tor | webmail | sim (`.onion` v3) | headers controlados pelo provedor | sim | apenas browser |
| Riseup / Disroot / Cock.li | provedores com .onion | sim (você routa via Tor) | dependente do cliente | sim | depende do MUA |

> ⚠️ **Empilhe com um SO Tor-endurecido** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.


**Onde OnionBird é único:**

1. **Uma extensão Thunderbird normal, não um SO separado.** Tails e Whonix são o padrão-ouro mas requerem boot ou VM separados. OnionBird assume que já tem Tor a correr (ou está em Tails/Whonix) e endurece o comportamento do TB dentro desse ambiente.
2. **Verificado empiricamente end-to-end.** Suite local: 5 smoke + 148 integration (1 skip esperado), 7+ cenários com Tor real contra `undisclose.de` e auditoria de cabeçalhos byte-a-byte (H1–H15). O `dns-trap` regista cada query DNS que o TB faz durante um envio real — 0 queries para o host SMTP/IMAP.
3. **Canary contínuo.** Corre no arranque do TB e periodicamente; compara 3 circuitos Tor isolados por stream com o conjunto completo do resolver do sistema, e exige que cada IP pública divergente seja PTR-confirmada via Tor como sendo o host alvo ou um subdomínio.
4. **Sem Message-ID supercluster.** Ferramentas anteriores (em particular TorBirdy) usavam `Message-ID: <uuid@localhost.localdomain>` — uma impressão digital global distinta. OnionBird faz por padrão o domínio do From (combina com o `d=` do DKIM); configurável via Opções para `localhost`, `localhost.localdomain` ou personalizado.
5. **Configurável, não dogmático.** TorBirdy era pegar-ou-largar. OnionBird deixa-o ativar/desativar o endurecimento, escolher porta SOCKS (Tor sistema 9050, Tor Browser 9150, workstation Whonix `10.152.152.10:9050`) e escolher a estratégia de FQDN do Message-ID.

**Onde OnionBird NÃO é substituto:**

- NÃO substitui Tails / Whonix para isolamento ao nível do SO.
- NÃO routa o tráfego de OUTRAS aplicações via Tor.
- NÃO impede o destinatário de saber que usou Tor (vê o IP de saída no `Received:`).
- NÃO esconde a identidade da caixa autenticada dos destinatários (inerente a SMTP-AUTH).

---

## Antes de instalar

A extensão endurece o que corre **dentro** do Thunderbird. Para cobertura Tor a 100%, o **resolver do SO** também tem de passar por Tor. Escolha o caminho conforme o seu ambiente:

- **Tails / workstation Whonix** — DNS do sistema já é Tor. Instale o `.xpi`, está feito.
- **Linux normal com Tor sistema** — adicione `DNSPort 5353` ao seu `/etc/tor/torrc` e garanta que `/etc/resolv.conf` chega lá (um `dnsmasq`/`unbound` local a reencaminhar para `127.0.0.1:5353` é o padrão).
- **Apenas Tor Browser bundle** — Tor escuta em `9150`, não `9050`; a extensão sonda prefs existentes e ambos os portos comuns antes de escrever as prefs de proxy.
- **SOCKS Tor/Whonix remoto** — use um literal IP como `10.152.152.10:9050`, não hostname. A extensão ignora intencionalmente endpoints SOCKS com hostname.
- **Desktop normal sem DNS sistema via Tor** — instale por sua conta e risco. O canary sinaliza a configuração na página Opções e na consola.

---

## O que faz hoje

- Routa IMAP/SMTP por um proxy SOCKS5 local (por padrão `127.0.0.1:9050`, configurável) com `socks_remote_dns=true` e `failover_direct=false`. Ativar sonda a pref SOCKS existente, Tor sistema `9050` e Tor Browser `9150`; reafirmações no arranque/periódicas preservam o endpoint atual apenas se for loopback ou literal IP.
- Normaliza cabeçalhos identificadores em saída: `User-Agent` / `X-Mailer` suprimidos, FQDN do `Message-ID` configurável (default = seu From-domain), `HELO`/`EHLO` SMTP reescritos para `[127.0.0.1]`, `Date` UTC via `privacy.resistFingerprinting`, sem `format=flowed`.
- Endurecimento defesa-em-profundidade: TRR=5, OCSP off, sem WebRTC, sem DNS prefetch, sem predictor, sem update phone-home, sem telemetria, sem Safebrowsing, sem sondas captive-portal, sem renderização de conteúdo remoto.
- **Canary SOCKS5-RESOLVE vs DNS do sistema** no arranque e periodicamente.
- Logging que respeita privacidade: IPs/PTR do canary e identificadores de conta mascarados por padrão.
- **Modo de teste Tor** na página Opções.
- Página Opções com tema sistema/claro/escuro, strings UI multi-idioma e Ajuda integrada (TL;DR + modo Nerd).
- Ativa automaticamente na primeira instalação. **Botão Desativar** restaura o snapshot.
- Por padrão, apenas servidores SMTP **onion + loopback** são endurecidos (B-003) — as suas contas clearnet existentes continuam a funcionar.
- `user.js` complementar para endurecimento pré-arranque + script que enumera contas existentes em `prefs.js`.

---

## Início rápido

```sh
# Build do .xpi (MV2, canónico)
make build

# Opcional: build MV3 paralelo
make build-mv3

# Iniciar pod de teste
make COMPOSE_ENGINE=docker test-up

# Correr suite de integração (148 testes a 0.1.4)
make COMPOSE_ENGINE=docker test-integration

# Desmontar
make COMPOSE_ENGINE=docker test-down
```

### Assinatura para ATN

Ver [docs/atn-signing.md](docs/atn-signing.md) — requer credenciais Mozilla developer.

---

## Arquitetura

OnionBird é híbrido: um script de background MailExtension fornece a superfície de API pública (página opções, auto-ativação na instalação, bus de mensagens enable/disable, self-test periódico), enquanto um módulo Experiments API corre no processo parent e expõe `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, SOCKS5 RESOLVE / RESOLVE_PTR brutos e manipulação de `nsIDNSService.clearCache`. As duas metades comunicam pelo namespace personalizado `browser.onionbird.*`.

Ver [docs/architecture.md](docs/architecture.md) para diagrama.

---

## Roadmap / limitações conhecidas

Ver [docs/follow-up.md](docs/follow-up.md) para a lista completa priorizada. Diferido para iterações futuras: toggle UI mixed-mode, hook em mudanças de link de rede / resolver, retry PTR multi-circuito, tagging de logins criados pela extensão, assistente first-run, bridges / pluggable-transports para ISPs censurados, integração Tor control-port (NEWNYM por envio), instalador cross-platform empacotado.

---

## Licença

MPL-2.0. Ver [LICENSE](LICENSE) para o texto completo.

Este software é fornecido COMO ESTÁ, sem garantia de qualquer tipo. Os autores não são responsáveis por qualquer desanonimização ou outros danos resultantes da sua utilização. Ver LICENSE para o disclaimer completo.
