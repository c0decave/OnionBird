# OnionBird

**Langues:** [English](README.md) · [Deutsch](README.de.md) · **Français** · [Português](README.pt.md) · [Español](README.es.md) · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **BETA — alpha tardive, étanche aux fuites sur un OS avec DNS via Tor. Lisez [les prérequis](#avant-dinstaller) avant d’installer.**

> Lisez [le modèle de menace](docs/threat-model.md) et la [liste de suivi](docs/follow-up.md) avant de confier à OnionBird un usage critique pour l’anonymat.

OnionBird est une extension Thunderbird qui route IMAP/SMTP via un proxy Tor local et qui supprime ou normalise les en-têtes de message historiquement utilisés pour désanonymiser l’expéditeur. Cible : Thunderbird 140 ESR. Conçu comme le successeur moderne de l’extension TorBirdy non maintenue (dernière version v0.2.6 en 2018, tuée par le retrait de Legacy XUL dans TB 78).

Version actuelle de l’extension : **0.1.4**.

---

## Politique 100 % confidentialité et sécurité

Le mandat du projet est binaire : **toute trajectoire de code observable qui laisse fuir l’identité de l’utilisateur, son IP réelle, son hostname, sa langue, son fuseau horaire, ou le fait même qu’il durcit son courrier est un défaut P0 et bloque la sortie.** « Suffisamment bon », « ça marche en général » ou « presque aucune fuite » ne sont pas des résultats acceptables.

Concrètement :

- **Fail closed par défaut.** `network.proxy.failover_direct = false` est forcé — si le proxy Tor configuré est injoignable, l’envoi échoue. L’extension ne tombe JAMAIS silencieusement en clearnet.
- **DNS uniquement via Tor.** `socks_remote_dns = true`, `network.trr.mode = 5` (pas de DoH parallèle), `network.dns.disablePrefetch = true`. Vérifié empiriquement : zéro requête DNS atteint le résolveur local pendant un envoi via Tor.
- **OCSP désactivé.** Les vérifications de révocation déclencheraient sinon une requête HTTP clearnet vers l’AC à chaque handshake TLS.
- **Pas de phone-home pour les mises à jour.** URLs app + extensions + GMP-manager vidées.
- **Pas de télémétrie, pas de Safebrowsing, pas de sondes captive-portal, pas de rendu de contenu distant.**
- **Ni WebRTC, ni géolocalisation, ni DNS prefetch, ni predictor.**
- **Protection mid-session.** Les prefs sont ré-affirmées à chaque démarrage de TB et périodiquement pendant que le durcissement est actif. Si un tiers modifie une pref durcie, l’extension la répare sans écraser l’endpoint SOCKS détecté.
- **Le durcissement est réversible.** Un instantané est pris avant la première activation, restaurable via le bouton Désactiver de la page Options ou le message `disable-hardening`.
- **Canary self-test** au démarrage et pendant le durcissement actif : compare SOCKS5-RESOLVE (3 circuits Tor isolés en stream) à l’ensemble complet des réponses du résolveur système. Chaque IP publique du système doit être vue via Tor ou confirmée par PTR via Tor comme étant exactement l’hôte canary ou un sous-domaine ; les suffixes publics partagés (par ex. `co.uk`) ne sont jamais acceptés comme preuve.
- **Diagnostic respectant la vie privée.** Les logs et messages console résument compteurs, IPs masquées et classes d’erreur — pas d’IPs brutes ni d’identifiants de comptes.
- **Allowlist d’écritures de prefs** dans l’API experiment. La surface parent ne peut pas écrire de prefs arbitraires (`browser.startup.*`, `devtools.*`, etc. sont refusées) — limite la portée d’une éventuelle régression future.

**Limites inhérentes — OnionBird NE PEUT PAS corriger :**

1. **`Authentication-Results: ... smtp.auth=<votre-boîte>@<fournisseur>`** est ajouté par le MTA du fournisseur en sortie ; il divulgue à chaque destinataire la boîte avec laquelle vous vous êtes authentifié. Inhérent au SMTP authentifié. *Contournement :* utiliser une boîte jetable / pseudonyme pour les correspondances sensibles.
2. **L’IP de sortie Tor apparaît dans la chaîne `Received:` du destinataire.** Les MTAs effectuent un reverse-DNS sur l’IP entrante (`tor-exit-107.digitalcourage.de`, etc.). Le destinataire apprend « cet utilisateur a envoyé via Tor ». Inhérent au transport SMTP.
3. **Fuites au niveau OS** — hostname divulgué par d’autres apps, fuites NTP, fichiers de swap, horodatages du système de fichiers. Utilisez Tails ou Whonix.
4. **Corrélation réseau** — un adversaire qui observe les deux extrémités d’un circuit Tor. Non vaincu par l’hygiène des en-têtes.

Tout ce qui ne tombe pas dans ces quatre catégories est **dans le périmètre**. Ouvrez un bug P0 si vous trouvez un contre-exemple.

---

## Paysage mail-Tor — comment OnionBird se positionne

Il n’existe pas un unique projet « mail Tor ». Plusieurs efforts couvrent les mêmes couches que OnionBird ; voici ce qu’ils ont en commun et ce qui distingue OnionBird.

| Projet | Couche | Routage Tor | Hygiène d’en-têtes | Maintenu ? | Même OS ? |
|---|---|---|---|---|---|
| **OnionBird** (ici) | extension Thunderbird | oui (SOCKS5 + remoteDNS) | oui (tous les vecteurs historiques fermés ; canary détecte les nouveaux) | oui (2026-) | oui |
| TorBirdy | extension TB | oui | oui | non (dernière version 2018, cassé depuis TB 78) | oui |
| Tor Mail (legacy, `.onion`) | webmail .onion | n/a | n/a | fermé en 2013 (saisie FH) | n/a |
| Mailpile (mode Tor) | client local | optionnel | partiel | dernière version 2020 | oui |
| ProtonMail via Tor | webmail | oui (`.onion` v3) | en-têtes côté fournisseur | oui | navigateur uniquement |
| Riseup / Disroot / Cock.li | fournisseurs avec .onion | oui (vous routez via Tor) | dépend du client | oui | dépend du MUA |

> ⚠️ **Empilez avec un OS Tor-durci** — OnionBird → Thunderbird; [Tails](https://tails.net/) / [Whonix](https://www.whonix.org/) → OS-level isolation.

**Ce qu’elles ont en commun :** routage via Tor, reconnaissance que le simple routage ne suffit pas, et nécessité d’un OS qui ne fuit pas DNS / NTP / hostname hors bande.

**Ce qui distingue OnionBird :**

1. **Une extension Thunderbird normale, pas un OS séparé.** Tails et Whonix restent l’étalon-or, mais nécessitent un démarrage ou une VM séparés. OnionBird part du principe que vous avez déjà Tor en cours (ou que vous êtes sur Tails/Whonix) et durcit le comportement de TB dans cet environnement.
2. **Vérification empirique de bout en bout.** Suite locale : 5 smoke tests et 148 tests d’intégration (1 skip prévu), plus 7+ scénarios avec un vrai Tor sur `undisclose.de` et un audit en-têtes octet-par-octet (H1–H15). Le `dns-trap` du stack de tests enregistre *chaque* requête DNS faite par TB pendant un envoi réel — 0 requête observée pour l’hôte SMTP/IMAP.3. **Canary continu.** Démarre au lancement de TB et tourne périodiquement ; compare 3 circuits Tor isolés en stream à l’ensemble complet du résolveur système, et exige que chaque IP publique divergente soit confirmée par PTR via Tor comme étant l’hôte cible ou un sous-domaine. Expose la suspicion de fuite à l’utilisateur au lieu de « faire confiance » à l’extension.
4. **Pas de Message-ID supercluster.** Les anciens outils mail-Tor (TorBirdy surtout) utilisaient `Message-ID: <uuid@localhost.localdomain>` — une empreinte globale distinctive. OnionBird utilise par défaut le domaine de l’adresse From (correspond au `d=` DKIM, se fond avec les utilisateurs normaux du fournisseur) ; configurable via la page Options en `localhost`, `localhost.localdomain` ou personnalisé.
5. **Configurable, pas dogmatique.** TorBirdy était à prendre ou à laisser. OnionBird vous laisse activer/désactiver le durcissement, choisir votre port SOCKS (Tor système 9050, Tor Browser bundle 9150, Whonix workstation `10.152.152.10:9050`) et choisir la stratégie de FQDN Message-ID.

**Ce que OnionBird N’EST PAS un remplaçant pour :**

- Il ne remplace PAS Tails / Whonix pour l’isolation OS.
- Il ne route PAS le trafic d’AUTRES applications via Tor.
- Il n’EMPÊCHE PAS le destinataire de savoir que vous avez utilisé Tor (il voit l’IP de sortie Tor dans `Received:`).
- Il ne CACHE PAS votre identité de boîte authentifiée aux destinataires (inhérent à SMTP-AUTH).

---

## Avant d'installer

L’extension durcit ce qui tourne **dans** Thunderbird. Pour une couverture Tor à 100 %, le **résolveur de l’OS** doit aussi passer par Tor. Choisissez le scénario qui correspond à votre environnement :

- **Tails / station Whonix** — le DNS système passe déjà par Tor. Installez le `.xpi`, c’est tout.
- **Linux standard avec Tor système** — ajoutez `DNSPort 5353` à votre `/etc/tor/torrc` et faites pointer `/etc/resolv.conf` vers lui (un `dnsmasq`/`unbound` local qui redirige vers `127.0.0.1:5353` est le pattern standard).
- **Tor Browser bundle uniquement** — Tor écoute sur `9150` et non `9050` ; l’extension sonde la pref existante puis les deux ports locaux courants avant d’écrire les prefs de proxy. Les ré-affirmations ultérieures préservent ce endpoint.
- **SOCKS Tor/Whonix distant** — utilisez une IP littérale comme `10.152.152.10:9050`, pas un hostname. L’extension ignore volontairement les endpoints SOCKS valant un hostname, car résoudre ce hostname serait une requête DNS locale avant Tor.
- **Desktop sans DNS système via Tor** — installez à vos risques. Le canary signalera la configuration sur la page Options et dans la console.

---

## Ce que ça fait aujourd’hui

- Route IMAP/SMTP via un proxy SOCKS5 local (par défaut `127.0.0.1:9050`, configurable) avec `socks_remote_dns=true` et `failover_direct=false`. Activer sonde la pref SOCKS existante, Tor système `9050`, puis Tor Browser `9150` ; les ré-affirmations au démarrage et périodiques préservent l’endpoint courant uniquement s’il est loopback ou IP littérale.
- Normalise les en-têtes identifiants en sortie : `User-Agent` / `X-Mailer` supprimés, FQDN de `Message-ID` configurable (par défaut votre From-domain), `HELO`/`EHLO` SMTP réécrits en `[127.0.0.1]`, `Date` en UTC via `privacy.resistFingerprinting`, pas de `format=flowed`.
- Durcissement défense-en-profondeur : TRR=5, OCSP off, pas de WebRTC, pas de DNS prefetch, pas de predictor, pas de phone-home update, pas de télémétrie, pas de Safebrowsing, pas de sondes captive-portal, pas de rendu de contenu distant.
- **Canary SOCKS5-RESOLVE vs DNS système** au démarrage et périodiquement.
- Logs respectant la vie privée : par défaut, les IPs/PTR du canary et les identifiants de compte sont masqués.
- **Mode test Tor** sur la page Options.
- Page Options avec thème système/clair/sombre, chaînes UI multi-langues et Aide intégrée (TL;DR + mode Nerd).
- S’auto-active à la première installation. **Bouton Désactiver** restaure le snapshot.
- Par défaut, seuls les serveurs SMTP **onion + loopback** sont durcis (B-003) — vos comptes clearnet existants continuent à fonctionner.
- `user.js` compagnon pour un durcissement pré-démarrage + un script qui énumère vos comptes existants dans `prefs.js` et émet les lignes par serveur correspondantes.

---

## Démarrage rapide

```sh
# Build le .xpi (MV2, canonique)
make build

# Optionnel : build MV3 en parallèle pour smoke forward-compat
make build-mv3

# Démarrer le pod de test (Tor+DNSPort + aiosmtpd + DNS-forwarder + Xvfb+TB + runner)
make COMPOSE_ENGINE=docker test-up

# Lancer la suite d’intégration (148 tests en 0.1.4)
make COMPOSE_ENGINE=docker test-integration

# Démontage
make COMPOSE_ENGINE=docker test-down
```

### Signature pour l’ATN

Voir [docs/atn-signing.md](docs/atn-signing.md) — nécessite des identifiants Mozilla developer.

---

## Architecture

OnionBird est hybride : un script d’arrière-plan MailExtension fournit la surface API publique (page options, auto-activation à l’installation, bus de messages enable/disable, self-test périodique), tandis qu’un module Experiments API tourne dans le processus parent et expose `Services.prefs`, `MailServices.outgoingServer`, `MailServices.accounts`, SOCKS5 RESOLVE / RESOLVE_PTR bruts, et la manipulation de `nsIDNSService.clearCache`. Les deux moitiés communiquent par l’espace de noms personnalisé `browser.onionbird.*`.

Voir [docs/architecture.md](docs/architecture.md) pour un diagramme.

---

## Roadmap / limitations connues

Voir [docs/follow-up.md](docs/follow-up.md) pour la liste complète priorisée. Reportés à des itérations futures : toggle UI mixed-mode, hook sur changement de lien réseau / résolveur, retry PTR multi-circuits, marquage des logins créés par l’add-on, assistant first-run, bridges / pluggable-transports pour FAI censurés, intégration Tor control-port (NEWNYM par envoi), installateur cross-platform packagé.

---

## Licence

MPL-2.0. Voir [LICENSE](LICENSE) pour le texte complet.

Ce logiciel est fourni TEL QUEL sans garantie d’aucune sorte. Les auteurs ne sont pas responsables d’une éventuelle désanonymisation ou d’autres préjudices résultant de son usage. Voir LICENSE pour le disclaimer complet.
