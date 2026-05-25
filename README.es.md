# OnionBird

**Idiomas:** [English](README.md) · [Deutsch](README.de.md) · [Français](README.fr.md) · [Português](README.pt.md) · **Español** · [Polski](README.pl.md) · [Українська](README.uk.md) · [Русский](README.ru.md) · [Беларуская](README.be.md) · [Türkçe](README.tr.md) · [فارسی](README.fa.md) · [العربية](README.ar.md) · [עברית](README.he.md) · [Kurdî](README.ku.md) · [اردو](README.ur.md) · [پښتو](README.ps.md) · [ئۇيغۇرچە](README.ug.md) · [हिन्दी](README.hi.md) · [বাংলা](README.bn.md) · [简体中文](README.zh-CN.md) · [བོད་ཡིག](README.bo.md) · [Tiếng Việt](README.vi.md) · [ภาษาไทย](README.th.md) · [မြန်မာ](README.my.md) · [Bahasa Indonesia](README.id.md) · [Afrikaans](README.af.md) · [Kiswahili](README.sw.md) · [አማርኛ](README.am.md) · [ትግርኛ](README.ti.md) · [ქართული](README.ka.md)

> **ALFA — alfa avanzada, hermético ante fugas en sistemas con DNS por Tor. Lee [los requisitos previos](#antes-de-instalar) antes de instalar.**

> Lee el [modelo de amenazas](docs/threat-model.md) y la
> [lista de seguimiento](docs/follow-up.md) antes de confiar en él
> para usos críticos de anonimato.

OnionBird es un complemento de Thunderbird que enruta IMAP/SMTP a
través de un proxy Tor local y elimina o normaliza cabeceras
históricamente usadas para desanonimizar remitentes. Soporta
Thunderbird **128+** (manifest `strict_min_version: 128.0`); objetivo
principal de integración es la línea **Thunderbird 140 ESR**. Pensado
como sucesor moderno de la extensión TorBirdy (sin mantenimiento;
última versión v0.2.6 en 2018, rota tras la eliminación de Legacy XUL
en TB 78).

Versión actual del complemento: **0.1.1**.

---

## Política de Privacidad y Seguridad al 100%

El mandato del proyecto OnionBird es binario: **toda ruta de código
observable que filtre la identidad del usuario, la IP real, el nombre
de host, el locale, la zona horaria o el hecho de que el usuario está
endureciendo su correo se considera un defecto P0 y bloquea el
release.** "Suficientemente bueno", "normalmente funciona" o "casi
sin fugas" no son resultados aceptables.

En concreto significa:

- **Falla cerrado por defecto.** `network.proxy.failover_direct =
  false` se fuerza — si el proxy Tor configurado no es accesible, el
  envío falla. El complemento **JAMÁS** degrada silenciosamente a
  clearnet.
- **DNS solo a través de Tor.** `network.proxy.socks_remote_dns =
  true`, `network.trr.mode = 5` (sin DoH paralelo),
  `network.dns.disablePrefetch = true`. Verificado empíricamente: cero
  consultas DNS llegan al resolver local durante envíos reales por Tor.
- **OCSP apagado.** De lo contrario cada handshake TLS dispara una
  petición HTTP clearnet a la CA.
- **Sin phone-home de actualizaciones.** URLs de app + extensiones +
  GMP-manager vaciadas.
- **Sin telemetría, sin Safebrowsing, sin sondas de captive-portal,
  sin renderizado de contenido remoto.**
- **Sin WebRTC, sin geolocalización, sin DNS-prefetch, sin predictor.**
- **Protección durante la sesión.** Las prefs se vuelven a aplicar en
  cada arranque de TB y periódicamente mientras el hardening está
  activo. Si un tercero cambia una pref endurecida, el complemento la
  repara sin sobrescribir el endpoint SOCKS detectado.
- **El hardening es reversible.** Snapshot tomado antes del primer
  Enable, restaurable vía el botón Disable de la página de Opciones
  o el mensaje `disable-hardening`.
- **Canario de auto-test** al arranque y durante el hardening activo
  compara SOCKS5-RESOLVE (3 circuitos Tor aislados por stream) contra
  el conjunto completo de respuestas del resolver del sistema. Cada IP
  pública del sistema debe verse por Tor o confirmarse por
  PTR-vía-Tor como el host canario exacto o un subdominio; sufijos
  públicos compartidos como `co.uk` nunca cuentan como prueba.
- **Diagnóstico seguro para la privacidad.** Los logs de comandos en
  Opciones y los mensajes de consola del background resumen contadores,
  IPs enmascaradas y clases de error en vez de IPs/PTR crudos del
  canario, origins de cuentas, hostnames SMTP o dominios Message-ID.
- **Lista blanca de escritura de prefs** en la experiment API. La
  superficie del proceso padre del complemento **no puede** escribir
  prefs arbitrarias (`browser.startup.*`, `devtools.*`, etc. se
  rechazan) — limita el radio de impacto de cualquier regresión
  futura en handlers de mensajes.

**Límites inherentes — OnionBird NO PUEDE solucionar esto:**

1. **`Authentication-Results: ... smtp.auth=<tu-buzón>@<proveedor>`**
   lo añade el MTA del proveedor en el correo saliente. Revela tu
   buzón autenticado a cada destinatario. Es una propiedad del SMTP
   autenticado e imposible de eliminar desde el complemento.
   *Solución alternativa:* usa un buzón desechable / seudónimo para
   correspondencia sensible.
2. **La IP de salida de Tor aparece en la cadena `Received:` del
   destinatario.** Los MTAs de los proveedores hacen reverse-DNS sobre
   la IP que conecta y emiten nombres como
   `tor-exit-107.digitalcourage.de`. El destinatario aprende "este
   usuario envió vía Tor". Inherente al transporte SMTP.
3. **Fugas a nivel del SO** — divulgación del hostname desde otras
   apps, fugas de NTP, archivos de swap, timestamps del sistema de
   archivos. Usa Tails o Whonix.
4. **Correlación de red** — observadores de ambos extremos de un
   circuito Tor. No se derrota con higiene de cabeceras.

Cualquier cosa fuera de esos cuatro buckets está **dentro del alcance**
de la política. Abre un bug P0 si encuentras un contraejemplo.

---

## Panorama Tor-mail — cómo se compara OnionBird

No existe un único proyecto "Tor-mail". Varios esfuerzos se solapan
con OnionBird en diferentes capas; aquí lo que tienen en común y lo
que distingue a OnionBird.

OnionBird se sitúa en la **capa de cliente de correo** — endurece el
comportamiento de red y de cabeceras de Thunderbird mismo. Tails y
Whonix trabajan en una capa inferior (sistema operativo); pertenecen
al [stack de defensa en profundidad](#stack-con-un-so-tor-endurecido)
más abajo, no a una comparación de funciones con un único add-on de
MUA.

En la capa de cliente de correo, los vecinos directos de OnionBird son:

| Proyecto | Capa | Enrutado por Tor | Higiene de cabeceras | ¿Mantenido? |
|---|---|---|---|---|
| **OnionBird** (este) | Complemento de Thunderbird | sí (SOCKS5 + remoteDNS) | sí (todos los vectores históricos de fuga cerrados; el canario detecta nuevos) | sí (2026-) |
| TorBirdy | extensión de TB | sí | sí (histórico) | **no** — último release 2018, roto desde TB 78 (remoción de Legacy XUL) |
| Tor Mail (legacy, `.onion`) | proveedor de webmail en .onion | n/a | n/a | cerrado en 2013 (caída de Freedom Hosting) |
| Mailpile (modo Tor) | cliente de correo local | opcional | parcial | último release 2020 (efectivamente abandonado) |
| ProtonMail vía Tor | webmail | sí (`.onion` v3) | cabeceras controladas por el proveedor, sin higiene del lado del cliente | sí (solo en navegador) |
| Riseup / Disroot / Cock.li | proveedor de correo con .onion | sí (tú enrutas vía Tor) | depende del cliente | sí (depende del MUA que apuntes) |

Para una comparación característica-por-característica con el proyecto
cuya sucesión asume OnionBird — TorBirdy — consulta
[la sección equivalente en el README en inglés](README.md#onionbird-vs-torbirdy--feature-by-feature),
que también incluye la nueva fila **send-block de capa de aplicación**
(`compose.onBeforeSend` cancela envíos visiblemente cuando el verdict
del canario no es `clean`).

### Stack con un SO Tor-endurecido

OnionBird es deliberadamente *no* un sistema operativo. Para cerrar
fugas a nivel de SO (DNS de otras apps, sellos NTP, hostname,
swap-files, mtimes del sistema de archivos) deberías ejecutar
OnionBird **dentro** de un SO Tor-endurecido:

- **[Tails](https://tails.net/)** — sistema live basado en Debian que
  fuerza *todo* el tráfico de red a través de Tor y arranca desde USB,
  opcionalmente con almacenamiento persistente. Usa Thunderbird desde
  el almacenamiento persistente de Tails con OnionBird instalado;
  obtienes endurecimiento del cliente + enrutamiento global del SO en
  un mismo stack.
- **[Whonix](https://www.whonix.org/)** — par de VMs (Gateway + Workstation)
  que fuerza el tráfico de la Workstation por Tor a nivel de red. Instala
  OnionBird en la Thunderbird de la Workstation; la configuración SOCKS
  apuntará a `10.152.152.10:9050` (la IP de la Gateway).

Ambos resuelven los buckets 3 y 4 (fugas de SO y correlación) que
OnionBird por sí solo no puede cerrar. OnionBird + Tails o
OnionBird + Whonix es la configuración recomendada para uso crítico
de anonimato.

**Puntos en común:**

- Todas las soluciones anteriores enrutan tráfico por Tor de algún
  modo.
- Todas reconocen que el enrutado puro no basta — las cabeceras
  filtran identidad incluso si los bytes pasan por Tor.
- Todas requieren que el SO del usuario no filtre DNS / NTP / hostname
  fuera de banda para anonimato completo.

**En qué OnionBird es distinto:**

1. **Un complemento normal de Thunderbird, no un SO aparte.** Tails y
   Whonix son el estándar de oro para anonimato pero requieren un
   boot o VM aparte. OnionBird asume que ya tienes Tor corriendo (o
   estás en Tails/Whonix) y endurece el comportamiento de TB dentro
   de ese entorno.
2. **Verificado empíricamente extremo a extremo.** Suite local actual:
   5 smoke tests más 148 tests de integración (1 skip esperado), con
   7+ escenarios reales de Tor contra `undisclose.de` y auditoría
   byte-a-byte de cabeceras (H1–H15) sobre correo capturado. El
   `dns-trap` del stack de tests registra *cada* consulta DNS que TB
   hace durante un envío real — 0 consultas observadas para el host
   SMTP/IMAP. La auditoría SMTP onion exige un mensaje capturado por
   `smtp-trap` antes de que pueda pasar la aserción de no-DNS.
3. **Canario continuo.** Corre al inicio de TB y periódicamente mientras
   el hardening está activo, compara 3 circuitos Tor aislados por stream
   contra el conjunto completo del resolver del sistema y exige que
   cada IP pública divergente se confirme por PTR-vía-Tor como el host
   objetivo o un subdominio. Notifica sospecha de fuga al usuario en
   lugar de "confiar" silenciosamente en que el complemento sigue
   funcionando.
4. **Sin Message-ID supercluster.** Las herramientas Tor-mail
   anteriores (TorBirdy notablemente) usaban
   `Message-ID: <uuid@localhost.localdomain>` — una huella global
   distintiva. OnionBird por defecto usa el dominio de la dirección
   From (coincide con el `d=` de DKIM, se mezcla con usuarios
   normales del proveedor); configurable a `localhost`,
   `localhost.localdomain` o custom vía la página de Opciones.
5. **Configurable, no dogmático.** TorBirdy era tómalo-o-déjalo.
   OnionBird te permite habilitar/deshabilitar el hardening, elegir
   tu puerto SOCKS (Tor de sistema 9050, Tor Browser bundle 9150,
   estación de trabajo Whonix `10.152.152.10:9050`) y elegir la
   estrategia de FQDN del Message-ID.

**Dónde OnionBird NO es reemplazo:**

- **No** reemplaza Tails / Whonix para aislamiento a nivel de SO.
- **No** enruta tráfico de OTRAS aplicaciones a través de Tor.
- **No** impide que el destinatario sepa que usaste Tor (puede ver
  la IP de salida de Tor en `Received:`).
- **No** oculta tu identidad de buzón autenticado al destinatario
  (inherente a SMTP-AUTH).

---

## Antes de instalar

El complemento endurece lo que corre **dentro** de Thunderbird. Para
cobertura Tor al 100%, el **resolver del SO** también debe pasar por
Tor. Elige el camino que coincida con tu entorno:

- **Estación de trabajo Tails / Whonix** — el DNS del sistema ya es
  Tor. Instala el `.xpi`, listo.
- **Linux estándar con Tor de sistema** — añade `DNSPort 5353` a tu
  `/etc/tor/torrc` y asegura que `/etc/resolv.conf` lo alcance (un
  `dnsmasq`/`unbound` local reenviando a `127.0.0.1:5353` es el
  patrón estándar).
- **Solo Tor Browser bundle** — Tor escucha en `9150`, no en `9050`;
  el complemento prueba prefs existentes y los puertos locales comunes
  `9050` y `9150` antes de escribir prefs de proxy. Los re-asserts
  posteriores preservan ese endpoint.
- **SOCKS remoto de Tor/Whonix** — usa un literal IP como
  `10.152.152.10:9050`, no un hostname. El complemento ignora a
  propósito endpoints SOCKS con hostname, porque resolver el hostname
  del proxy ya sería una consulta DNS local antes de llegar a Tor.
- **Escritorio estándar sin DNS de sistema vía Tor** — instala bajo
  tu propia responsabilidad. El canario de arranque marcará la
  configuración en la página de Opciones y en la consola del
  navegador.

---

## Qué hace hoy

- Enruta IMAP/SMTP a través de un proxy SOCKS5 local (predeterminado
  `127.0.0.1:9050`, configurable) con `socks_remote_dns=true` y
  `failover_direct=false`. Enable prueba prefs SOCKS existentes, Tor
  de sistema `9050` y Tor Browser `9150`; el re-assert de arranque y
  periódico preserva el endpoint actual solo si es loopback o un
  literal IP.
- Normaliza cabeceras identificadoras en correo saliente:
  `User-Agent` / `X-Mailer` suprimidos, FQDN del `Message-ID`
  configurable (predeterminado = tu dominio From), `HELO`/`EHLO` SMTP
  reescritos a `[127.0.0.1]`, `Date` en UTC vía
  `privacy.resistFingerprinting`, sin `format=flowed`.
- Hardening de prefs en defensa-en-profundidad: TRR=5, OCSP apagado,
  sin WebRTC, sin DNS-prefetch, sin predictor, sin phone-home de
  updates, sin telemetría, sin Safebrowsing, sin sondas de
  captive-portal, sin renderizado de contenido remoto.
- **Canario SOCKS5-RESOLVE-vs-DNS-de-sistema** al arranque y
  periódicamente durante el hardening activo: compara todas las IPs
  públicas del sistema con circuitos Tor aislados por stream y usa
  PTR-vía-Tor solo como fallback estricto de host exacto/subdominio.
- Logging seguro para la privacidad: los logs de comandos y el
  diagnóstico del background redactan por defecto IP/PTR crudos del
  canario e identificadores de cuentas.
- **Modo de prueba Tor** en la página de Opciones verifica que un
  endpoint SOCKS local de Tor sea alcanzable sin enviar correo, cambiar
  prefs ni usar DNS del sistema para la prueba del host objetivo.
- La página de Opciones soporta tema de sistema/claro/oscuro, está
  disponible en **21 locales UI** (EN, DE, ES, FR, PT, PL, UK, RU, BE,
  TR, FA, AR, HE, KU, UR, HI, ZH-CN, VI, TH, ID, AF) e incluye ayuda
  integrada con TL;DR más modo nerd sobre alcance, límites,
  compatibilidad TorBirdy y la frontera necesaria de Experiments API.
- Auto-activa en la primera instalación. **Botón Disable** en la
  página de Opciones restaura el snapshot.
- Solo se endurecen por defecto servidores SMTP **onion + loopback**
  (B-003): tus cuentas clearnet existentes siguen funcionando.
- `user.js` complementario para hardening pre-arranque + un script
  que enumera tus cuentas existentes en `prefs.js` y emite líneas
  por servidor coincidentes.

---

## Inicio rápido

```sh
# Construye el .xpi (MV2, canónico)
make build

# Opcional: build paralelo MV3 para smoke de compat hacia adelante
make build-mv3

# Levanta el pod de tests (Tor+DNSPort + aiosmtpd + DNS-forwarder +
# Xvfb+TB + runner)
make COMPOSE_ENGINE=docker test-up

# Ejecuta la suite de integración (148 tests en la versión 0.1.1)
make COMPOSE_ENGINE=docker test-integration

# Desmonta
make COMPOSE_ENGINE=docker test-down
```

# O elige un proveedor explícitamente para una ejecución enfocada
set -a; source test/external/secrets.env; set +a
PYTHONPATH=test pytest -v -s test/external/ --provider=POSTEO
```

`T0R_TEST_PROVIDER` selecciona el proveedor por defecto para `make
test-external`. `--provider=...` lo sobrescribe en ejecuciones directas
de pytest. Si `T0R_RECV_USER` está definido, el receptor debe ser un
buzón distinto: `T0R_RECV_EMAIL` debe ser una dirección válida
diferente del remitente y `T0R_RECV_PASS` no puede estar vacío.

## Arquitectura

OnionBird es híbrido: un script background de MailExtension provee la
superficie de API pública (página de Opciones, handler de auto-enable
al instalar, message bus para enable/disable, auto-test periódico al
inicio), mientras que un módulo de Experiments API corre en el proceso
padre y expone manipulación de `Services.prefs`,
`MailServices.outgoingServer`, `MailServices.accounts`, SOCKS5 RESOLVE
/ RESOLVE_PTR crudos y `nsIDNSService.clearCache`. Las dos mitades se
comunican vía el namespace custom `browser.onionbird.*`.

Ver [docs/architecture.md](docs/architecture.md) para un diagrama.

---

## Roadmap / limitaciones conocidas

Ver [docs/follow-up.md](docs/follow-up.md) para la lista completa
ranked. Aspectos destacados diferidos a iteraciones futuras:

- Toggle UI de modo mixto para usuarios que explícitamente quieran
  endurecer todos los servidores SMTP, no solo onion/loopback.
- Evento de cambio de red/resolver adicional al canario periódico.
- Reintento PTR multi-circuito para reducir falsos positivos si una
  salida Tor rechaza PTR.
- Etiquetado de credenciales para cuentas Tor creadas por el add-on;
  disable ya ofrece borrado para logins mail onion/loopback detectados.
- Asistente de primer arranque con auto-detección de puerto SOCKS.
- Bridges / pluggable transports para ISPs censurados.
- Integración con el control-port de Tor (NEWNYM por envío).
- UX de instalador multiplataforma empaquetado más allá del script actual.
- Locales UI adicionales para hotspots de represión/censura aún no
  cubiertos por los 21 idiomas enviados (p. ej. `my`, `ug`, `bo`,
  `am`, `ti`, `ps`/`prs`, `bn`, `ka`, `sw`) — contribuciones de
  hablantes nativos bienvenidas vía PR.

---

## Licencia

MPL-2.0. Ver [LICENSE](LICENSE) para el texto completo.

Este software se proporciona TAL CUAL sin garantía de ningún tipo.
Los autores no se hacen responsables de desanonimización u otro daño
derivado de su uso. Ver LICENSE para el descargo completo.
