# OnionBird — Logo-Entwürfe

10 Konzepte, je zweimal:

- `NN-name.svg` — **Extern** (mit Wortmarke „OnionBird“ + Subtitle, 320×380)
- `NN-name.icon.svg` — **Plugin-Icon** (kompakt, 64×64, ohne Text, skaliert bis 16×16)

Vorschau aller 20 SVGs: [`index.html`](./index.html) im Browser öffnen.

| # | Konzept | Idee |
|---|---------|------|
| 01 | onion-bird | Vogelkörper = geschälte Zwiebel (Schalen sichtbar) |
| 02 | wing-rings | Großer Flügel gefüllt mit Onion-Ringen |
| 03 | bolt-onion | TB-Blitz schneidet Onion-Schalen |
| 04 | hooded-bird | Thunderbird mit Onion-Kapuze |
| 05 | onion-eye | Vogelkopf, Zwiebel als Auge |
| 06 | shield-bird | Onion-Schild + Vogel |
| 07 | t0-mono | Monogramm „t0“ (Blitz + Zwiebel) |
| 08 | phoenix-onion | Phoenix steigt aus Zwiebel (TorBirdy-Nachfolger-Narrativ) |
| 09 | circuit-bird | Tor-Circuit-Hops zeichnen Flugbahn |
| 10 | letter-onion | Briefumschlag mit Onion-Siegel |

## Farbpalette

| Farbe | Hex | Verwendung |
|-------|-----|------------|
| Tor-Purple | `#7D4698` | Primär (Zwiebel) |
| Tor-Dark | `#4A2D67` | Akzent / Outline |
| Tor-Deep | `#2B1640` | Wortmarke / dunkles Plate |
| Thunderbird-Orange | `#E66100` | Vogel / Akzent |
| Gold | `#F9A11B` | Highlights / Schnabel |
| Off-white | `#FFF7EE` | Hintergrund hell |

## Nächste Schritte

Sobald ein Favorit feststeht:

1. Final-Polish (Outline-Stärken, Beak-Geometrie, Kerning der Wortmarke).
2. Schwarzweiß-Variante + Single-Color-Variante (für Druck / Dark-Mode).
3. PNG-Exporte in den TB-Standardgrößen: 16, 32, 48, 64, 96, 128.
4. Manifest-Einbindung:
   ```jsonc
   // addon/manifest.json
   "icons": {
     "16": "icons/onionbird-16.png",
     "32": "icons/onionbird-32.png",
     "48": "icons/onionbird-48.png",
     "96": "icons/onionbird-96.png"
   }
   ```
