# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [1.2.0] - 2026-11-08

### Changed

- Status colours are named tokens (`--ok`, `--warn`, `--bad`) that read at
  4.5:1 on every colour scheme, Daylight included, and stay apart for
  colour-blind viewers. A service with a warning shows a diamond and its HTTP
  code, and feed values that need a look carry the same diamond.
- The briefing and security pages give each level a shape (circle, diamond,
  ring) and a word for screen readers, a down cell in a strip graph stands
  taller, and high-priority alerts are tagged "high".
- The layer, colour-scheme and panel toggles and the clocks are buttons, the
  overlays are dialogs that take focus and give it back, a closed overlay
  leaves the tab order, and every control shows the same focus ring.
- With reduced motion set, the globe stops turning, its pulses and orbits hold
  still, and panels and toasts fade in place.
- Daylight's accent, muted text and INTEL tabs are dark enough to read; panels
  and popovers share one corner radius.

### Fixed

- On a high-density screen wider than 1000 pixels, the globe's canvas drew at
  twice the window's size, so the globe sat off-centre towards the bottom
  right. It now fills the window.
