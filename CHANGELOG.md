# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.0.0] - 2026-10-27

The first public release.

### Added

- The console: host CPU, memory, disks, temperature and uptime beside a WebGL
  globe, with service checks and public data feeds (earthquakes, aircraft,
  cables, outages, weather, launches and more) as layers.
- A peer device panel fed by `agent.py`, for a laptop or a second machine.
- The briefing page, a security page that shows Lynis runs, and alerts to an
  ntfy topic.
- A token login, or the tailnet login through Tailscale Serve.
- Runs with Podman, Docker, compose, a rootless Quadlet or plain Python, on
  the standard library alone.
- An image at `ghcr.io/zakijss/vantage`, for amd64 and arm64.

[Unreleased]: https://github.com/zakijss/Vantage/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/zakijss/Vantage/releases/tag/v1.0.0
