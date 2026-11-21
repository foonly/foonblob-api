# Changelog

## 0.9.0 (2026-11-21)

#### Features

- api: expose the Date header to browser clients (5fc9064)

#### Maintenance

- rename foonver.toml (ed725dd)

## 0.8.0 (2026-11-19)

#### Features

- api: allow concurrent devices by rejecting replayed signatures (3f6991c)

#### Bug Fixes

- deploy: make new releases readable and roll back on failed restart (8804a52)

## 0.7.0 (2026-11-19)

#### Features

- deploy: continuous deployment with automatic rollback (7888597)

#### Bug Fixes

- api: make replay protection atomic and harden websocket hub (f01e359)

#### Documentation

- correct security claims and update deployment guide (45bc623)

#### Build System

- embed version in release builds and run all tests in CI (0fd491f)

## 0.6.0 (2026-06-23)

#### Features

- api: implement WebSocket support for real-time updates (b37c650)

#### Bug Fixes

- api: increase write rate limit (1bc6fee)

## v0.5.0 (2026-06-19)

#### Features

- api: enforce and validate registered AllowedOrigin, normalize origin and add tests (909791b)
- implement security hardening and production features (27c75c4)
- api: add Viper-based config, stats auth, and rate limiter cleanup (06c2b99)
- api: add per-id dynamic CORS and store allowed_origin (b32ed6d)

#### Bug Fixes

- store: return errors on encryption and decryption failures (a12bfca)
- api: decode HMAC signature and stop rate limiter goroutine on shutdown (e874a2c)
- api: return 500 and log errors when UpdateIdentityTimestamp fails (59efe97)
- api: allow Authorization header and simplify sync routes (1d5ede0)

#### Documentation

- API: update documentation with new endpoints and formatting (13038f2)
- config: clarify that empty stats_token denies access to /api/v1/stats (f148c91)
- go: update Go requirement to 1.25 (274a341)
- api: add client development guide (027fd41)
- readme: add systemd deployment instructions (ee2ee58)

#### Build System

- makefile: add Makefile for build and development tasks (e7770a3)

### v0.4.1 (2026-04-13)

#### Performance Improvements

- server: add error logging and optimize SQLite for concurrency (c6dc4d8)

#### Maintenance

- foonver: remove parser setting from foonver.toml (b7ea981)

## v0.4.0 (2026-04-12)

#### Features

- api: add stats endpoint and background cleanup worker (ab6a3b2)

#### Refactor

- module: rename project and module path to foonblob-api (e488ed7)

#### Documentation

- readme: add management endpoints, stats response, and background cleanup policy (922c0cb)

#### Maintenance

- gitignore: ignore all .db files instead of only sync.db (dd9285f)

## v0.3.0 (2026-04-07)

#### Features

- api: Implement sync endpoint with HMAC signature verification (88b9de2)

### v0.2.1 (2026-04-07)

#### Documentation

- Update README with GPL-3.0-only license (e59d9a4)

#### Build System

- ci: Add GitHub Actions release workflow (f86fb00)

## v0.2.0 (2026-04-07)

#### Features

- config: Add foonver configuration file (dc4e8d4)
- api: implement sync endpoint and persistence (9235a49)

#### Documentation

- Add README.md with project overview and usage (17db423)
