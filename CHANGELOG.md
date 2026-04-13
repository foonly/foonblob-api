# Changelog

### 0.4.1 (2026-04-13)

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

