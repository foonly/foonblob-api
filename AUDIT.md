# Security and Best Practices Audit - Foonblob API

This document provides a comprehensive audit of the `foonblob-api` project, covering security vulnerabilities, architectural best practices, and actionable recommendations.

## 1. Security Analysis

### Findings: High Priority

- **CORS Configuration**: [RESOLVED] The project implements **Dynamic CORS**. When an identity is registered, its `Origin` is captured and stored. Subsequent requests for that sync ID are restricted to that specific origin via custom middleware.
- **Plaintext Secret Storage**: [RESOLVED] The `signing_secret` is now encrypted at rest using **AES-GCM** (with an `enc:` prefix in the database). The encryption key is managed via configuration (`secret_encryption_key`), significantly reducing the risk of identity compromise if the database file is leaked.
- **Unauthenticated Read Access**: [RESOLVED] All GET requests (`/api/v1/sync/{id}`, `/history`, and versioned lookups) now require a valid **HMAC signature**. Clients must sign the URL path, ensuring that only authorized parties can retrieve blobs.

### Findings: Medium Priority

- **Public Statistics Endpoint**: [RESOLVED] The `/api/v1/stats` endpoint is now protected by **Bearer token authentication**. Access is denied if `stats_token` is not configured or if the provided token is incorrect.
- **In-Memory Rate Limiting**: The rate limiter remains in-memory. While suitable for single-node deployments, a distributed store (like Redis) would be required for scaling across multiple instances.
- **Rate Limiter Memory Leak**: [RESOLVED] The `RateLimiter` includes a background cleanup worker that prunes inactive buckets every hour.
- **Information Leakage in Logs**: [RESOLVED] Structured logging via `log/slog` is implemented. Request metadata is logged without exposing sensitive payload data or secrets.

### Findings: Low Priority

- **Timing Attacks**: Signature verification uses `hmac.Equal`, providing constant-time comparison to prevent timing attacks.
- **Replay Protection**: The system enforces a 5-minute window and requires strictly increasing timestamps for every identity, providing robust protection against replay attacks.
- **Resource Exhaustion**: `MaxBytesReader` limits upload sizes to 1MB.

---

## 2. Best Practices Analysis

### Code Quality & Architecture

- **Project Structure**: Follows standard Go layout (`cmd/`, `internal/`).
- **Concurrency**: SQLite uses WAL mode and `MaxOpenConns(1)` for safe concurrent access.
- **Error Handling**: Consistent use of Go 1.13+ error wrapping.
- **Graceful Shutdown**: Properly handles OS signals to ensure data integrity during shutdown.
- **Go Version**: Correctly pinned to a stable version (`1.24.0`).

### Database Management

- **Migration Tooling**: [RESOLVED] Integrated `goose` for formal database migrations. Schema changes are now versioned and embedded in the binary via `embed.FS`.
- **Cleanup Logic**: Automated background worker prunes inactive identities and orphaned blobs based on idle-time rules.

---

## 3. Actionable Recommendations

### Phase 1: Immediate Security Fixes (Completed)

- [x] **Restrict CORS**: Implemented Dynamic CORS locked to registration origins.
- [x] **Protect Stats**: Added Bearer token authentication.
- [x] **Authenticate Reads**: Enforced HMAC signatures for all retrieval endpoints.
- [x] **Encrypt Secrets**: Implemented AES-GCM encryption for signing secrets in the database.

### Phase 2: Architectural Improvements (Completed)

- [x] **Structured Logging**: Migrated to `log/slog` with JSON output.
- [x] **Configuration Management**: Integrated Viper for TOML and Environment Variable support.
- [x] **Migration Tooling**: Integrated `goose` for schema management.
- [x] **Fix Rate Limiter Leak**: Added pruning worker for rate limit buckets.

### Phase 3: Robustness & Scaling (Future)

- [ ] **Database Encryption**: For environments requiring high-security at rest, consider migrating to a SQLite driver supporting SQLCipher for full-file encryption.
- [ ] **Distributed Rate Limiting**: If scaling horizontally, migrate the rate limiter state to Redis.
- [ ] **Audit Logging**: Implement a specific audit log for registration events and failed authentication attempts.

---

## Conclusion

The `foonblob-api` has been upgraded to a production-ready security posture. By enforcing HMAC signatures for all data access, encrypting secrets at rest, and implementing formal migration and configuration systems, the most critical risks identified in the initial audit have been mitigated. The system now follows modern Go best practices and provides a secure foundation for client-side encrypted data synchronization.
