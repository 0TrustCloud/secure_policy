

# Secure Policy Engine (`secure_policy`)

`secure_policy` is a high-performance, zero-trust security enforcement framework designed for distributed mesh networks and edge computing topologies. Engineered in Go, it abstracts and replaces old, slow database queries with a **Polymorphic Cryptographic State Transition** model built natively on top of the **Secure Data Format (SDF)** protocol.

The architecture decouples business logic from physical storage layout, orchestrating session lifecycles, Role-Based Access Control (RBAC), and Attribute-Based Access Control (ABAC) using strict isolation boundaries.

---

## 1. Core Architectural Pillars

* **Dual-Tier State Verification:** Validates access requests through a cache-first hierarchy. It evaluates non-blocking snapshot reads across a lock-free memory ring (`GlobalCacheStore`) before falling back to abstract key-value lookups (`KVStore`).
* **Cryptographic Immutability:** Every policy mutation, permission grant, or session revocation compiles into an SDF contract. This produces an un-tamperable state receipt tracking nonces and signing envelopes.
* **Strict Deny-Override:** Implements a fail-closed evaluation matrix. If a subject matches multiple intersecting policies, any explicit `DENY` automatically short-circuits and overrides all matching `ALLOW` assertions.
* **Advanced Attribute Matching:** ABAC conditions support high-performance pattern evaluations, including exact string comparisons, `prefix:` pathing, and `suffix:` extension matching.

---

## 2. Component Layout

The framework isolates identity management from fine-grained policy evaluation through two core subsystems:

### Policy Engine (`PolicyEngine`)

Handles permission delegation and complex ABAC evaluation loops. It maps authorization matrices into explicit data state blocks and validates live parameters against prefix/suffix constraints.

### Session Manager (`SessionManager`)

Manages the lifecycle of hardware-bound identity tokens (cookies). It handles short-term cryptographic token synthesis, parsing, and revocation tracking using unique system transaction tags (`jti`).

---

## 3. Integration & Usage Examples

### Initializing the Architecture

```go
import (
    "github.com/0TrustCloud/secure_data_format"
    "github.com/0TrustCloud/secure_policy"
)

// Instantiate the policy engine using your active SDF compiler instance
policyEngine := secure_policy.NewPolicyEngine(sdfEngineInstance)

// Instantiate the session manager with public-key verification capabilities
sessionManager := secure_policy.NewSessionManager(sdfEngineInstance, rsaPublicKey)

```

### Managing Fine-Grained ABAC Policies

```go
subject := []byte("hardware-enclave-id-992")
conditions := map[string]string{
    "binary_path": "prefix:/usr/bin/",
    "log_ext":     "suffix:.log",
    "environment": "production",
}

// Add a policy contract signed and registered via SDF
err := policyEngine.AddPolicy(subject, "execute", "secure-vault", "ALLOW", conditions)

// Evaluate incoming parameters at runtime
context := map[string]string{
    "binary_path": "/usr/bin/security_agent",
    "log_ext":     "audit_trail.log",
    "environment": "production",
}

if policyEngine.Evaluate(subject, "execute", "secure-vault", context) {
    // Request authorized
}

```

### Issuing and Validating Identity Sessions

```go
// Issue an encrypted, signed session token bound to a hardware identity
tokenStr, jti, err := sessionManager.IssueCookieToken(subject, 1*time.Hour)

// Validate incoming token string properties against real-time blacklists
validatedSubject, err := sessionManager.ValidateCookieToken(tokenStr)
if err != nil {
    // Token is expired, signature is corrupted, or identity has been blacklisted
}

```

### Executing Global Kill Switches

```go
// Invalidate a single cryptographic session instantly across memory and ledger logs
err := sessionManager.RevokeSession(activeJTI, 24*time.Hour)

// Permanently blacklist a compromised hardware device identity globally across the mesh
err := sessionManager.BlacklistDevice(subject)
// After restore / incident closed:
err = sessionManager.ClearDeviceBlacklist(subject)

```

---

## 4. Under the Hood: The Evaluation Flow

When an application calls `Evaluate()` or `ValidateCookieToken()`, the engine coordinates across the architecture using a lock-free fast-path execution loop:

1. **Identity Extraction:** Parses the token to extract the structural payload metadata blocks safely.
2. **Postures Check (POP Profiles):** Queries the memory ring for global hardware blocklists matching the subject's hash signature.
3. **Session Check (GRANT Profiles):** Scans for session-specific revocation states matching the token's unique ID (`jti`).
4. **Hierarchical Scan:** If the identity is clear, it crawls the key matrix (exact targets $\rightarrow$ action wildcards $\rightarrow$ global wildcards) to resolve policy effects under strict Deny-Override parameters.

---

## 5. Security & Verification Baseline

| Operational Risk Vector | Enforcement Mechanism |
| --- | --- |
| **Token Hijacking & Replay** | Strict sequence tracking via cryptographic nonces (`getNextNonce`). |
| **Silent Log/Policy Editing** | Deterministic `state_root_hash` validation prevents out-of-band tampering. |
| **Identity/Session Revocation Lag** | Immediate validation eviction from the lock-free cache interrupts active sessions in microseconds. |
| **Policy Ingestion Attacks** | Recursive AST depth controls inside the SDF layer prevent nesting execution panics. |

---

## 6. Testing the Environment

The test suite runs entirely decoupled from disk I/O, utilizing in-memory mock stores to test edge cases, policy pattern variations, and revocation boundaries.

Run the test matrix locally via the Go toolchain:

```bash
go test -v ./...

```

---

## License

MIT
