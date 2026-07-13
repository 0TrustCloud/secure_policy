package secure_policy

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"
        "strings"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/ultimate_db"
)

// =============================================================================
// Interface Mock Layer for Test Isolation
// =============================================================================

type mockTxnHandle struct {
	id        uint64
	committed bool
	aborted   bool
}

func (m *mockTxnHandle) ID() uint64    { return m.id }
func (m *mockTxnHandle) Commit() error { m.committed = true; return nil }
func (m *mockTxnHandle) Abort() error  { m.aborted = true; return nil }

type mockKVStore struct {
	records map[string][]byte
	nextID  uint64
}

func (m *mockKVStore) Begin() ultimate_db.TxnHandle {
	m.nextID++
	return &mockTxnHandle{id: m.nextID}
}

func (m *mockKVStore) Get(txn ultimate_db.TxnHandle, key []byte) ([]byte, error) {
	if val, ok := m.records[string(key)]; ok {
		return val, nil
	}
	return nil, fmt.Errorf("key not found")
}

func (m *mockKVStore) Put(txn ultimate_db.TxnHandle, key []byte, value []byte, ttl time.Duration) error {
	m.records[string(key)] = value
	return nil
}

func (m *mockKVStore) Delete(txn ultimate_db.TxnHandle, key []byte) error {
	delete(m.records, string(key))
	return nil
}

func (m *mockKVStore) NewIterator(txn ultimate_db.TxnHandle, prefix []byte) ultimate_db.KVIterator {
	return nil
}

func (m *mockKVStore) Flush() error { return nil }

type mockLockManager struct {
	acquiredLocks map[string]uint64
	releasedAll   bool
}

func (m *mockLockManager) Acquire(txnID uint64, key string, mode ultimate_db.LockMode) error {
	m.acquiredLocks[key] = txnID
	return nil
}

func (m *mockLockManager) Release(txnID uint64, key string) error {
	delete(m.acquiredLocks, key)
	return nil
}

func (m *mockLockManager) ReleaseAll(txnID uint64) error {
	m.releasedAll = true
	return nil
}

// Helper to bootstrap a test SDF engine instance
func setupTestSDFEngine(t *testing.T) (*secure_data_format.SecureDataEngine, *mockKVStore, *rsa.PrivateKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating test key pair: %v", err)
	}

	storeMock := &mockKVStore{records: make(map[string][]byte)}
	lockMock := &mockLockManager{acquiredLocks: make(map[string]uint64)}

	engine, err := secure_data_format.New(storeMock, lockMock, "test-policy-authority", privKey)
	if err != nil {
		t.Fatalf("failed initializing underlying SDF engine: %v", err)
	}

	return engine, storeMock, privKey
}

// =============================================================================
// Policy Engine Test Suites
// =============================================================================

func TestPolicyEngine_PermissionLifecycle(t *testing.T) {
	sdf, _, _ := setupTestSDFEngine(t)
	pe := NewPolicyEngine(sdf)

	subject := []byte("hardware-token-greg")

	// Verify permission defaults to false when unassigned
	if pe.HasPermission(subject, "cluster:write") {
		t.Error("expected default permission state to evaluate to false")
	}

	// Grant permission via the SDF tracking compiler
	err := pe.GrantPermission(subject, "cluster:write")
	if err != nil {
		t.Fatalf("failed granting permission sequence: %v", err)
	}

	// Verify permission registers as true after being committed
	if !pe.HasPermission(subject, "cluster:write") {
		t.Error("failed evaluating granted token permission ledger receipt")
	}
}

func TestPolicyEngine_ABACEvaluationWithPatterns(t *testing.T) {
	sdf, _, _ := setupTestSDFEngine(t)
	pe := NewPolicyEngine(sdf)

	subject := []byte("analyst-identity-frame")
	conditions := map[string]string{
		"binary_path": "prefix:/usr/bin/",
		"log_ext":     "suffix:.log",
		"environment": "production",
	}

	err := pe.AddPolicy(subject, "execute", "secure-vault", "ALLOW", conditions)
	if err != nil {
		t.Fatalf("failed writing ABAC contract matrix: %v", err)
	}

	// 1. Test clean matching context pass
	validContext := map[string]string{
		"binary_path": "/usr/bin/security_agent",
		"log_ext":     "audit_trail.log",
		"environment": "production",
	}
	if !pe.Evaluate(subject, "execute", "secure-vault", validContext) {
		t.Error("expected matching prefix/suffix conditions to evaluate to ALLOW")
	}

	// 2. Test context breakage (prefix failure)
	invalidPrefixContext := map[string]string{
		"binary_path": "/tmp/malicious_binary",
		"log_ext":     "audit_trail.log",
		"environment": "production",
	}
	if pe.Evaluate(subject, "execute", "secure-vault", invalidPrefixContext) {
		t.Error("expected policy violation block to deny request on invalid path prefix")
	}
}

func TestPolicyEngine_DenyOverrideRule(t *testing.T) {
	sdf, _, _ := setupTestSDFEngine(t)
	pe := NewPolicyEngine(sdf)

	subject := []byte("restricted-service-principal")

	// Add an explicit general ALLOW statement
	err := pe.AddPolicy(subject, "read", "*", "ALLOW", nil)
	if err != nil {
		t.Fatalf("failed establishing fallback allow: %v", err)
	}

	// Superimpose an explicit targeted DENY statement
	err = pe.AddPolicy(subject, "read", "restricted-vault", "DENY", nil)
	if err != nil {
		t.Fatalf("failed establishing target boundary deny: %v", err)
	}

	// Verification of strict Deny-Override sequence alignment
	if pe.Evaluate(subject, "read", "restricted-vault", nil) {
		t.Error("security breach: Deny-Override rule logic failed to prioritize DENY branch status")
	}
}

// =============================================================================
// Session Manager Test Suites
// =============================================================================

func TestSessionManager_IssuanceAndValidation(t *testing.T) {
	sdf, _, privKey := setupTestSDFEngine(t)
	sm := NewSessionManager(sdf, &privKey.PublicKey)

	subject := []byte("user-session-subject-01")

	// Issue cookie token state claims mapping
	tokenStr, jti, err := sm.IssueCookieToken(subject, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed to compile session cookie token: %v", err)
	}

	if jti == "" {
		t.Fatal("expected structural verification token identifier JTI to be generated")
	}

	// Parse and validate the token signature parameters
	validatedSub, err := sm.ValidateCookieToken(tokenStr)
	if err != nil {
		t.Fatalf("token validation procedure failed: %v", err)
	}

	if validatedSub != string(subject) {
		t.Errorf("subject context desynchronization. Expected %s, got %s", string(subject), validatedSub)
	}
}

func TestSessionManager_RevocationVectors(t *testing.T) {
	sdf, _, privKey := setupTestSDFEngine(t)
	sm := NewSessionManager(sdf, &privKey.PublicKey)

	subject := []byte("revocation-test-target")

	tokenStr, _, err := sm.IssueCookieToken(subject, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed token generation tracking initialization: %v", err)
	}

	// Revoke the session string mapping directly
	err = sm.RevokeTokenString(tokenStr)
	if err != nil {
		t.Fatalf("failed committing token string cancellation: %v", err)
	}

	// Ensure validation returns an explicit error on a revoked session
	_, err = sm.ValidateCookieToken(tokenStr)
	if err == nil || !strings.Contains(err.Error(), "session has been revoked") {
		t.Errorf("expected session revocation error block, got: %v", err)
	}
}

func TestSessionManager_DeviceGlobalKillSwitch(t *testing.T) {
	sdf, _, privKey := setupTestSDFEngine(t)
	sm := NewSessionManager(sdf, &privKey.PublicKey)

	subject := []byte("hardware-enclave-id-992")

	tokenStr, _, err := sm.IssueCookieToken(subject, 1*time.Hour)
	if err != nil {
		t.Fatalf("failed initializing state trace: %v", err)
	}

	// Permanent device ban (keeps working after compromise recovery tooling)
	err = sm.BlacklistDevice(subject)
	if err != nil {
		t.Fatalf("failed committing device hardware identity blacklisting sequence: %v", err)
	}

	// Ensure subsequent verification blocks validation on identity criteria match
	_, err = sm.ValidateCookieToken(tokenStr)
	if err == nil || !strings.Contains(err.Error(), "blacklisted") {
		t.Errorf("expected permanent device blacklist blockage, got: %v", err)
	}

	// Clear ban restores access for a new session after restore
	if err := sm.ClearDeviceBlacklist(subject); err != nil {
		t.Fatalf("ClearDeviceBlacklist: %v", err)
	}
	token2, _, err := sm.IssueCookieToken(subject, 1*time.Hour)
	if err != nil {
		t.Fatalf("re-issue after clear: %v", err)
	}
	if _, err := sm.ValidateCookieToken(token2); err != nil {
		t.Fatalf("expected session ok after un-blacklist, got: %v", err)
	}
}
