package secure_policy

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0TrustCloud/ultimate_db"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/golang-jwt/jwt/v5"
)

type SessionManager struct {
	sdfEngine *secure_data_format.SecureDataEngine
	publicKey *rsa.PublicKey
}

func NewSessionManager(sdf *secure_data_format.SecureDataEngine, pubKey *rsa.PublicKey) *SessionManager {
	return &SessionManager{
		sdfEngine: sdf,
		publicKey: pubKey,
	}
}

// =============================================================================
// Token Generation & Synthesis Path
// =============================================================================

func (sm *SessionManager) IssueCookieToken(subject []byte, ttl time.Duration) (string, string, error) {
	subjectID := string(subject)
	targetAddress := "session:user:" + hashSubject(subject)
	
	script := fmt.Sprintf(`session:identity(user("%s"))`, subjectID)
	nonce := getNextNonce(sm.sdfEngine, "grant", targetAddress)

	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "session-manager-core",
		Nonce:         nonce,
		Method:        "ISSUE",
		Profile:       secure_data_format.ProfileGrant,
		Args:          map[string]interface{}{"sub": subjectID},
	}

	tokenStr, err := sm.sdfEngine.CompileSecureData(script, tx)
	if err != nil {
		return "", "", fmt.Errorf("failed synthesizing token state: %w", err)
	}

	p := new(jwt.Parser)
	parsedToken, _, err := p.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return "", "", fmt.Errorf("failed reading compiled transaction properties: %w", err)
	}

	claims, _ := parsedToken.Claims.(jwt.MapClaims)
	jti, _ := claims["jti"].(string)

	return tokenStr, jti, nil
}

// =============================================================================
// Validation & Verification Infrastructure
// =============================================================================

func (sm *SessionManager) ValidateCookieToken(tokenString string) (string, error) {
	tokenString = strings.TrimPrefix(tokenString, "user_session_")

	if sm.publicKey == nil {
		return "", errors.New("cryptographic context error: public verification key unassigned")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return sm.publicKey, nil
	})

	if err != nil || !token.Valid {
		return "", errors.New("invalid or expired token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", errors.New("invalid token claims")
	}

	stateUpdates, ok := claims["state_updates"].(map[string]interface{})
	if !ok {
		return "", errors.New("missing structured payload context block")
	}

	subjectID, _ := stateUpdates["sub"].(string)
	jti, _ := claims["jti"].(string)

	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	txn := sm.sdfEngine.Store.Begin()
	defer txn.Commit()

	hashedSub := hashSubject([]byte(subjectID))
	if sm.isDeviceBlacklisted(txID, txn, hashedSub) {
		return "", errors.New("device identity is permanently blacklisted")
	}

	if sm.isSessionRevoked(txID, txn, jti) {
		return "", errors.New("session has been revoked")
	}

	return subjectID, nil
}

// ExtractJTI returns the session id (jti claim) from a session_id cookie value.
func (sm *SessionManager) ExtractJTI(cookieValue string) (string, error) {
	cookieValue = strings.TrimPrefix(cookieValue, "user_session_")
	token, _, err := new(jwt.Parser).ParseUnverified(cookieValue, jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["jti"] == nil {
		return "", errors.New("malformed token claims")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return "", errors.New("missing jti")
	}
	return jti, nil
}

// isDeviceBlacklisted reports a permanent device ban (blacklist:device:* ledger REVOKE).
func (sm *SessionManager) isDeviceBlacklisted(txID uint64, txn ultimate_db.TxnHandle, hashedSub string) bool {
	targetAddress := "blacklist:device:" + hashedSub
	worldStateKey := "state:pop:" + targetAddress

	var stateData []byte
	var err error
	if stateData, err = ultimate_db.GlobalCacheStore.Read(txID, worldStateKey); err != nil {
		stateData, err = sm.sdfEngine.Store.Get(txn, []byte(worldStateKey))
		if err != nil || len(stateData) == 0 {
			return false
		}
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(stateData, &meta); err != nil {
		return false
	}

	nonceVal, ok := meta["nonce"].(float64)
	if !ok {
		return false
	}

	ledgerKey := fmt.Sprintf("transaction_ledger:pop:%s:%d", targetAddress, uint64(nonceVal))
	var ledgerData []byte
	if ledgerData, err = ultimate_db.GlobalCacheStore.Read(txID, ledgerKey); err != nil {
		ledgerData, err = sm.sdfEngine.Store.Get(txn, []byte(ledgerKey))
		if err != nil || len(ledgerData) == 0 {
			return false
		}
	}

	var ledger map[string]interface{}
	if err := json.Unmarshal(ledgerData, &ledger); err != nil {
		return false
	}

	return ledger["method"] == "REVOKE"
}

func (sm *SessionManager) isSessionRevoked(txID uint64, txn ultimate_db.TxnHandle, jti string) bool {
	targetAddress := "blacklist:jti:" + jti
	worldStateKey := "state:grant:" + targetAddress

	var stateData []byte
	var err error
	if stateData, err = ultimate_db.GlobalCacheStore.Read(txID, worldStateKey); err != nil {
		stateData, err = sm.sdfEngine.Store.Get(txn, []byte(worldStateKey))
		if err != nil || len(stateData) == 0 {
			return false
		}
	}

	var meta map[string]interface{}
	if err := json.Unmarshal(stateData, &meta); err != nil {
		return false
	}

	nonceVal, ok := meta["nonce"].(float64)
	if !ok {
		return false
	}

	ledgerKey := fmt.Sprintf("transaction_ledger:grant:%s:%d", targetAddress, uint64(nonceVal))
	var ledgerData []byte
	if ledgerData, err = ultimate_db.GlobalCacheStore.Read(txID, ledgerKey); err != nil {
		ledgerData, err = sm.sdfEngine.Store.Get(txn, []byte(ledgerKey))
		if err != nil || len(ledgerData) == 0 {
			return false
		}
	}

	var ledger map[string]interface{}
	if err := json.Unmarshal(ledgerData, &ledger); err != nil {
		return false
	}

	return ledger["method"] == "REVOKE"
}

// =============================================================================
// Session Management / Revocation Mutation Interface
// =============================================================================

func (sm *SessionManager) RevokeTokenString(tokenString string) error {
	tokenString = strings.TrimPrefix(tokenString, "user_session_")

	p := new(jwt.Parser)
	token, _, err := p.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if jti, ok := claims["jti"].(string); ok {
			return sm.RevokeSession(jti, 24*time.Hour)
		}
	}
	return errors.New("could not extract JTI from token payload")
}

func (sm *SessionManager) RevokeSession(jti string, expiry time.Duration) error {
	targetAddress := "blacklist:jti:" + jti
	script := `blacklist:session(status("revoked"))`
	nonce := getNextNonce(sm.sdfEngine, "grant", targetAddress)

	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "session-admin-service",
		Nonce:         nonce,
		Method:        "REVOKE",
		Profile:       secure_data_format.ProfileGrant,
		Args:          map[string]interface{}{"status": "revoked"},
	}

	_, err := sm.sdfEngine.CompileSecureData(script, tx)
	return err
}

// BlacklistDevice permanently bans a subject/device identity across the mesh.
// Existing and future sessions for that identity fail validation until ClearDeviceBlacklist.
// Storage key remains blacklist:device:<hash> so historical bans stay effective.
func (sm *SessionManager) BlacklistDevice(subject []byte) error {
	hashedSub := hashSubject(subject)
	targetAddress := "blacklist:device:" + hashedSub

	script := `blacklist:device(status("revoked"))`
	nonce := getNextNonce(sm.sdfEngine, "pop", targetAddress)

	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "session-admin-service",
		Nonce:         nonce,
		Method:        "REVOKE",
		Profile:       secure_data_format.ProfileProofOfPoss,
		Args:          map[string]interface{}{"status": "revoked"},
	}

	_, err := sm.sdfEngine.CompileSecureData(script, tx)
	return err
}

// RevokeDevice is a deprecated alias for BlacklistDevice.
func (sm *SessionManager) RevokeDevice(subject []byte) error {
	return sm.BlacklistDevice(subject)
}

// ClearDeviceBlacklist lifts a prior BlacklistDevice so the subject can authenticate again.
// Passkey reset must call this (must not leave a permanent device ban).
func (sm *SessionManager) ClearDeviceBlacklist(subject []byte) error {
	if sm == nil || sm.sdfEngine == nil {
		return errors.New("session manager unavailable")
	}
	return sm.clearDeviceBlacklistAddress("blacklist:device:" + hashSubject(subject))
}

// ClearDeviceRevocation is a deprecated alias for ClearDeviceBlacklist.
func (sm *SessionManager) ClearDeviceRevocation(subject []byte) error {
	return sm.ClearDeviceBlacklist(subject)
}

// ClearAllDeviceBlacklists lifts every device blacklist entry in SDF storage.
// Emergency restore after mass-ban or recovery from compromise cleanup.
func (sm *SessionManager) ClearAllDeviceBlacklists() (int, error) {
	if sm == nil || sm.sdfEngine == nil || sm.sdfEngine.Store == nil {
		return 0, errors.New("session manager unavailable")
	}
	seen := map[string]struct{}{}
	var addrs []string
	add := func(addr string) {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		addrs = append(addrs, addr)
	}

	// Iterate world-state keys: state:pop:blacklist:device:<hash>
	txn := sm.sdfEngine.Store.Begin()
	it := sm.sdfEngine.Store.NewIterator(txn, []byte("state:pop:blacklist:device:"))
	for {
		k, _, err := it.Next()
		if err != nil {
			break
		}
		key := string(k)
		const pfx = "state:pop:"
		if strings.HasPrefix(key, pfx) {
			add(strings.TrimPrefix(key, pfx))
		}
	}
	it.Close()
	_ = txn.Commit()

	// Ledger keys: transaction_ledger:pop:blacklist:device:<hash>:<nonce>
	txn2 := sm.sdfEngine.Store.Begin()
	it2 := sm.sdfEngine.Store.NewIterator(txn2, []byte("transaction_ledger:pop:blacklist:device:"))
	for {
		k, _, err := it2.Next()
		if err != nil {
			break
		}
		parts := strings.Split(string(k), ":")
		// transaction_ledger pop blacklist device hash nonce
		if len(parts) >= 5 {
			add("blacklist:device:" + parts[4])
		}
	}
	it2.Close()
	_ = txn2.Commit()

	// Always cover common bootstrap subjects even if scan misses.
	for _, sub := range []string{"admin", "operator-core", "operator", "root"} {
		add("blacklist:device:" + hashSubject([]byte(sub)))
	}

	cleared := 0
	var firstErr error
	for _, addr := range addrs {
		if err := sm.clearDeviceBlacklistAddress(addr); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		cleared++
	}
	return cleared, firstErr
}

// ClearAllDeviceRevocations is a deprecated alias for ClearAllDeviceBlacklists.
func (sm *SessionManager) ClearAllDeviceRevocations() (int, error) {
	return sm.ClearAllDeviceBlacklists()
}

func (sm *SessionManager) clearDeviceBlacklistAddress(targetAddress string) error {
	if sm == nil || sm.sdfEngine == nil {
		return errors.New("session manager unavailable")
	}
	targetAddress = strings.TrimSpace(targetAddress)
	if !strings.HasPrefix(targetAddress, "blacklist:device:") {
		return fmt.Errorf("invalid device blacklist address %q", targetAddress)
	}
	script := `blacklist:device(status("active"))`
	nonce := getNextNonce(sm.sdfEngine, "pop", targetAddress)

	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "session-admin-service",
		Nonce:         nonce,
		Method:        "GRANT",
		Profile:       secure_data_format.ProfileProofOfPoss,
		Args:          map[string]interface{}{"status": "active"},
	}

	_, err := sm.sdfEngine.CompileSecureData(script, tx)
	return err
}
