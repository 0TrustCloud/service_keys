package service_keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/ultimate_db"
	"github.com/google/go-tpm/legacy/tpm2"
)

// =============================================================================
// Storage & Transaction Mocks for Testing Continuity
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

type mockLockManager struct {
	acquiredLocks map[string]uint64
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
	return nil
}

// =============================================================================
// Cryptographic Hardware Modeling Helpers
// =============================================================================

// makeTPM2BPublic converts a test RSA key into standard TPM serialized public key bytes
func makeTPM2BPublic(priv *rsa.PrivateKey) ([]byte, error) {
	return EncodeTPM2BPublic(&priv.PublicKey)
}

func setupTestEnvironment(t *testing.T) (*ServiceKeyManager, *rsa.PrivateKey) {
	authorityKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating token authority key: %v", err)
	}

	storeMock := &mockKVStore{records: make(map[string][]byte)}
	lockMock := &mockLockManager{acquiredLocks: make(map[string]uint64)}

	sdf, err := secure_data_format.New(storeMock, lockMock, "test-identity-authority", authorityKey)
	if err != nil {
		t.Fatalf("failed initializing underlying SDF compiler: %v", err)
	}

	deviceKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating simulated device key: %v", err)
	}

	skm := NewServiceKeyManager(sdf, nil, nil)
	return skm, deviceKey
}

// =============================================================================
// Test Suites
// =============================================================================

func TestRegisterServiceIdentity_ValidTPM(t *testing.T) {
	skm, deviceKey := setupTestEnvironment(t)
	serviceName := "auth-pod-omega"

	tpmBytes, err := makeTPM2BPublic(deviceKey)
	if err != nil {
		t.Fatalf("failed synthesizing mock TPM format: %v", err)
	}

	err = skm.RegisterServiceIdentity(serviceName, tpmBytes)
	if err != nil {
		t.Fatalf("expected successful device registration, got: %v", err)
	}
}

func TestVerifySignature_Lifecycle(t *testing.T) {
	skm, deviceKey := setupTestEnvironment(t)
	serviceName := "crypto-broker-01"

	tpmBytes, _ := makeTPM2BPublic(deviceKey)
	_ = skm.RegisterServiceIdentity(serviceName, tpmBytes)

	payload := []byte("transaction_ledger_sequence_data_block")
	hash := sha256.Sum256(payload)

	signature, err := rsa.SignPKCS1v15(rand.Reader, deviceKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("failed signing test payload: %v", err)
	}

	// Assert valid signatures pass authentication validations
	if !skm.VerifySignature(serviceName, payload, signature) {
		t.Error("failed validating authenticated signature against registered hardware key map")
	}

	// Assert modified payloads fail verification checks
	corruptedPayload := []byte("transaction_ledger_sequence_data_block_altered")
	if skm.VerifySignature(serviceName, corruptedPayload, signature) {
		t.Error("security violation: engine accepted valid signature on manipulated payload data")
	}
}

func TestVerifyServiceSession_MiddlewareEnforcement(t *testing.T) {
	skm, deviceKey := setupTestEnvironment(t)
	serviceName := "gateway-mesh-node"

	tpmBytes, _ := makeTPM2BPublic(deviceKey)
	_ = skm.RegisterServiceIdentity(serviceName, tpmBytes)

	// Setup mock inner application endpoint handler
	endpointReached := false
	testEndpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		endpointReached = true
		w.WriteHeader(http.StatusOK)
	})

	protectedHandler := skm.VerifyServiceSession(testEndpoint)

	// 1. Verify failure path when DBSC tracking headers are entirely missing
	reqNoHeader := httptest.NewRequest("POST", "/v2/api/mutate", nil)
	wNoHeader := httptest.NewRecorder()
	protectedHandler.ServeHTTP(wNoHeader, reqNoHeader)

	if wNoHeader.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 Unauthorized, got: %d", wNoHeader.Code)
	}

	// 2. Verify success path with genuine, signed cryptographic proofs
	nonce := fmt.Sprintf("%d", time.Now().Unix())
	targetPath := "/v2/api/mutate"
	
	payload := fmt.Sprintf("%s|%s", nonce, targetPath)
	payloadHash := sha256.Sum256([]byte(payload))

	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, deviceKey, crypto.SHA256, payloadHash[:])
	if err != nil {
		t.Fatalf("failed generating proof payload signature: %v", err)
	}
	sigBase64 := base64.StdEncoding.EncodeToString(sigBytes)

	// Assemble matching header string layout -> serviceName:nonce:signature
	proofHeader := fmt.Sprintf("%s:%s:%s", serviceName, nonce, sigBase64)

	reqValid := httptest.NewRequest("POST", targetPath, nil)
	reqValid.Header.Set("X-DBSC-Hardware-Proof", proofHeader)
	wValid := httptest.NewRecorder()

	protectedHandler.ServeHTTP(wValid, reqValid)

	if wValid.Code != http.StatusOK {
		t.Errorf("expected status 200 OK, got: %d (%s)", wValid.Code, wValid.Body.String())
	}

	if !endpointReached {
		t.Error("inner handler boundary was unexpectedly intercepted or ignored by verified credential loop")
	}

	// 3. Verify protection against replay vector manipulation (Expired Proof Window)
	expiredNonce := fmt.Sprintf("%d", time.Now().Add(-5*time.Minute).Unix())
	expiredPayload := fmt.Sprintf("%s|%s", expiredNonce, targetPath)
	expiredHash := sha256.Sum256([]byte(expiredPayload))
	
	expiredSigBytes, _ := rsa.SignPKCS1v15(rand.Reader, deviceKey, crypto.SHA256, expiredHash[:])
	expiredSigBase64 := base64.StdEncoding.EncodeToString(expiredSigBytes)
	expiredHeader := fmt.Sprintf("%s:%s:%s", serviceName, expiredNonce, expiredSigBase64)

	reqExpired := httptest.NewRequest("POST", targetPath, nil)
	reqExpired.Header.Set("X-DBSC-Hardware-Proof", expiredHeader)
	wExpired := httptest.NewRecorder()

	protectedHandler.ServeHTTP(wExpired, reqExpired)

	if wExpired.Code != http.StatusForbidden {
		t.Errorf("expected status 403 Forbidden for replayed anti-replay window proof, got: %d", wExpired.Code)
	}
}
