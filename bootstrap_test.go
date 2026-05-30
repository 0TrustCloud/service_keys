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
	"os"
	"testing"
	"time"

	"github.com/0TrustCloud/ultimate_db"
	"github.com/0TrustCloud/webauthnext"
	"github.com/google/go-tpm/legacy/tpm2"
)

// Helper: Generates a mock TPMT_PUBLIC structure from a standard Go RSA Public Key.
func generateMockTPMPublicKey(pubKey *rsa.PublicKey) ([]byte, error) {
	tpmPub := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSign | tpm2.FlagUserWithAuth,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits:    2048,
			ModulusRaw: pubKey.N.Bytes(),
		},
	}

	// tpmPub.Encode() returns the raw TPMT_PUBLIC byte structure, 
	// which is exactly what tpm2.DecodePublic expects to receive.
	return tpmPub.Encode()
}

// Helper: Properly spins up ultimate_db using DiskManager, BufferPool, and WAL
func setupTestDB(t *testing.T, prefix string) (*ultimate_db.DB, func()) {
	dbPath := prefix + ".db"
	walPath := prefix + ".wal"

	dm, err := ultimate_db.NewDiskManager(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize DiskManager: %v", err)
	}

	bp := ultimate_db.NewBufferPool(dm, 64)
	
	wal, err := ultimate_db.NewBatchingWAL(walPath)
	if err != nil {
		t.Fatalf("Failed to initialize BatchingWAL: %v", err)
	}

	db := ultimate_db.NewDB(bp, wal)

	// Ensure the specific AuthPageID exists before we write to it
	pageID := webauthnext.AuthPageID
	if _, err := bp.FetchPage(pageID); err != nil {
		// Keep allocating new pages until we hit our designated Auth page ID
		for {
			p, err := bp.NewPage()
			if err != nil {
				t.Fatalf("Failed to allocate new page: %v", err)
			}
			bp.UnpinPage(p.ID, true)
			if p.ID >= pageID {
				break
			}
		}
	} else {
		bp.UnpinPage(pageID, false)
	}

	// Return the initialized DB and a cleanup closure to remove files after the test
	cleanup := func() {
		os.Remove(dbPath)
		os.Remove(walPath)
	}

	return db, cleanup
}

func TestVerifyServiceSession_Success(t *testing.T) {
	db, cleanup := setupTestDB(t, "test_success")
	defer cleanup()

	skm := &ServiceKeyManager{
		DB: db,
	}

	serviceName := "test-agent-01"

	agentPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate agent key: %v", err)
	}

	mockTPMBytes, err := generateMockTPMPublicKey(&agentPrivateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to generate mock TPM structure: %v", err)
	}

	// Use the manager to register the identity (this also validates DecodePublic)
	err = skm.RegisterServiceIdentity(serviceName, mockTPMBytes)
	if err != nil {
		t.Fatalf("Failed to register service identity: %v", err)
	}

	// Build the HTTP request
	targetPath := "/api/v1/internal/agent/task"
	req := httptest.NewRequest(http.MethodPost, targetPath, nil)

	nonce := fmt.Sprintf("%d", time.Now().Unix())
	payload := fmt.Sprintf("%s|%s", nonce, targetPath)
	
	hash := sha256.Sum256([]byte(payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, agentPrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatalf("Failed to sign payload: %v", err)
	}

	sigBase64 := base64.StdEncoding.EncodeToString(signature)
	proofHeader := fmt.Sprintf("%s:%s:%s", serviceName, nonce, sigBase64)

	req.Header.Set("X-DBSC-Hardware-Proof", proofHeader)

	rr := httptest.NewRecorder()
	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Agent authorized"))
	})

	handler := skm.VerifyServiceSession(finalHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
		t.Errorf("Response body: %s", rr.Body.String())
	}
}

func TestVerifyServiceSession_MissingHeader(t *testing.T) {
	skm := &ServiceKeyManager{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/internal/agent/task", nil)
	rr := httptest.NewRecorder()

	finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := skm.VerifyServiceSession(finalHandler)
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for missing header, got %v", status)
	}
}

func TestVerifyServiceSession_ExpiredNonce(t *testing.T) {
	db, cleanup := setupTestDB(t, "test_expired")
	defer cleanup()

	skm := &ServiceKeyManager{DB: db}
	serviceName := "test-agent-old"

	agentPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	mockTPMBytes, _ := generateMockTPMPublicKey(&agentPrivateKey.PublicKey)

	err := skm.RegisterServiceIdentity(serviceName, mockTPMBytes)
	if err != nil {
		t.Fatalf("Failed to register service identity: %v", err)
	}

	targetPath := "/api/v1/internal/agent/task"
	req := httptest.NewRequest(http.MethodPost, targetPath, nil)

	// Create an intentionally expired nonce
	oldNonce := fmt.Sprintf("%d", time.Now().Add(-2*time.Hour).Unix())
	payload := fmt.Sprintf("%s|%s", oldNonce, targetPath)
	hash := sha256.Sum256([]byte(payload))
	signature, _ := rsa.SignPKCS1v15(rand.Reader, agentPrivateKey, crypto.SHA256, hash[:])
	
	req.Header.Set("X-DBSC-Hardware-Proof", fmt.Sprintf("%s:%s:%s", serviceName, oldNonce, base64.StdEncoding.EncodeToString(signature)))
	rr := httptest.NewRecorder()

	handler := skm.VerifyServiceSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request){}))
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("Expected 403 Forbidden for expired nonce, got %v", status)
	}
}
