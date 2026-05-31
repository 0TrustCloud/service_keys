package service_keys

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/0TrustCloud/logger"
	"github.com/0TrustCloud/secure_data_format"
	"github.com/0TrustCloud/ultimate_db"
	"github.com/0TrustCloud/auth_provider"
	"github.com/google/go-tpm/legacy/tpm2"
)

// ServiceKeyManager handles TPM-backed machine identities and hardware attestations.
type ServiceKeyManager struct {
	Provider  *webauthnext.Provider
	SdfEngine *secure_data_format.SecureDataEngine
	Logger    *logger.LogDispatcher
}

// NewServiceKeyManager creates an active service identity coordinator instance.
func NewServiceKeyManager(
	sdf *secure_data_format.SecureDataEngine,
	provider *webauthnext.Provider,
	sysLog *logger.LogDispatcher,
) *ServiceKeyManager {
	return &ServiceKeyManager{
		Provider:  provider,
		SdfEngine: sdf,
		Logger:    sysLog,
	}
}

// LoadOrCreateManager validates context properties and instantiates the manager cleanly.
func LoadOrCreateManager(
	sdf *secure_data_format.SecureDataEngine,
	sysLog *logger.LogDispatcher,
) (*ServiceKeyManager, error) {
	if sdf == nil {
		return nil, fmt.Errorf("cannot instantiate identity management infrastructure without an active SDF engine reference")
	}
	return &ServiceKeyManager{
		SdfEngine: sdf,
		Logger:    sysLog,
	}, nil
}

// RegisterServiceIdentity binds a machine asset configuration record to the local and distributed index tiers.
func (s *ServiceKeyManager) RegisterServiceIdentity(
	name string,
	tpmPublicBytes []byte,
) error {
	_, err := tpm2.DecodePublic(tpmPublicBytes)
	if err != nil {
		if s.Logger != nil {
			s.Logger.Error(fmt.Sprintf("Failed to decode TPM2B_PUBLIC structure for %s: %v", name, err))
		}
		return fmt.Errorf("failed to decode TPM2B_PUBLIC structure: %w", err)
	}

	user := &webauthnext.PasskeyUser{
		ID:          tpmPublicBytes,
		Name:        name,
		DisplayName: "Service: " + name,
	}

	val, err := json.Marshal(user)
	if err != nil {
		return err
	}

	targetAddress := "device:identity:" + name
	script := `device:hardware(status("registered"))`

	// Compile transaction envelope via the cryptographic state engine
	tx := secure_data_format.DataInvocation{
		TargetAddress: targetAddress,
		Caller:        "service-key-provisioner",
		Nonce:         0, // Initial registration sequence
		Method:        "REGISTER",
		Profile:       secure_data_format.ProfileProofOfPoss,
		Args: map[string]interface{}{
			"service_name": name,
			"status":       "active",
		},
	}

	_, err = s.SdfEngine.CompileSecureData(script, tx)
	if err != nil {
		return fmt.Errorf("failed compiling hardware registration token: %w", err)
	}

	// Persist the schema-specific identity mapping block into the decoupled data domain slot
	dataKey := "data:user:" + name
	txID := ultimate_db.GlobalCacheStore.BeginOCC()
	_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{dataKey: val}, 0)

	txn := s.SdfEngine.Store.Begin()
	if err := s.SdfEngine.Store.Put(txn, []byte(dataKey), val, 0); err != nil {
		txn.Abort()
		return fmt.Errorf("failed committing hardware profile map to durable storage: %w", err)
	}

	if err := txn.Commit(); err != nil {
		return err
	}

	if s.Logger != nil {
		s.Logger.Audit(
			"system",
			"TPM_REGISTERED",
			"Registered new hardware-backed service identity via SDF: "+name,
		)
	}

	return nil
}

// VerifySignature validates an inbound payload signature against the cryptographic key material stored inside the hardware layout.
func (s *ServiceKeyManager) VerifySignature(
	serviceID string,
	payload []byte,
	signature []byte,
) bool {
	if s.SdfEngine == nil {
		return false
	}

	dataKey := "data:user:" + serviceID
	txID := ultimate_db.GlobalCacheStore.BeginOCC()

	// Optimistic Read Verification Loop: Attempt lock-free cache lookup first
	userBytes, err := ultimate_db.GlobalCacheStore.Read(txID, dataKey)
	if err != nil {
		txn := s.SdfEngine.Store.Begin()
		userBytes, err = s.SdfEngine.Store.Get(txn, []byte(dataKey))
		txn.Commit()

		if err != nil || len(userBytes) == 0 {
			return false
		}
		// Repopulate cache frame to accelerate subsequent validations
		_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{dataKey: userBytes}, 0)
	}

	var user webauthnext.PasskeyUser
	if err := json.Unmarshal(userBytes, &user); err != nil {
		return false
	}

	tpmPubKey, err := tpm2.DecodePublic(user.ID)
	if err != nil {
		return false
	}

	cryptoKey, err := tpmPubKey.Key()
	if err != nil {
		return false
	}

	rsaPubKey, ok := cryptoKey.(*rsa.PublicKey)
	if !ok {
		return false
	}

	hash := sha256.Sum256(payload)
	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hash[:], signature)
	return err == nil
}

// VerifyServiceSession acts as a high-performance HTTP network guardian enforcing continuous DBSC cryptographic proofs.
func (s *ServiceKeyManager) VerifyServiceSession(
	next http.HandlerFunc,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		proof := r.Header.Get("X-DBSC-Hardware-Proof")
		if proof == "" {
			if s.Logger != nil {
				s.Logger.Audit("unknown_agent", "TPM_AUTH_FAILED", "Hardware proof required but missing")
			}
			http.Error(w, "Hardware proof required", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(proof, ":", 3)
		if len(parts) != 3 {
			if s.Logger != nil {
				s.Logger.Audit("unknown_agent", "TPM_AUTH_FAILED", "Malformed DBSC proof payload format")
			}
			http.Error(w, "Malformed DBSC proof", http.StatusBadRequest)
			return
		}

		serviceName := parts[0]
		nonce := parts[1]
		sigBase64 := parts[2]

		dataKey := "data:user:" + serviceName
		txID := ultimate_db.GlobalCacheStore.BeginOCC()

		// Route session verification through high-speed cache window
		userBytes, err := ultimate_db.GlobalCacheStore.Read(txID, dataKey)
		if err != nil {
			txn := s.SdfEngine.Store.Begin()
			userBytes, err = s.SdfEngine.Store.Get(txn, []byte(dataKey))
			txn.Commit()

			if err != nil || len(userBytes) == 0 {
				if s.Logger != nil {
					s.Logger.Audit(serviceName, "TPM_AUTH_FAILED", "Service identity not found in registry")
				}
				http.Error(w, "Service identity not found", http.StatusUnauthorized)
				return
			}
			_ = ultimate_db.GlobalCacheStore.ValidateAndCommit(txID, map[string][]byte{dataKey: userBytes}, 0)
		}

		var user webauthnext.PasskeyUser
		if err := json.Unmarshal(userBytes, &user); err != nil {
			if s.Logger != nil {
				s.Logger.Error("Corrupted identity record for: " + serviceName)
			}
			http.Error(w, "Corrupted identity record", http.StatusInternalServerError)
			return
		}

		tpmPubKey, err := tpm2.DecodePublic(user.ID)
		if err != nil {
			if s.Logger != nil {
				s.Logger.Error("Failed to parse stored TPM key for: " + serviceName)
			}
			http.Error(w, "Failed to parse stored TPM key", http.StatusInternalServerError)
			return
		}

		cryptoKey, err := tpmPubKey.Key()
		if err != nil {
			if s.Logger != nil {
				s.Logger.Error("Failed to extract cryptographic key for: " + serviceName)
			}
			http.Error(w, "Failed to extract cryptographic key", http.StatusInternalServerError)
			return
		}

		signature, err := base64.StdEncoding.DecodeString(sigBase64)
		if err != nil {
			if s.Logger != nil {
				s.Logger.Audit(serviceName, "TPM_AUTH_FAILED", "Invalid base64 signature encoding")
			}
			http.Error(w, "Invalid signature encoding", http.StatusBadRequest)
			return
		}

		payload := fmt.Sprintf("%s|%s", nonce, r.URL.Path)
		payloadHash := sha256.Sum256([]byte(payload))

		rsaPubKey, ok := cryptoKey.(*rsa.PublicKey)
		if !ok {
			if s.Logger != nil {
				s.Logger.Error("Unsupported TPM key type (expected RSA) for: " + serviceName)
			}
			http.Error(w, "Unsupported TPM key type", http.StatusInternalServerError)
			return
		}

		err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, payloadHash[:], signature)
		if err != nil {
			if s.Logger != nil {
				s.Logger.Audit(serviceName, "TPM_AUTH_FAILED", "Hardware signature verification failed")
			}
			http.Error(w, "Hardware signature verification failed", http.StatusForbidden)
			return
		}

		var timestamp int64
		fmt.Sscanf(nonce, "%d", &timestamp)

		// Anti-Replay Attack Window Protection
		if time.Now().Unix()-timestamp > 60 {
			if s.Logger != nil {
				s.Logger.Audit(serviceName, "TPM_AUTH_FAILED", "DBSC Proof expired (Possible replay attack)")
			}
			http.Error(w, "DBSC Proof expired", http.StatusForbidden)
			return
		}

		if s.Logger != nil {
			s.Logger.Info("TPM DBSC hardware session verified for service: " + serviceName)
		}

		next(w, r)
	}
}
