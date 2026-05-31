
# Service Keys (service_keys)

`service_keys` provides a hardware-bound identity and session management layer for service-to-service communication. By leveraging **TPM 2.0 (Trusted Platform Module)** and **DBSC (Device Bound Session Credentials)**, this package ensures that machine-to-machine requests are cryptographically pinned to specific hardware, mitigating the risks of token theft and replay attacks.

---

## Architecture

The service authentication flow follows a zero-trust model:

1. **Registration:** Agents register their TPM-backed public key with the central authority.
2. **Attestation:** The central server validates the TPM structure using `go-tpm` protocols.
3. **Verification:** Instead of static secrets, agents generate an ephemeral signature using their local TPM hardware.
4. **Binding:** The server validates the hardware signature against the registered key, ensuring the session is strictly bound to the physical device.

---

## Getting Started

### Prerequisites

* `go-tpm` for TPM 2.0 communication.
* `ultimate_db` for secure persistence.
* `webauthnext` for core identity structures.

### Installation

```bash
go get github.com/gddisney/service_keys

```

### Usage

#### 1. Service Agent Registration

Register a machine identity by providing its TPM 2.0 public key structure (as a `TPM2B_PUBLIC` byte slice).

```go
skm := &service_keys.ServiceKeyManager{DB: db}
err := skm.RegisterServiceIdentity("my-internal-agent", tpmPubBytes)

```

#### 2. Protecting API Routes

Use the `VerifyServiceSession` middleware to protect internal API endpoints. Agents must provide a custom header `X-DBSC-Hardware-Proof`.

```go
r.Mux.HandleFunc("POST /api/v1/internal/agent/task", skm.VerifyServiceSession(func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Authorized"))
}))

```

#### 3. Agent-Side Proof Generation

Agents construct a proof by signing a payload containing a timestamp (nonce) and the request path:
`{service_name}:{nonce}:{signature_base64}`

---

## Security Guarantees

* **Hardware Pinning:** Identity is tied to the physical TPM, making keys non-exportable and resistant to extraction.
* **Replay Protection:** Every request requires a fresh, time-limited nonce signed by the TPM.
* **Minimal Trust Surface:** Removes the need to manage and rotate long-lived `client_secret` strings.

## Testing

Run the comprehensive test suite to verify hardware identity decoding and signature verification logic:

```bash
go test -v ./...

```


## License

This project is licensed under the **MIT License**.
