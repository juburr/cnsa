<div align="center">
  <img align="center" width="200" src="assets/logos/cnsa.png" alt="CNSA">
  <h1>CNSA Lite for Go</h1>
  <i>A partial implementation of NSA's Commercial National Security Algorithm Suite (CNSA) 2.0 in Go. This is a "lite" version designed to harden the existing classical baseline algorithms only.</i><br /><br />
</div>

## Summary
This package imposes additional restrictions atop Go's FIPS 140-3 module, aiming to approximate the CNSA 2.0 requirements for classical baseline algorithms only. **It is a best-effort approach operating within the constraints of Go's standard libraries and does not achieve formal compliance with CNSA 2.0 at this time**.

Most notably, it does not include the future quantum-resistant algorithms specified in CNSA 2.0, such as ML-KEM-1024 and ML-DSA-87, which are central to the suite's objectives. Additionally, Go currently lacks a mechanism to disable the AES-128 variant within the TLS 1.3 cipher suite list (`TLS_AES_128_GCM_SHA256`).

Despite these known limitations, this package can still be viewed as providing additional hardening above and beyond what's provided in FIPS 140-3, working in the general direction of CNSA 2.0 and attempting to satisfy several of the key requirements outlined in the discussion section of the most recent update to DISA STIG V-265634.

## TLS Hardening Details

This package provides a hardened `*tls.Config` object to achieve the following objectives:

* **Enforces TLS 1.3 Only:**
    * Connections are restricted exclusively to TLS 1.3. TLS 1.2 and all prior versions are disabled.
* **Restricts Key Exchange Mechanism:**
    * Mandates Elliptic Curve Diffie-Hellman Ephemeral key exchange using the P-384 curve (ECDHE P-384).
    * Traditional RSA key exchange (key transport) is not used, as it is deprecated in TLS 1.3.
* **Governs Certificate Cryptography:**
    * **Public Keys:** Requires that the public keys in the server's certificate (and any peer certificates, if mTLS is used) are either:
        * RSA with a minimum key length of 3072 bits, or
        * ECDSA using the P-384 curve.
    * **Signature Algorithms:** Mandates that all certificates in the verified chain (including the server's own certificate and any intermediate/peer certificates) are signed using SHA-384 (e.g., `SHA384WithRSA`, `ECDSAWithSHA384`, `SHA384WithRSAPSS`).
* **Manages TLS 1.3 Cipher Suites (within Go's FIPS mode limitations):**
    * Relies on Go's FIPS 140-3 mode (activated by `GODEBUG=fips140=on`) being enabled. This inherently disables certain cipher suites not permitted by FIPS, such as `TLS_CHACHA20_POLY1305_SHA256`.
    * The primary targeted CNSA 2.0 compliant cipher suite is `TLS_AES_256_GCM_SHA384`.
    * **Limitation:** Go's standard library (as of version 1.24) does not provide a direct mechanism to remove `TLS_AES_128_GCM_SHA256` from the list of available TLS 1.3 cipher suites. This suite is allowed by FIPS 140-3 but not by CNSA 2.0.
    * **Workaround:** An optional function (`cnsa.WithRejectAES128()`) is provided, which can be used to configure the `*tls.Config` to reject any connection that successfully negotiates `TLS_AES_128_GCM_SHA256` after the handshake is complete.
* **Enhances Session Security:**
    * Disables TLS session tickets by default. This is a conservative security measure, though session tickets can be re-enabled via an option (`cnsa.WithSessionTicketsEnabled()`) if permitted by specific operational requirements.
    * Prohibits TLS renegotiation (set to `tls.RenegotiateNever`).
* **Server Cipher Suite Preference:**
    * The `PreferServerCipherSuites` flag is set to `true`. While its impact is reduced in TLS 1.3 (where cipher suite selection is more deterministic), it's included as a general hardening practice.

It's crucial to understand that this package provides a best-effort hardening towards CNSA 2.0 for classical algorithms and does not achieve formal compliance, particularly due to the aforementioned cipher suite limitation and the absence of quantum-resistant algorithms.

## TLS Key Requirements

| Component | NSA Suite B Cryptography (2005) | CNSA 1.0 (2016) | CNSA 2.0 (2022) - Classical Baseline | CNSA 2.0 (2022) - Future Quantum-Resistant |
| ------------- | ------------- | ------------- | ------------- | ------------- |
| Symmetric Crypto | AES-128 and AES-256 | AES-256 | AES-256 | AES-256 |
| Hash / MAC | SHA-256 and SHA-384 | SHA-384 | SHA-384 | SHA-384 |
| Key Exchange (KE) | ECDH P-256, P-384 | DH/RSA >= 3072, ECDH P-384 | DH/RSA >= 3072, ECDH P-384 | CRYSTALS-Kyber (ML-KEM) |
| Digital Signatures (DS) | ECDSA P-256, P-384 | RSA >= 3072, ECDSA P-384 | RSA >= 3072, ECDSA P-384 | CRYSTALS-Dilithium (ML-DSA) |
| Software/Firmware Signatures | (As above) | (As above) | (As above, noting transition) | SPHINCS+ (SLH-DSA), Dilithium |
| TLS Profile | TLS 1.2 (AES-GCM/ECC) | TLS >= 1.2 (CNSA 1.0 suites) | TLS >= 1.3 (using classical suites) | TLS >= 1.3 (Initially Hybrid KE, then QR KE/DS) |
| Primary Focus | ECC Adoption | Stronger Classical Algorithms | Maintain Strong Classical Baseline During Transition | Mandated Transition to PQC/QR |


## TLS Example Usage

```go
//go:debug fips140=on
package main

import (
	"crypto/fips140"
	"log"
	"net/http"

	"github.com/juburr/cnsa"
)

func main() {
	if !fips140.Enabled() {
		log.Fatalf("FIPS 140-3 mode must be enabled (set GODEBUG=fips140=on)")
	}

	cfg, err := cnsa.NewTLSConfig(
		cnsa.WithX509KeyPair("server.crt", "server.key"),
	)
	if err != nil {
		log.Fatalf("Failed to create TLS config: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, CNSA World!"))
	})

	svr := &http.Server{
		Addr:      "localhost:443",
		Handler:   mux,
		TLSConfig: cfg,
	}

	log.Println("Server is listening on https://localhost:443")
	log.Fatal(svr.ListenAndServeTLS("", ""))
}
```
