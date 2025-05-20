package cnsa

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

type tlsOption func(*tls.Config) error

// WithX509KeyPair loads a certificate and private key from the specified
// files and adds them to the TLS configuration.
func WithX509KeyPair(certFile, keyFile string) tlsOption {
	return func(cfg *tls.Config) error {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}

		if err = ValidateTLSCertificate(&cert); err != nil {
			return fmt.Errorf("failed to validate server certificate: %w", err)
		}

		cfg.Certificates = append(cfg.Certificates, cert)
		return nil
	}
}

// WithSessionTicketsEnabled enables session tickets in the TLS configuration.
// Although th is is not required or recommended by FIPS or CNSA 2.0, it isn't
// explicitly prohibited, and may be allowed by a specific ATO. We default to
// disabling session tickets to be conservative and avoid any potential security
// issues. This optional function can be used to re-enable session tickets.
func WithSessionTicketsEnabled() tlsOption {
	return func(cfg *tls.Config) error {
		cfg.SessionTicketsDisabled = false
		return nil
	}
}

// WithMutualTLS configures the server to require and verify client certificates
// signed by a CA present in the provided clientCAPool. While not required or
// discussed in CNSA 2.0, other government standards (e.g., NIST/CMMC) do require
// mTLS in certain contexts. This function is provided as an optional convenience
// for those who need it. It is not required for CNSA 2.0 compliance.
func WithMutualTLS(clientCAPool *x509.CertPool) tlsOption {
	return func(cfg *tls.Config) error {
		if clientCAPool == nil {
			// Require a pool. Using system roots (nil pool) is generally
			// insecure/undesirable for specific client CA validation.
			return errors.New("mutual TLS requires a non-nil clientCAPool")
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = clientCAPool
		return nil
	}
}

// WithMutualTLSFromFile configures the server to require and verify client
// certificates signed by a CA present in the specified clientCAFile (PEM format).
// This is convenience wrapper around WithMutualTLS that loads the CA file into a
// CertPool. It is not required for CNSA 2.0 compliance.
func WithMutualTLSFromFile(clientCAFile string) tlsOption {
	return func(cfg *tls.Config) error {
		caCertPEM, err := os.ReadFile(clientCAFile)
		if err != nil {
			return fmt.Errorf("failed to read client CA file %q: %w", clientCAFile, err)
		}

		clientCAPool := x509.NewCertPool()
		if ok := clientCAPool.AppendCertsFromPEM(caCertPEM); !ok {
			return fmt.Errorf("failed to append client CA certs from %q", clientCAFile)
		}

		// Delegate to the other function's logic or set directly
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = clientCAPool
		return nil
	}
}

// WithRejectAES128 adds a VerifyConnection hook that will reject any TLS 1.3
// handshake negotiating the AES-128 cipher suite, as it is not allowed by
// CNSA 2.0, but we have no way to disable it directly in the Go standard library.
// This is a workaround (or dare I say, dirty hack), and is not clean because it
// allows the negotiation to complete before severing the connection. I don't
// recommend using this in production, but offer it merely as a convenience for
// those who have hard requirements to reject AES-128 cipher suites.
func WithRejectAES128() tlsOption {
	return func(cfg *tls.Config) error {
		// Wrap any existing VerifyConnection to preserve other checks
		prev := cfg.VerifyConnection
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if cs.CipherSuite == tls.TLS_AES_128_GCM_SHA256 {
				return errors.New("cnsa does not allow TLS_AES_128_GCM_SHA256")
			}
			// call previous callback if set
			if prev != nil {
				return prev(cs)
			}
			return nil
		}
		return nil
	}
}

// NewTLSConfig returns a TLS configuration that adheres to CNSA 2.0,
// keeping only TLS 1.3 with "TLS_AES_256_GCM_SHA384" as the cipher
// suite with a key exchange of ECDHE with P-384 or RSA with at least
// 3072 bits.
func NewTLSConfig(options ...tlsOption) (*tls.Config, error) {
	if !fips140.Enabled() {
		// The TLS 1.3 cipher suites are fixed in Go, and cannot simply be
		// modified through the CipherSuites field, as the field applies to
		// TLS 1.2 and below. The fixed TLS 1.3 cipher list currently includes
		// the following three cipher suites:
		//  - TLS_AES_256_GCM_SHA384
		//  - TLS_AES_128_GCM_SHA256 (not allowed by CNSA 2.0)
		//  - TLS_CHACHA20_POLY1305_SHA256 (not allowed by CNSA 2.0)
		//
		// We can disable "TLS_CHACHA20_POLY1305_SHA256" by simply enabling
		// the FIPS 140-3 module. CNSA compliance is about more than just the
		// TLS configuration anyways, mandating the use of FIPS modules.
		//
		// In the future, we can potentially add a way to check for other FIPS
		// modules (such as dynamically linking into OpenSSL, like in Microsoft's
		// Go fork or the Red Hat toolchain). For the vast majority of consumers,
		// the built-in FIPS 140-3 module is easiest, albeit not yet certified
		// by CMVP.
		//
		// Known Issue: The "TLS_AES_128_GCM_SHA256" is allowed by FIPS 140-3
		// and included in the default Go TLS 1.3 cipher suites. That means we
		// have no way to disable this one without changes to the Go standard
		// library.
		return nil, errors.New("the fips 140-3 mode must be enabled")
	}
	cfg := &tls.Config{
		// TLS 1.3 is required
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,

		// The "CipherSuites" field only applies to TLS 1.2 and below. We set
		// it to an empty list to prevent confusion with the TLS 1.3 cipher list,
		// but more importantly to reinforce that TLS 1.2 ciphers are not allowed.
		CipherSuites: []uint16{},

		// FIPS 140-3 mode uses tls.CurveP256, tls.CurveP384, and tls.CurveP521,
		// but CNSA 2.0 only allows P-384.
		CurvePreferences: []tls.CurveID{tls.CurveP384},

		// Ensures the strongest supported cipher suite is selected. Less
		// relevant in TLS 1.3 (where suites are tied to key exchange),
		// but harmless and good practice.
		PreferServerCipherSuites: true,

		// Renegotation is explicitly probibited. This should already be the
		// default for Go servers.
		Renegotiation: tls.RenegotiateNever,

		// (Optional) Disable session tickets based on accreditation
		// requirements. Disabling is recommended but not required by FIPS or
		// CNSA. This can be re-enabled if allowed by a specific ATO.
		SessionTicketsDisabled: true,

		// Verify peer certificate chain meets all requirements
		VerifyPeerCertificate: verifyPeerCertificates,
	}

	// Apply all options to the TLS configuration
	for _, opt := range options {
		if err := opt(cfg); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

// isSelfSigned returns true for all self-signed certificates.
func isSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}

// isTrustAnchor returns true for the final self-signed root certificate in a chain
func isTrustAnchor(cert *x509.Certificate) bool {
	// Basic checks
	if !cert.IsCA || !isSelfSigned(cert) {
		return false
	}

	// Subject and Issuer should match for self-signed
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}

	// If extensions are present, they should match
	if len(cert.SubjectKeyId) > 0 && len(cert.AuthorityKeyId) > 0 {
		return bytes.Equal(cert.SubjectKeyId, cert.AuthorityKeyId)
	}

	return true
}

// validateCertificatePublicKey checks the public key of a certificate and
// returns an error if it does not meet CNSA 2.0 requirements.
//
// RSA keys: 3072+ bits
// ECDSA keys: P-384 (larger curves like P-521 are not permitted)
func validateCertificatePublicKey(cert *x509.Certificate) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		if bits < 3072 {
			return fmt.Errorf("certificate (%s): RSA key size of %d bits is less than 3072 bits",
				cert.Subject.CommonName, bits)
		}
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P384() {
			return fmt.Errorf("certificate (%s): ECDSA key curve %s is not P-384", cert.Subject.CommonName, pub.Curve.Params().Name)
		}
	default:
		return fmt.Errorf("certificate (%s): unsupported public key type %T", cert.Subject.CommonName, pub)
	}
	return nil
}

// isValidSignatureAlgorithmID returns true if the signature algorithm ID is compliant
// with CNSA 2.0 requirements. Only SHA-384 is allowed for all signatures, including
// RSA and ECDSA signatures. SHA-512 is not allowed for any signature algorithm.
func isValidSignatureAlgorithmID(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		return true
	default:
		return false
	}
}

// verifyPeerCertificates verifies the certificate chain and returns true if
// the certificate chains meet CNSA 2.0 requirements. Go has already verified
// the signature itself during chain building, so we are really just checking
// if the algorithm used to sign the certificate is compliant with CNSA 2.0
// requirements.
func verifyPeerCertificates(_ [][]byte, verifiedChains [][]*x509.Certificate) error {

	// Check if the certificate chain is empty
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return errors.New("no verified chains")
	}

	// Audit every chain and reject on the first violation. For each chain, verify
	// the entire chain, including root and intermediate CAs. Other similar
	// libraries and Go code on GitHub will only verify the leaf certificate in
	// verifiedChains[0][0]. However, NSA's CSfC Key-Management Annex (v2.1)
	// mandates that all certificates in the chain be verified for high-value
	// national security systems, per rule KM-10.
	for cIdx, chain := range verifiedChains {
		for i, cert := range chain {

			if err := validateCertificatePublicKey(cert); err != nil {
				return fmt.Errorf("chain %d, cert %d: %w", cIdx, i, err)
			}

			// Skip signature check for trust anchors (self-signed root certs)
			if !isTrustAnchor(cert) {
				if !isValidSignatureAlgorithmID(cert.SignatureAlgorithm) {
					return fmt.Errorf("chain %d, cert %d (%s): invalid signature algorithm %s",
						cIdx, i, cert.Subject.CommonName, cert.SignatureAlgorithm)
				}
			}

		}
	}

	return nil
}

// ValidateX509Certificate checks if an X509 certificate meets CNSA 2.0 requirements
func ValidateX509Certificate(cert *x509.Certificate) error {
	if err := validateCertificatePublicKey(cert); err != nil {
		return err
	}
	if !isValidSignatureAlgorithmID(cert.SignatureAlgorithm) {
		return fmt.Errorf("server certificate (%s) uses invalid signature algorithm %s",
			cert.Subject.CommonName, cert.SignatureAlgorithm)
	}
	return nil
}

// ValidateTLSCertificate verifies that the actual server certificate
// loaded by the TLS server meets CNSA 2.0 requirements as well. This is
// important because the other functions only verify the certificate chain
// of peer certificates, not the server certificate itself.
func ValidateTLSCertificate(cert *tls.Certificate) error {
	if len(cert.Certificate) == 0 {
		return errors.New("loaded key pair contains no certificate")
	}
	leafCert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse leaf certificate: %w", err)
	}
	if err := ValidateX509Certificate(leafCert); err != nil {
		return err
	}
	return nil
}
