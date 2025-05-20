package cnsa

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
)

// CNSA 2.0 SSH Algorithm Requirements Summary:
// KEX: ECDH P-384 (ecdh-sha2-nistp384)
// Ciphers: AES-256 GCM (aes256-gcm@openssh.com)
// MACs: HMAC-SHA-384 (hmac-sha2-384)
// Host Keys / Public Key Auth: ECDSA P-384 (ecdsa-sha2-nistp384) or RSA >= 3072 bits
// Signatures: SHA-384 based (e.g., ecdsa-sha2-nistp384, rsa-sha2-512 as SSH standard alternative)

// ValidateSSHPublicKey checks if an ssh.PublicKey meets CNSA 2.0 requirements
// for key type and size/curve (ECDSA P-384 or RSA >= 3072 bits).
func ValidateSSHPublicKey(key ssh.PublicKey) error {
	if key == nil {
		return errors.New("public key is nil")
	}

	// Standard keys implement ssh.CryptoPublicKey.
	cryptoPubKey, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		// Fallback parsing for rare cases or custom key types.
		parsedKey, err := ssh.ParsePublicKey(key.Marshal())
		if err != nil {
			return fmt.Errorf("failed to parse public key type %s for validation: %w", key.Type(), err)
		}
		var okAssert bool
		cryptoPubKey, okAssert = parsedKey.(ssh.CryptoPublicKey)
		if !okAssert {
			// This should be extremely rare if parsing succeeded.
			return fmt.Errorf("parsed key type %s does not expose crypto.PublicKey", parsedKey.Type())
		}
	}

	actualKey := cryptoPubKey.CryptoPublicKey()
	switch pub := actualKey.(type) {
	case *rsa.PublicKey:
		bits := pub.N.BitLen()
		if bits < 3072 {
			return fmt.Errorf("RSA key size (%d bits) is less than CNSA required 3072 bits (key type: %s)", bits, key.Type())
		}
	case *ecdsa.PublicKey:
		if pub.Curve != elliptic.P384() {
			return fmt.Errorf("ECDSA key curve (%s) is not P-384 as required by CNSA (key type: %s)", pub.Curve.Params().Name, key.Type())
		}
	default:
		// This case covers key types not explicitly allowed by CNSA (e.g., Ed25519, DSA).
		return fmt.Errorf("unsupported public key type %T for CNSA validation (key type: %s)", actualKey, key.Type())
	}
	return nil
}

// LoadPrivateHostKeyFromFile loads a private key (PEM format) from the specified file,
// validates its public component against CNSA 2.0 requirements using ValidateSSHPublicKey,
// and returns an ssh.Signer.
func LoadPrivateHostKeyFromFile(keyFile string) (ssh.Signer, error) {
	pemBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read host key file %q: %w", keyFile, err)
	}

	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from %q: %w", keyFile, err)
	}

	// Validate the public key component before returning the signer.
	if err := ValidateSSHPublicKey(signer.PublicKey()); err != nil {
		return nil, fmt.Errorf("host key from %q is not CNSA compliant: %w", keyFile, err)
	}

	return signer, nil
}

// sshServerOption defines the functional option type for configuring an ssh.ServerConfig.
type sshServerOption func(*ssh.ServerConfig) error

// WithHostKeyFile returns an sshServerOption that loads a host key from the given file path
// and adds it to the server config using the AddHostKey method.
// The key is validated for CNSA 2.0 compliance before being added.
func WithHostKeyFile(keyFile string) sshServerOption {
	return func(cfg *ssh.ServerConfig) error {
		signer, err := LoadPrivateHostKeyFromFile(keyFile)
		if err != nil {
			// Error includes context about the key file and compliance failure.
			return err
		}
		cfg.AddHostKey(signer)
		return nil
	}
}

// WithCNSAPublicKeyAuth returns an sshServerOption that configures the PublicKeyCallback.
// The callback first validates the presented public key against CNSA 2.0 requirements.
// If compliant, it delegates to the provided `authorizedKeysCallback` to determine
// if the key is authorized for the user.
// If `authorizedKeysCallback` is nil, this option effectively disables public key auth
// unless the default behavior (accepting any compliant key) is explicitly desired (NOT RECOMMENDED).
func WithCNSAPublicKeyAuth(authorizedKeysCallback func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error)) sshServerOption {
	return func(cfg *ssh.ServerConfig) error {
		cfg.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Step 1: Validate the key's algorithm and size/curve per CNSA.
			if err := ValidateSSHPublicKey(key); err != nil {
				// Key does not meet CNSA crypto requirements. Reject immediately.
				// Log details if necessary: conn.User(), key.Type(), err
				return nil, fmt.Errorf("public key offered by user %q (type: %s) is not CNSA compliant: %w", conn.User(), key.Type(), err)
			}

			// Step 2: Check if the key is authorized for this user.
			if authorizedKeysCallback != nil {
				// Delegate to the actual authorization check (e.g., authorized_keys lookup).
				return authorizedKeysCallback(conn, key)
			}

			// If no authorization callback was provided, reject the key.
			// Allowing any CNSA-compliant key without authorization is insecure.
			return nil, errors.New("public key authentication is configured but no authorization callback was provided")
		}
		return nil
	}
}

// NewSSHServerConfig returns an ssh.ServerConfig configured with cryptographic algorithms
// adhering to CNSA 2.0 classical baseline requirements.
// Requires Go's FIPS 140-3 mode to be enabled (`GODEBUG=fips140=only`).
//
// Defaults:
//   - KEX: ecdh-sha2-nistp384
//   - Ciphers: aes256-gcm@openssh.com
//   - MACs: hmac-sha2-384
//   - Password authentication: DISABLED
//   - Public key authentication: DISABLED (must be enabled via WithCNSAPublicKeyAuth)
//
// CRITICAL: Host keys MUST be added via options (e.g., WithHostKeyFile). The server
// will fail the handshake if no host keys are configured.
func NewSSHServerConfig(options ...sshServerOption) (*ssh.ServerConfig, error) {
	if !fips140.Enabled() {
		return nil, errors.New("FIPS 140-3 mode must be enabled (GODEBUG=fips140=only) for CNSA compliant SSH config")
	}

	cfg := &ssh.ServerConfig{
		// Configure cryptographic algorithms within the embedded ssh.Config.
		Config: ssh.Config{
			KeyExchanges: []string{
				"ecdh-sha2-nistp384", // CNSA specified KEX
			},
			Ciphers: []string{
				"aes256-gcm@openssh.com", // CNSA specified AES-256 (GCM preferred)
			},
			MACs: []string{
				"hmac-sha2-384", // CNSA specified SHA-384 MAC
			},
			// Go's SSH library handles negotiation based on these lists.
			// FIPS mode enforces underlying crypto implementation constraints.
		},

		// Disable password auth by default; prefer public key auth.
		PasswordCallback: nil,

		// Public key auth must be explicitly enabled via WithCNSAPublicKeyAuth option.
		PublicKeyCallback: nil,

		// Host keys MUST be added using cfg.AddHostKey() via options like WithHostKeyFile.
	}

	// Apply functional options to customize the configuration.
	for _, opt := range options {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("failed to apply SSH server option: %w", err)
		}
	}

	// Note: Cannot programmatically check for host keys here as the field is unexported.
	// The caller is responsible for adding at least one host key via options.

	return cfg, nil
}

// sshClientOption defines the functional option type for configuring an ssh.ClientConfig.
type sshClientOption func(*ssh.ClientConfig) error

// WithCNSACompliantHostKeyCallback returns an sshClientOption that sets a HostKeyCallback.
// The configured callback first validates the server's host key against CNSA 2.0 requirements
// using ValidateSSHPublicKey. If the key is compliant, it then invokes the provided
// `underlyingCallback` (e.g., `knownhosts.New` callback) to verify host authenticity.
// An `underlyingCallback` MUST be provided to prevent TOFU attacks.
func WithCNSACompliantHostKeyCallback(underlyingCallback ssh.HostKeyCallback) sshClientOption {
	return func(cfg *ssh.ClientConfig) error {
		if underlyingCallback == nil {
			// This check prevents configurations that are vulnerable to TOFU (Trust On First Use) attacks.
			return errors.New("a non-nil underlying HostKeyCallback (e.g., for known_hosts verification) is required for CNSA compliant host key verification")
		}
		cfg.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// Step 1: Validate the key's algorithm and size/curve per CNSA.
			if err := ValidateSSHPublicKey(key); err != nil {
				return fmt.Errorf("server host key for %s (addr: %s, type: %s) is not CNSA compliant: %w",
					hostname, remote.String(), key.Type(), err)
			}
			// Step 2: Perform standard host key verification (e.g., check known_hosts).
			return underlyingCallback(hostname, remote, key)
		}
		return nil
	}
}

// NewSSHClientConfig returns an ssh.ClientConfig configured with cryptographic algorithms
// adhering to CNSA 2.0 classical baseline requirements.
// Requires Go's FIPS 140-3 mode to be enabled (`GODEBUG=fips140=only`) and a non-empty username.
//
// Defaults:
//   - KEX: ecdh-sha2-nistp384
//   - Ciphers: aes256-gcm@openssh.com
//   - MACs: hmac-sha2-384
//   - HostKeyAlgorithms (accepted host key signature types): ecdsa-sha2-nistp384, rsa-sha2-512
//
// CRITICAL: A HostKeyCallback MUST be provided via options (e.g., using
// WithCNSACompliantHostKeyCallback wrapping a known_hosts implementation) to ensure
// server authenticity and prevent MITM attacks.
// CRITICAL: Authentication methods (e.g., `ssh.PublicKeys(...)`) MUST be configured
// by the caller by setting the `Auth` field on the returned config or via options.
func NewSSHClientConfig(username string, options ...sshClientOption) (*ssh.ClientConfig, error) {
	if !fips140.Enabled() {
		return nil, errors.New("FIPS 140-3 mode must be enabled (GODEBUG=fips140=only) for CNSA compliant SSH config")
	}
	if username == "" {
		return nil, errors.New("username is required for SSH client config")
	}

	cfg := &ssh.ClientConfig{
		// Configure cryptographic algorithms within the embedded ssh.Config.
		Config: ssh.Config{
			KeyExchanges: []string{
				"ecdh-sha2-nistp384", // CNSA specified KEX
			},
			Ciphers: []string{
				"aes256-gcm@openssh.com", // CNSA specified AES-256 (GCM preferred)
			},
			MACs: []string{
				"hmac-sha2-384", // CNSA specified SHA-384 MAC
			},
		},

		User: username,

		// HostKeyAlgorithms restricts the signature algorithms the client accepts for host keys.
		// It aligns with the keys validated by ValidateSSHPublicKey.
		// "rsa-sha2-512" is used as the standard SSH identifier for strong RSA signatures.
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoECDSA384, // "ecdsa-sha2-nistp384" (ECDSA P-384 key with SHA-384 digest)
			"rsa-sha2-512",      // RSA key (>=3072 bits) with SHA-512 digest
		},

		// Auth methods must be provided by the caller. Initialize as empty.
		Auth: []ssh.AuthMethod{},

		// HostKeyCallback MUST be set via options for secure operation. Initialize as nil.
		HostKeyCallback: nil,
	}

	// Apply functional options to customize the configuration.
	for _, opt := range options {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("failed to apply SSH client option: %w", err)
		}
	}

	// Enforce HostKeyCallback requirement post-options.
	if cfg.HostKeyCallback == nil {
		return nil, errors.New("critical security requirement: an SSH HostKeyCallback must be configured (e.g., using WithCNSACompliantHostKeyCallback)")
	}

	return cfg, nil
}

// LoadAuthorizedKeysFromFile loads public keys from a file path, parsing the content
// in standard authorized_keys format (one key per line, comments allowed).
// It validates each parsed key using the provided `validator` function (e.g., ValidateSSHPublicKey).
// If a non-compliant key is found, it returns an error.
// Returns a map where keys are the base64-encoded wire format of the authorized public keys.
func LoadAuthorizedKeysFromFile(filePath string, validator func(key ssh.PublicKey) error) (map[string]bool, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read authorized keys file %q: %w", filePath, err)
	}

	authorizedKeysMap := make(map[string]bool)

	for len(content) > 0 {
		// ssh.ParseAuthorizedKey consumes one key entry, handles comments/whitespace,
		// and returns the remainder of the content.
		key, _, _, rest, err := ssh.ParseAuthorizedKey(content)
		if err != nil {
			if err == io.EOF { // Expected end of file after processing all keys.
				break
			}
			// Indicates a malformed entry in the file.
			return nil, fmt.Errorf("failed to parse entry in authorized keys file %q: %w", filePath, err)
		}

		// If a key was successfully parsed (ParseAuthorizedKey skips comment/empty lines)
		if key != nil {
			// Validate the key against CNSA requirements using the provided validator.
			if validator != nil {
				if errVal := validator(key); errVal != nil {
					// Strict Enforcement: A non-compliant key in the authorized list is an error.
					return nil, fmt.Errorf("non-CNSA compliant key (type: %s) found in authorized keys file %s: %w", key.Type(), filePath, errVal)
				}
			}
			// Store the authorized key in its wire format (used by ssh library for comparison).
			authorizedKeysMap[string(key.Marshal())] = true
		}

		// Continue parsing with the remainder of the file content.
		content = rest
	}

	// After parsing the entire file, check if any valid keys were actually found.
	if len(authorizedKeysMap) == 0 {
		// Return an error if the file was successfully read but contained no valid keys
		// (or only comments/invalid entries). This prevents silent failures.
		return nil, fmt.Errorf("no valid/compliant authorized keys found in %q", filePath)
	}

	return authorizedKeysMap, nil
}

// ExampleAuthorizedKeysCallback returns an ssh.PublicKeyCallback function suitable for use
// with `WithCNSAPublicKeyAuth`. It checks if the public key presented by the client
// exists in the `authorizedKeysMap`.
// This map should be pre-populated by `LoadAuthorizedKeysFromFile` using a CNSA-compliant validator.
func ExampleAuthorizedKeysCallback(authorizedKeysMap map[string]bool) func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
	// Return the actual callback function.
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if authorizedKeysMap == nil {
			// Defensive check: should not happen if used correctly, but prevents nil panic.
			return nil, errors.New("internal error: authorized keys map is nil")
		}
		// Use the wire format of the key for lookup, matching how LoadAuthorizedKeysFromFile stores them.
		keyString := string(key.Marshal())
		if authorizedKeysMap[keyString] {
			// Key is present in the map, therefore it's authorized.
			// Return nil permissions (no specific restrictions).
			return nil, nil
		}
		// Key not found in the map.
		return nil, fmt.Errorf("public key for user %q is not authorized", conn.User())
	}
}
