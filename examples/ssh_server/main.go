//go:debug fips140=on
package main

import (
	"crypto/fips140"
	"log"
	"net"

	"github.com/juburr/cnsa"
	"golang.org/x/crypto/ssh"
)

func main() {
	// GODEBUG=fips140=only must be set
	if !fips140.Enabled() {
		log.Fatalf("FIPS 140-3 mode must be enabled (set GODEBUG=fips140=on)")
	}

	// --- Setup Server ---
	// Create authorized_keys file for testing
	// Ensure server_host_ecdsa_p384_key and user_ecdsa_p384_key.pub are CNSA compliant
	// For example, generate with:
	// ssh-keygen -t ecdsa -b 384 -f server_host_ecdsa_p384_key -N ""
	// ssh-keygen -t ecdsa -b 384 -f user_ecdsa_p384_key -N ""
	// cat user_ecdsa_p384_key.pub > authorized_keys_file

	authKeysMap, err := cnsa.LoadAuthorizedKeysFromFile("authorized_keys_file", cnsa.ValidateSSHPublicKey)
	if err != nil {
		log.Fatalf("Failed to load authorized keys: %v", err)
	}

	serverConfig, err := cnsa.NewSSHServerConfig(
		cnsa.WithHostKeyFile("server_host_ecdsa_p384_key"), // or an RSA 3072+ bit key
		cnsa.WithCNSAPublicKeyAuth(cnsa.ExampleAuthorizedKeysCallback(authKeysMap)),
	)
	if err != nil {
		log.Fatalf("Failed to create CNSA SSH server config: %v", err)
	}

	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		log.Fatalf("Failed to listen on 0.0.0.0:2222: %v", err)
	}
	log.Println("SSH server listening on 0.0.0.0:2222")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection: %v", err)
			continue
		}

		sshConn, chans, reqs, err := ssh.NewServerConn(conn, serverConfig)
		if err != nil {
			log.Printf("Failed to handshake: %v", err)
			continue
		}
		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

		go ssh.DiscardRequests(reqs)
		go handleChannels(chans)
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	for newChannel := range chans {
		// Handle new channels (e.g., "session")
		// This is a placeholder; a real server would handle channel types
		log.Printf("Incoming channel: %s", newChannel.ChannelType())
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			continue
		}
		defer channel.Close()

		// Example: Simple echo handler for session
		go func(in <-chan *ssh.Request) {
			for req := range in {
				log.Printf("Request type: %s, WantReply: %v", req.Type, req.WantReply)
				if req.WantReply {
					req.Reply(true, nil) // Or false, payload
				}
				// Handle "shell", "exec", "pty-req" etc.
			}
		}(requests)

		// Simple interaction
		channel.Write([]byte("CNSA Compliant SSH Server!\r\n"))
	}
}
