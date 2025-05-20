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
