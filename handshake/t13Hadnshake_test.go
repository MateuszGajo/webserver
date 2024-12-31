package handshake

import (
	"fmt"
	"testing"
)

func TestHandshakeOpenT13_AES_128_SHA256(t *testing.T) {
	params := generateRsaCert()

	fmt.Println(params)

	server := startServer(params, TLS13Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-ciphersuites", "TLS_AES_128_GCM_SHA256", "-tls1_3"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT13_AES_256_SHA384(t *testing.T) {
	params := generateRsaCert()

	fmt.Println(params)

	server := startServer(params, TLS13Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-ciphersuites", "TLS_AES_256_GCM_SHA384", "-tls1_3"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT13_CHACHA20_POLY1305_SHA256(t *testing.T) {
	params := generateRsaCert()

	fmt.Println(params)

	server := startServer(params, TLS13Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256", "-tls1_3"}); err != nil {
		t.Error(err)
	}
}
