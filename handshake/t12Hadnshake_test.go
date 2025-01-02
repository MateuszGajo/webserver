package handshake

import (
	"testing"
)

func TestHandshakeOpenT12_EDH_RSA_AES128_SHA256(t *testing.T) {
	params := generateRsaCert()

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DHE-RSA-AES128-SHA256", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_EDH_RSA_AES256_SHA256(t *testing.T) {
	params := generateRsaCert()

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DHE-RSA-AES256-SHA256", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_EDH_RSA_AES256_SHA(t *testing.T) {
	params := generateRsaCert()

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DHE-RSA-AES256-SHA", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_RSA_AES256_SHA256(t *testing.T) {
	params := generateRsaCert()

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "AES256-SHA256", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_RSA_AES256_SHA(t *testing.T) {
	params := generateRsaCert()

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "AES256-SHA", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_RSA_AES128_SHA256(t *testing.T) {
	params := generateRsaCert()

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "AES128-SHA256", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_RSA_AES128_SHA(t *testing.T) {
	params := generateRsaCert()

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "AES128-SHA", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}
