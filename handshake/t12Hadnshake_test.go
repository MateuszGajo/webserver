package handshake

import (
	"fmt"
	"testing"
)

func TestHandshakeOpenT12_ADH_DES_CBC3_SHA(t *testing.T) {
	server := startServer(nil, TLS12Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "ADH-DES-CBC3-SHA", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_ADH_RC4_MD5(t *testing.T) {
	server := startServer(nil, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "ADH-RC4-MD5", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_DES_CBC3_SHA(t *testing.T) {
	params := generateRsaCert()

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DES-CBC3-SHA", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_RC4_SHA(t *testing.T) {
	params := generateRsaCert()

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "RC4-SHA", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

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

func TestHandshakeOpenT12_DH_RSA_AES128_SHA256(t *testing.T) {
	params := generateRsaDHCert()

	fmt.Println(params)

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DH-RSA-AES128-SHA256", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_DH_RSA_AES256_SHA256(t *testing.T) {
	params := generateRsaDHCert()

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DH-RSA-AES256-SHA256", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_DHE_DSS_AES256_SHA256(t *testing.T) {
	params := generateDSsCert()

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DHE-DSS-AES256-SHA256", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_DHE_DSS_AES256_SHA(t *testing.T) {
	params := generateDSsCert()

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DHE-DSS-AES256-SHA", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_DH_DSS_AES256_SHA256(t *testing.T) {
	params := generateDssDHCert()

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DH-DSS-AES256-SHA256", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}
