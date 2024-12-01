package handshake

import (
	"fmt"
	"testing"
)

func TestHandshakeOpenT1_ADH_DES_CBC3_SHA(t *testing.T) {
	server := startServer(nil, TLS10Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "ADH-DES-CBC3-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_ADH_DES_CBC_SHA(t *testing.T) {
	server := startServer(nil, TLS10Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "ADH-DES-CBC-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_ADH_RC4_MD5(t *testing.T) {
	server := startServer(nil, TLS10Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "ADH-RC4-MD5", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_EXP_ADH_RC4_MD5(t *testing.T) {
	server := startServer(nil, TLS10Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-ADH-RC4-MD5", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_DES_CBC3_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS10Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DES-CBC3-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS10Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DES-CBC-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_EDH_RSA_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS10Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-RSA-DES-CBC-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_EXP_EDH_RSA_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS10Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-EDH-RSA-DES-CBC-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_EXP_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(true)

	server := startServer(params, TLS10Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-DES-CBC-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_EXP_ADH_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS10Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-ADH-DES-CBC-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_RC4_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS10Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "RC4-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_EXP_RC4_MD5(t *testing.T) {
	params := generateRsaCert(true)

	server := startServer(params, TLS10Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-RC4-MD5", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_EXP_RC2_CBC_MD5(t *testing.T) {
	params := generateRsaCert(true)

	server := startServer(params, TLS10Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-RC2-CBC-MD5", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_EDH_RSA_DES_CBC3_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS10Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-RSA-DES-CBC3-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_EDH_DSS_DES_CBC3_SHA(t *testing.T) {
	params := generateDSsCert()

	server := startServer(params, TLS10Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-DSS-DES-CBC3-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_EDH_DSS_DES_CBC_SHA(t *testing.T) {
	params := generateDSsCert()

	server := startServer(params, TLS10Version)
	fmt.Println("hello??")
	fmt.Println(OpenSSLVersion)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-DSS-DES-CBC-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_EXP_EDH_DSS_DES_CBC_SHA(t *testing.T) {
	params := generateDSsCert()

	server := startServer(params, TLS10Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-EDH-DSS-DES-CBC-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}
