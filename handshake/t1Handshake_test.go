package handshake

import "testing"

func TestHandshakeOpenT1_ADH_DES_CBC3_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS10Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "ADH-DES-CBC3-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_ADH_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS10Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "ADH-DES-CBC-SHA", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT1_ADH_RC4_MD5(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS10Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "ADH-RC4-MD5", "-tls1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}
