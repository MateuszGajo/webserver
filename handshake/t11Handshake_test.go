package handshake

import "testing"

func TestHandshakeOpenT11_ADH_DES_CBC3_SHA(t *testing.T) {
	server := startServer(nil, TLS11Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "ADH-DES-CBC3-SHA", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_ADH_DES_CBC_SHA(t *testing.T) {
	server := startServer(nil, TLS11Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "ADH-DES-CBC-SHA", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_ADH_RC4_MD5(t *testing.T) {
	server := startServer(nil, TLS11Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "ADH-RC4-MD5", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_EXP_ADH_RC4_MD5(t *testing.T) {
	server := startServer(nil, TLS11Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-ADH-RC4-MD5", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_DES_CBC3_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS11Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DES-CBC3-SHA", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS11Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DES-CBC-SHA", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_EDH_RSA_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS11Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-RSA-DES-CBC-SHA", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_EXP_EDH_RSA_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS11Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-EDH-RSA-DES-CBC-SHA", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_EXP_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(true)

	server := startServer(params, TLS11Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-DES-CBC-SHA", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_EXP_ADH_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS11Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-ADH-DES-CBC-SHA", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_RC4_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS11Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "RC4-SHA", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_EXP_RC4_MD5(t *testing.T) {
	params := generateRsaCert(true)

	server := startServer(params, TLS11Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-RC4-MD5", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_EXP_RC2_CBC_MD5(t *testing.T) {
	params := generateRsaCert(true)

	server := startServer(params, TLS11Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-RC2-CBC-MD5", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_EDH_RSA_DES_CBC3_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS11Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-RSA-DES-CBC3-SHA", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_EDH_DSS_DES_CBC3_SHA(t *testing.T) {
	params := generateDSsCert()

	server := startServer(params, TLS11Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-DSS-DES-CBC3-SHA", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_EDH_DSS_DES_CBC_SHA(t *testing.T) {
	params := generateDSsCert()

	server := startServer(params, TLS11Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-DSS-DES-CBC-SHA", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT11_EXP_EDH_DSS_DES_CBC_SHA(t *testing.T) {
	params := generateDSsCert()

	server := startServer(params, TLS11Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-EDH-DSS-DES-CBC-SHA", "-tls1_1", "-reconnect"}); err != nil {
		t.Error(err)
	}
}
