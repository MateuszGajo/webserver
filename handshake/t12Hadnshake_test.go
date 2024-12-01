package handshake

import "testing"

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
	params := generateRsaCert(false)

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DES-CBC3-SHA", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenT12_RC4_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, TLS12Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "RC4-SHA", "-tls1_2", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

// func TestHandshakeOpenT12_EDH_RSA_DES_CBC3_SHA(t *testing.T) {
// 	params := generateRsaCert(false)

// 	server := startServer(params, TLS12Version)
// 	defer StopServer(*server)

// 	if err := runOpensslCommand([]string{"-cipher", "EDH-RSA-DES-CBC3-SHA", "-tls1_2", "-reconnect"}); err != nil {
// 		t.Error(err)
// 	}
// }

// func TestHandshakeOpenT12_EDH_DSS_DES_CBC3_SHA(t *testing.T) {
// 	params := generateDSsCert()

// 	server := startServer(params, TLS12Version)
// 	defer StopServer(*server)

// 	if err := runOpensslCommand([]string{"-cipher", "EDH-DSS-DES-CBC3-SHA", "-tls1_2", "-reconnect"}); err != nil {
// 		t.Error(err)
// 	}
// }
