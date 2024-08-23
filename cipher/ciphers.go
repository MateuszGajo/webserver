package cipher

import (
	"fmt"
	"os"
)

func DecryptMessage(recordLayerData []byte, encryptedData []byte, cipherSuite uint16, writeKey, iv []byte) []byte {

	switch TLSCipherSuite(cipherSuite) {
	case TLS_CIPER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
		return DecryptDesMessage(recordLayerData, encryptedData, writeKey, iv)
	default:
		fmt.Printf("unkonw cipher suite: %v", cipherSuite)
		os.Exit(1)

	}

	return []byte{}
}
