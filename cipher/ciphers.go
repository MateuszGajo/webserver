package cipher

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
)

func DecryptMessage(encryptedData []byte, cipherSuite uint16, writeKey, iv []byte) []byte {

	switch TLSCipherSuite(cipherSuite) {
	case TLS_CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
		return DecryptDesMessage(encryptedData, writeKey, iv)
	case TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return DecryptDesMessage(encryptedData, writeKey, iv)
	case TLS_CIPHER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA:
		return DecryptDesMessage(encryptedData, writeKey, iv)
	case TLS_CIPHER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
		return DecryptDesMessage(encryptedData, writeKey, iv)
	default:
		fmt.Printf("unkonw cipher suite: %v", cipherSuite)
		os.Exit(1)

	}

	return []byte{}
}

func (cipherDef *CipherDef) EncryptMessage(data []byte) []byte {

	switch TLSCipherSuite(cipherDef.CipherSuite) {
	case TLS_CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
		return EncryptDesMessage(data, cipherDef.Keys.WriteKeyServer, cipherDef.Keys.IVServer)
	case TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return EncryptDesMessage(data, cipherDef.Keys.WriteKeyServer, cipherDef.Keys.IVServer)
	case TLS_CIPHER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA:
		return EncryptDesMessage(data, cipherDef.Keys.WriteKeyServer, cipherDef.Keys.IVServer)
	case TLS_CIPHER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
		return EncryptDesMessage(data, cipherDef.Keys.WriteKeyServer, cipherDef.Keys.IVServer)
	default:
		fmt.Printf("unkonw cipher suite: %v", cipherDef.CipherSuite)
		os.Exit(1)

	}

	return []byte{}
}

func (cipherDef *CipherDef) ComputerMasterSecret() *big.Int {
	var preMasterSecret *big.Int
	switch cipherDef.Spec.KeyExchange {
	case KeyExchangeMethodDH:
		preMasterSecret = cipherDef.DhParams.ComputePreMasterSecret()
	case KeyExchangeMethodRSA:
	case KeyExchangeMethodDHE:
	default:
		fmt.Print("Key exchang method not implmeneted yet")
		os.Exit(1)
	}

	return preMasterSecret
}

func (cipherDef *CipherDef) GenerateServerKeyExchange() []byte {

	var resp []byte

	switch cipherDef.Spec.KeyExchange {
	case KeyExchangeMethodDH:
		resp = cipherDef.DhParams.GenerateDhParams()
	case KeyExchangeMethodRSA:
		return []byte{}
	case KeyExchangeMethodDHE:
		return []byte{}
	default:
		fmt.Printf("Key exchange parameters not implemented for: %v", cipherDef.Spec.KeyExchange)
		os.Exit(1)
	}

	return resp
}

func (cipherDef *CipherDef) SelectCipherSuite(cipherSuites []byte) []byte {

	cipherList := []uint16{}

	for i := 0; i < len(cipherSuites); i += 2 {
		cipher := binary.BigEndian.Uint16(cipherSuites[i : i+2])
		cipherList = append(cipherList, cipher)
	}

	// TODO implement this
	cipherDef.CipherSuite = cipherList[0]

	// TODO should also setup this
	cipherDef.GetCipherSpecInfo()

	return []byte{0, 27}

}

func (cipherDef *CipherDef) SelectCompressionMethod() []byte {

	// TODO implement this
	// cipherDef.CipherSuite = 0x001B

	return []byte{0}

}

// TODO implement RSA, DHE, move to ciphers?

func (cipherDef *CipherDef) GetCipherSpecInfo() {
	//TODO  fill all data
	switch TLSCipherSuite(cipherDef.CipherSuite) {
	case TLS_CIPHER_SUITE_SSL_NULL_WITH_NULL_NULL:
	case TLS_CIPHER_SUITE_SSL_RSA_WITH_NULL_MD5:
	case TLS_CIPHER_SUITE_SSL_RSA_WITH_NULL_SHA:
	case TLS_CIPHER_SUITE_SSL_RSA_EXPORT_WITH_RC4_40_MD5:
	case TLS_CIPHER_SUITE_SSL_RSA_WITH_RC4_128_MD5:
	case TLS_CIPHER_SUITE_SSL_RSA_WITH_RC4_128_SHA:
	case TLS_CIPHER_SUITE_SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5:
	case TLS_CIPHER_SUITE_SSL_RSA_WITH_IDEA_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_RSA_EXPORT_WITH_DES40_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_RSA_WITH_DES_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA:
		cipherDef.Spec.HashSize = 20
		cipherDef.Spec.KeyMaterial = 24
		cipherDef.Spec.IvSize = 8
		cipherDef.Spec.HashAlgorithm = HashAlgorithmSHA
		// TODO change this to DHE
		// TODO roate his when using DHE
		cipherDef.Spec.KeyExchange = KeyExchangeMethodRSA
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithm3DES
		cipherDef.Spec.SignatureAlgorithm = SignatureAlgorithmRSA
	case TLS_CIPHER_SUITE_SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_DH_DSS_WITH_DES_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_DH_RSA_WITH_DES_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_DHE_DSS_WITH_DES_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
		cipherDef.Spec.HashSize = 20
		cipherDef.Spec.KeyMaterial = 24
		cipherDef.Spec.IvSize = 8
		cipherDef.Spec.HashAlgorithm = HashAlgorithmSHA
		// TODO change this to DHE
		// TODO roate his when using DHE
		cipherDef.Spec.KeyExchange = KeyExchangeMethodDH
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithm3DES
		cipherDef.Spec.SignatureAlgorithm = SignatureAlgorithmDSA
	case TLS_CIPHER_SUITE_SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_DES_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
		cipherDef.Spec.HashSize = 20
		cipherDef.Spec.KeyMaterial = 24
		cipherDef.Spec.IvSize = 8
		cipherDef.Spec.HashAlgorithm = HashAlgorithmSHA
		// TODO change this to DHE
		// TODO roate his when using DHE
		cipherDef.Spec.KeyExchange = KeyExchangeMethodDH
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithm3DES
		cipherDef.Spec.SignatureAlgorithm = SignatureAlgorithmRSA
	case TLS_CIPHER_SUITE_SSL_DH_anon_EXPORT_WITH_RC4_40_MD5:
	case TLS_CIPHER_SUITE_SSL_DH_anon_WITH_RC4_128_MD5:
	case TLS_CIPHER_SUITE_SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_DH_anon_WITH_DES_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
		cipherDef.Spec.HashSize = 20
		cipherDef.Spec.KeyMaterial = 24
		cipherDef.Spec.IvSize = 8
		cipherDef.Spec.HashAlgorithm = HashAlgorithmSHA
		cipherDef.Spec.KeyExchange = KeyExchangeMethodDH
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithm3DES
		cipherDef.Spec.SignatureAlgorithm = SignatureAlgorithmAnonymous
	case TLS_CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_NULL_SHA:
	case TLS_CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA:
	case TLS_CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA:
	default:
		cipherDef.Spec.HashSize = 0
		cipherDef.Spec.HashSize = 0
		cipherDef.Spec.KeyMaterial = 0
	}
}
