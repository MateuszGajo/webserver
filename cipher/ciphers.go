package cipher

import (
	"crypto"
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
	"os"
)

func (cipherDef *CipherDef) DecryptMessage(encryptedData []byte, writeKey, iv []byte) []byte {
	cipherDef.Keys.IVClient = encryptedData[len(encryptedData)-8:]

	switch TLSCipherSuite(cipherDef.CipherSuite) {
	case TLS_CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
		return DecryptDesMessage(encryptedData, writeKey, iv)
	case TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
		return DecryptDesMessage(encryptedData, writeKey, iv)
	case TLS_CIPHER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA:
		return DecryptDesMessage(encryptedData, writeKey, iv)
	case TLS_CIPHER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
		return DecryptDesMessage(encryptedData, writeKey, iv)
	default:
		fmt.Printf("unkonw cipher suite: %v", cipherDef.CipherSuite)
		os.Exit(1)

	}

	return []byte{}
}

func (cipherDef *CipherDef) EncryptMessage(data []byte, writeKey, iv []byte) []byte {
	var encryptedMsg []byte
	switch TLSCipherSuite(cipherDef.CipherSuite) {
	case TLS_CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:
		encryptedMsg = EncryptDesMessage(data, writeKey, iv)
	case TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA:
		encryptedMsg = EncryptDesMessage(data, writeKey, iv)
	case TLS_CIPHER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA:
		encryptedMsg = EncryptDesMessage(data, writeKey, iv)
	case TLS_CIPHER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA:
		encryptedMsg = EncryptDesMessage(data, writeKey, iv)
	default:
		fmt.Printf("unkonw cipher suite: %v", cipherDef.CipherSuite)
		os.Exit(1)

	}

	cipherDef.Keys.IVServer = encryptedMsg[len(encryptedMsg)-8:]

	return encryptedMsg
}

func (cipherDef *CipherDef) ComputerMasterSecret(data []byte) []byte {
	fmt.Println("enter??? ")
	fmt.Println("enter??? ")
	fmt.Println("enter??? ")
	var preMasterSecret []byte
	switch cipherDef.Spec.KeyExchange {
	case KeyExchangeMethodDH:

		fmt.Println("compute master secret dat")
		fmt.Println("compute master secret dat")
		fmt.Println("compute master secret dat")
		fmt.Println(data)

		clientPublicKeyLength := binary.BigEndian.Uint16(data[:2])
		// TODO: fix this, we coudl passed data[:6+clientPublicKeyLength] and somehow worked
		clientPublicKey := data[2 : 2+clientPublicKeyLength]
		fmt.Println("compute master secret dat")
		fmt.Println("compute master secret dat")
		fmt.Println(data)
		fmt.Println("pub key")
		fmt.Println(clientPublicKey)

		clinetPublicKeyInt := new(big.Int).SetBytes(clientPublicKey)
		cipherDef.DhParams.ClientPublic = clinetPublicKeyInt
		preMasterSecret = cipherDef.DhParams.ComputePreMasterSecret().Bytes()
	case KeyExchangeMethodRSA:
		fmt.Println("data enters")
		fmt.Println("data enters")
		fmt.Println(cipherDef.Rsa.PrivateKey)
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, &cipherDef.Rsa.PrivateKey, data)

		fmt.Println("decrypted rsa!!")
		fmt.Println("decrypted rsa!!")
		fmt.Println("decrypted rsa!!")
		fmt.Println(len(decrypted))
		fmt.Println(decrypted)
		if err != nil {
			fmt.Printf("couldnt decrypt rsa, err: %v", err)
			os.Exit(1)
		}
		preMasterSecret = decrypted
	case KeyExchangeMethodDHE:
		fmt.Print("Key exchang dhe not implemented")
		os.Exit(1)
	default:
		fmt.Print("Key exchang method not implmeneted yet")
		os.Exit(1)
	}

	fmt.Println("skip all??")

	return preMasterSecret

}

func signKeyParams(algorithm hash.Hash, clientRandom, serverRandom, serverParams []byte) []byte {
	algorithm.Reset()
	algorithm.Write(clientRandom)
	algorithm.Write(serverRandom)
	algorithm.Write(serverParams)

	return algorithm.Sum(nil)

}

type DSA_SIG struct {
	R *big.Int
	S *big.Int
}

func DSAtoASN1(sig *DSA_SIG) ([]byte, error) {
	// The DSA signature (r, s) will be encoded as an ASN.1 sequence
	return asn1.Marshal(*sig)
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

func (cipherDef *CipherDef) SignParams(hash []byte) []byte {
	resp := []byte{}
	switch cipherDef.Spec.SignatureAlgorithm {
	case SignatureAlgorithmAnonymous:
	case SignatureAlgorithmRSA:

		fmt.Println("key data exchange")
		resp = append(resp, []byte{1, 0}...)

		signature, err := rsa.SignPKCS1v15(rand.Reader, &cipherDef.Rsa.PrivateKey, crypto.Hash(0), hash)
		resp = append(resp, signature...)

		if err != nil {
			fmt.Println("problem ecnrypting data")
			fmt.Println(err)
		}

	case SignatureAlgorithmDSA:

		r, s, err := dsa.Sign(rand.Reader, &cipherDef.Dsa.PrivateKey, hash)
		if err != nil {
			fmt.Printf("\n error while singing, err: %v", err)
		}
		signnn, err := DSAtoASN1(&DSA_SIG{R: r, S: s})
		if err != nil {
			fmt.Printf("\n error occured while doing some anc1, err:%v", err)
		}

		if err != nil {
			fmt.Println("cant sign dsa")
			fmt.Println(err)
			os.Exit(1)
		}
		lengthhh := len(signnn)
		resp = append(resp, []byte{0, byte(lengthhh)}...)
		resp = append(resp, signnn...)

	default:
		fmt.Printf("Unsupported Algorithm: %v", cipherDef.Spec.SignatureAlgorithm)
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

	// TODO and make this better
	cipherDef.GetCipherSpecInfo()

	return []byte{0, 27}

}

func (cipherDef *CipherDef) SelectCompressionMethod() []byte {

	// TODO implement this
	// cipherDef.CipherSuite = 0x001B

	return []byte{0}

}

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
		// TODO roate keys when using DHE
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
		// TODO roate keys when using DHE
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
