package cipher

import (
	"crypto"
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"os"
)

func (cipherDef *CipherDef) DecryptMessage(encryptedData []byte, cipherSuite uint16, writeKey, iv []byte) []byte {
	cipherDef.Keys.IVClient = encryptedData[len(encryptedData)-8:]

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

func (cipherDef *CipherDef) ComputerMasterSecret(data []byte) []byte {
	var preMasterSecret []byte
	switch cipherDef.Spec.KeyExchange {
	case KeyExchangeMethodDH:

		clientPublicKeyLength := binary.BigEndian.Uint16(data[:2])
		clientPublicKey := data[:6+clientPublicKeyLength]

		clinetPublicKeyInt := new(big.Int).SetBytes(clientPublicKey)
		cipherDef.DhParams.ClientPublic = clinetPublicKeyInt
		preMasterSecret = cipherDef.DhParams.ComputePreMasterSecret().Bytes()
	case KeyExchangeMethodRSA:
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, &cipherDef.rsa.privateKey, data)
		if err != nil {
			fmt.Println("couldnt decrypt rsa")
			os.Exit(1)
		}
		preMasterSecret = decrypted
	case KeyExchangeMethodDHE:
	default:
		fmt.Print("Key exchang method not implmeneted yet")
		os.Exit(1)
	}

	return preMasterSecret

}

func ParseDSAPrivateKey(der []byte) (*dsa.PrivateKey, error) {
	var k struct {
		Version int
		P       *big.Int
		Q       *big.Int
		G       *big.Int
		Pub     *big.Int
		Priv    *big.Int
	}
	rest, err := asn1.Unmarshal(der, &k)
	fmt.Println("lets display k")
	fmt.Printf("/n %+v", k)
	fmt.Println("bytes")
	fmt.Println(k.Priv.Bytes())
	if err != nil {
		return nil, errors.New("ssh: failed to parse DSA key: " + err.Error())
	}
	if len(rest) > 0 {
		return nil, errors.New("ssh: garbage after DSA key")
	}

	return &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: k.P,
				Q: k.Q,
				G: k.G,
			},
			Y: k.Pub,
		},
		X: k.Priv,
	}, nil
}

func (cipherDef *CipherDef) ParseCertificate(certFile, keyFile string) ([]byte, error) {
	// Read the certificate file
	fmt.Println("hello enter??")
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	// Read the private key file
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}
	// Decode the private key PEM block
	// keyBlockBytes := keyPEM
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}
	keyBlockBytes := keyBlock.Bytes

	if cipherDef.Spec.SignatureAlgorithm == SignatureAlgorithmDSA {
		fmt.Println("dsa key")
		dsaPrivate, err := ParseDSAPrivateKey(keyBlockBytes)

		if err != nil {
		} else {
			cipherDef.dsa.privateKey = *dsaPrivate
		}
	} else if cipherDef.Spec.SignatureAlgorithm == SignatureAlgorithmRSA {

		// TODO do better parsing
		privateKey, err := x509.ParsePKCS8PrivateKey(keyBlockBytes)
		if err != nil {
			fmt.Println("helo1")
			fmt.Println(err)
			privateKey, err = x509.ParsePKCS1PrivateKey(keyBlockBytes)
			if err != nil {
				fmt.Println("helo2")
				fmt.Println(err)
				privateKey, err = x509.ParseECPrivateKey(keyBlockBytes)
				if err != nil {
					return nil, fmt.Errorf("failed to parse private key: %v", err)
				}
			}
		}

		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if ok {
			cipherDef.rsa.privateKey = *rsaKey
		}
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	rawBytes := cert.Raw
	return rawBytes, nil
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

func i2d_DSA_SIG(sig *DSA_SIG) ([]byte, error) {
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

		signature, err := rsa.SignPKCS1v15(rand.Reader, &cipherDef.rsa.privateKey, crypto.Hash(0), hash)
		resp = append(resp, signature...)

		if err != nil {
			fmt.Println("problem ecnrypting data")
			fmt.Println(err)
		}

	case SignatureAlgorithmDSA:

		r, s, err := dsa.Sign(rand.Reader, &cipherDef.dsa.privateKey, hash)
		// TODO check if rsa signin is actualy saving it in asn format
		signnn, err := i2d_DSA_SIG(&DSA_SIG{R: r, S: s})
		if err != nil {
			fmt.Println("error occured while doing some anc1")
		}

		if err != nil {
			fmt.Println("cant sign dsa")
			fmt.Println(err)
			os.Exit(1)
		}
		lengthhh := len(signnn)
		resp = append(resp, []byte{0, byte(lengthhh)}...)
		resp = append(resp, signnn...)

		fmt.Printf("Algorithm: %v not implemented yet", cipherDef.Spec.SignatureAlgorithm)
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
