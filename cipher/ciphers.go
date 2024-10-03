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
	var preMasterSecret []byte
	switch cipherDef.Spec.KeyExchange {
	case KeyExchangeMethodDH:
		clientPublicKeyLength := binary.BigEndian.Uint16(data[:2])
		clientPublicKey := data[2 : 2+clientPublicKeyLength]
		clinetPublicKeyInt := new(big.Int).SetBytes(clientPublicKey)
		cipherDef.DhParams.ClientPublic = clinetPublicKeyInt
		preMasterSecret = cipherDef.DhParams.ComputePreMasterSecret().Bytes()
	case KeyExchangeMethodRSA:
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, &cipherDef.Rsa.PrivateKey, data)
		if err != nil {
			fmt.Printf("couldnt decrypt rsa, err: %v", err)
			os.Exit(1)
		}
		preMasterSecret = decrypted
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

func (cipherDef *CipherDef) GenerateServerKeyExchange() []byte {

	var resp []byte

	switch cipherDef.Spec.KeyExchange {
	case KeyExchangeMethodDH:
		resp = cipherDef.DhParams.GenerateDhParams()
	case KeyExchangeMethodRSA:
		return []byte{}
	default:
		fmt.Printf("Key exchange parameters not implemented for: %v", cipherDef.Spec.KeyExchange)
		os.Exit(1)
	}

	return resp
}

func (cipherDef *CipherDef) SignData(hash []byte) ([]byte, error) {
	switch cipherDef.Spec.SignatureAlgorithm {
	case SignatureAlgorithmAnonymous:
		return []byte{}, nil
	case SignatureAlgorithmRSA:
		signature, err := rsa.SignPKCS1v15(rand.Reader, &cipherDef.Rsa.PrivateKey, crypto.Hash(0), hash)

		if err != nil {
			return nil, fmt.Errorf("\n problem ecnrypting data, err: %v", err)
		}

		return signature, nil

	case SignatureAlgorithmDSA:
		r, s, err := dsa.Sign(rand.Reader, &cipherDef.Dsa.PrivateKey, hash)
		if err != nil {
			return nil, fmt.Errorf("\n error while singing, err: %v", err)
		}
		signature, err := asn1.Marshal(DSA_SIG{R: r, S: s})
		if err != nil {
			return nil, fmt.Errorf("\n error occured while marshal r,s to anc1 structure, err:%v", err)
		}
		return signature, nil

	default:
		fmt.Printf("Unsupported Algorithm: %v", cipherDef.Spec.SignatureAlgorithm)
		os.Exit(1)
	}
	return []byte{}, nil

}

func (cipherDef *CipherDef) VerifySignedData(hash, signature []byte) error {
	var err error
	switch cipherDef.Spec.SignatureAlgorithm {
	case SignatureAlgorithmAnonymous:
	case SignatureAlgorithmRSA:
		err = rsa.VerifyPKCS1v15(&cipherDef.Rsa.PublicKey, crypto.Hash(0), hash, signature)

	case SignatureAlgorithmDSA:
		var params DSA_SIG

		_, err := asn1.Unmarshal(signature, &params)
		if err != nil {
			fmt.Printf("\n error unmarshaling, err: %v", err)
		}

		ok := dsa.Verify(&cipherDef.Dsa.PublicKey, hash, params.R, params.S)
		if !ok {
			return fmt.Errorf("cant verify dsa signature")
		}

	default:
		fmt.Printf("Unsupported Algorithm: %v", cipherDef.Spec.SignatureAlgorithm)
		os.Exit(1)
	}

	return err
}

// List was made based on hunch, please follow official rfc documentation when choosing cipher
// All of them are considered insecure in today's world, tbh you don't want to choose any of them

// DES - des is considered vunlerable to brute-force attacks due to several factors: relatively short key length + advancements in computional power
// DES uses 56 bit key length which means there are 2^56 combinations = 72,057,594,037,926,936, in 1998 it was broken in 22 hours
// Lets consider a distrubuted computing project harnessing power of 1 milion computers, each capable of testing 1 biliong key per second 1,000,000 x 1,000,000,000 = 10^ 15, 2^56/10^15 = about 20 hours (worst case scenario, lets say avg is 10 hours).
// https://eitca.org/cybersecurity/eitc-is-ccf-classical-cryptography-fundamentals/conclusions-for-private-key-cryptography/multiple-encryption-and-brute-force-attacks/examination-review-multiple-encryption-and-brute-force-attacks/why-is-the-data-encryption-standard-des-considered-vulnerable-to-brute-force-attacks-and-how-does-modern-computational-power-affect-its-security/
// Its seems 1 milion computers is a lot, but in today's world with IOT where everything has its own processor, can be used to such things. So 1 milion its not really a lot, moreover its was broken in 1998 when computation power was relativly low.

// 3DES -big brother of des, uses stronger key which is 168 bites. A bit of math (approx calculation) 2^168=3.69x10^50 -> (3.69*10^50)/10^15 = 3.69*x10^35  seconds -> 1.025*10^32 hours.... 1.14x^10^28 years. So its much harder to brutce force unless we increase computer power.
// https://www.baeldung.com/cs/des-vs-3des-vs-blowfish-vs-aes according to this source it can broken in 800 days.
// Rember if you used same keys for few session, all msgs can be decrypted,

// First drawback is execution time, let's see results on  P-4 2.4 GHz machine
// Input 	Size (bytes) 	DES 	    3DES 		AES 	BF(blow fish)
// 20,527 					2 			7 		 	4 		2
// 36,002 					4 			13 			6 		3
// 45,911 					5 			17 			8		4
// 59,852 					7 			23 			11 		6
// 69,545 					9 			26 			13 		7
// 137,325 					17 			51 			26 		14
// 158,959 					20 			60 			30 		16
// 166,364 					21 			62 			31 		17
// 191,383 					24 			72 			36 		19
// 232,398 					30 			87 			44 		24
// Average Time 			14 			42 			21 		11
// Bytes/sec 				7,988 		2,663 		5,320 	10,167
// source: https://www.cse.wustl.edu/~jain/cse567-06/ftp/encryption_perf/
// TODO: maybe let's do own comparision??

// Sweet32 attacks on cipher block 64 bytes (des, 3des, blow fish)
// The DES ciphers (and triple-DES) only have a 64-bit block size. ciphers are mostly vulnerable to birthday attacks when the message is 2n/2 block of messages. This enables an attacker to run JavaScript in a browser and send large amounts of traffic during the same TLS connection, creating a collision. With this collision, the attacker is able to retrieve information from a session cookie.
// Due to a flaw in the algorithm, there will be a situation where two block has the same key. An attacker can access the information by using XOR operation on the blocks to reveal the plain text.
// This vulnerability could be used by a man-in-the-middle attacker to recover some plaintext data. The attacker is able to intercept vast volumes of encrypted traffic between the client and the TLS/SSL server.
// Sweet32 can break 3des in matter of minutes or even seconds

// blow fish - faster than 3des, but still vulnerable to sweet32, probably that's why was never used in ssl/tls. Moreover short afrer bf release AES was published

// AES - is consider secure, tls 1.3 can be confirmation of it as it is still using it as recommended cipher.
// https://www.baeldung.com/cs/des-vs-3des-vs-blowfish-vs-aes according to this source where 3des was broken in 800, for aes we need >13 bilion years.

var serverCipherPreferences = []TLSCipherSuite{
	TLS_CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA,
	TLS_CIPHER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_RSA_WITH_RC4_128_MD5,
	TLS_CIPHER_SUITE_SSL_RSA_WITH_RC4_128_SHA,
	TLS_CIPHER_SUITE_SSL_RSA_WITH_DES_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DHE_DSS_WITH_DES_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_DES_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DH_DSS_WITH_DES_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DH_RSA_WITH_DES_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_RSA_EXPORT_WITH_RC4_40_MD5,
	TLS_CIPHER_SUITE_SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	TLS_CIPHER_SUITE_SSL_RSA_WITH_IDEA_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DH_anon_WITH_RC4_128_MD5,
	TLS_CIPHER_SUITE_SSL_DH_anon_WITH_DES_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_DH_anon_EXPORT_WITH_RC4_40_MD5,
	TLS_CIPHER_SUITE_SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
	TLS_CIPHER_SUITE_SSL_RSA_WITH_NULL_SHA,
	TLS_CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_NULL_SHA,
	TLS_CIPHER_SUITE_SSL_RSA_WITH_NULL_MD5,
}

func (cipherDef *CipherDef) SelectCipherSuite(cipherSuites []byte) error {

	cipherList := []uint16{}

	for i := 0; i < len(cipherSuites); i += 2 {
		cipher := binary.BigEndian.Uint16(cipherSuites[i : i+2])
		cipherList = append(cipherList, cipher)
	}

	// TODO: low prio, lets try avoid double looping if possible
	if cipherDef.PreferServerCipher {
		for _, serverCipher := range serverCipherPreferences {
			for _, clientCipher := range cipherList {
				if serverCipher == TLSCipherSuite(clientCipher) {
					cipherDef.CipherSuite = clientCipher
					return nil
				}
			}
		}
	} else {
		for _, clientCipher := range cipherList {
			for _, serverCipher := range serverCipherPreferences {
				if clientCipher == uint16(serverCipher) {
					cipherDef.CipherSuite = clientCipher
					return nil
				}
			}
		}
	}

	return fmt.Errorf("server doesnt have any of provided suites :%v", cipherSuites)

}

var serverCompressionMethods = []CompressionMethod{
	CompressionAlgorithmNull,
	CompressionAlgorithmDeflate,
}

func (cipherDef *CipherDef) SelectCompressionMethod(compressionMethods []byte) error {

	for _, clientMethod := range compressionMethods {
		for _, serverMethod := range serverCompressionMethods {
			if clientMethod == byte(serverMethod) {
				cipherDef.Spec.CompressionMethod = serverMethod
				return nil
			}
		}
	}

	return fmt.Errorf("server doesn't have any provided compression method: %v", compressionMethods)

}

func (cipherDef *CipherDef) GetCipherSpecInfo() {
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
		cipherDef.Spec.KeyExchangeRotation = true
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
		cipherDef.Spec.KeyExchangeRotation = true
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
