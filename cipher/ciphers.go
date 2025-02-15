package cipher

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
	"os"
	"strings"
)

type TLSCipherSuite uint16

type CipherKeys struct {
	MacClient      []byte
	MacServer      []byte
	WriteKeyClient []byte
	WriteKeyServer []byte
	IVClient       []byte
	IVServer       []byte
	CipherSuite    uint16
}

type HashAlgorithm string

const (
	HashAlgorithmSHA    HashAlgorithm = "SHA"
	HashAlgorithmSHA256 HashAlgorithm = "SHA256"
	HashAlgorithmSHA384 HashAlgorithm = "SHA384"
	HashAlgorithmMD5    HashAlgorithm = "MD5"
)

type KeyExchangeMethod string

const (
	KeyExchangeMethodDH  KeyExchangeMethod = "dh"
	KeyExchangeMethodRSA KeyExchangeMethod = "rsa"
)

type EncryptionAlgorithm string

const (
	EncryptionAlgorithm3DES     EncryptionAlgorithm = "3des"
	EncryptionAlgorithmDES      EncryptionAlgorithm = "des"
	EncryptionAlgorithmDES40    EncryptionAlgorithm = "des40"
	EncryptionAlgorithmRC4      EncryptionAlgorithm = "RC4"
	EncryptionAlgorithmRC2      EncryptionAlgorithm = "RC2"
	EncryptionAlgorithmAES      EncryptionAlgorithm = "AES"
	EncryptionAlgorithmCHACHA20 EncryptionAlgorithm = "CHACHA20"
	EncryptionAlgorithmFortezza EncryptionAlgorithm = "FORTEZZA"
)

type EncryptionAlgorithmBlockMode string

const (
	EncryptionAlgorithmBlockModeGCM EncryptionAlgorithmBlockMode = "GCM"
)

type SignatureAlgorithm string

const (
	SignatureAlgorithmRSA       SignatureAlgorithm = "signatureRSA"
	SignatureAlgorithmDSA       SignatureAlgorithm = "signatureDSA" // DSS is standard developved by nist, DSA is algorithm defines within for creating and veryfin digital signatures
	SignatureAlgorithmAnonymous SignatureAlgorithm = "signatureAnonymous"
)

type HashAlgorithmIdentifier byte

const (
	HashAlgorithmNumberNone   HashAlgorithmIdentifier = 0
	HashAlgorithmNumberMd5    HashAlgorithmIdentifier = 1
	HashAlgorithmNumberSha1   HashAlgorithmIdentifier = 2
	HashAlgorithmNumberSha224 HashAlgorithmIdentifier = 3
	HashAlgorithmNumberSha256 HashAlgorithmIdentifier = 4
	HashAlgorithmNumberSha384 HashAlgorithmIdentifier = 5
	HashAlgorithmNumberSha512 HashAlgorithmIdentifier = 6
)

type SignatureAlgorithmIdentifier byte

const (
	SignatureAlgorithmNumberAnonymous SignatureAlgorithmIdentifier = 0
	SignatureAlgorithmNumberRsa       SignatureAlgorithmIdentifier = 1
	SignatureAlgorithmNumberDsa       SignatureAlgorithmIdentifier = 2
	SignatureAlgorithmNumberECDSA     SignatureAlgorithmIdentifier = 3
)

type CipherSpec struct {
	HashSize                   int
	KeyMaterial                int
	ExportKeyMaterial          int
	IvSize                     int
	IvAsPayload                bool
	HashBasedSigning           bool
	HashAlgorithm              func() hash.Hash
	ExtHashAlgorithmIdentifier HashAlgorithmIdentifier
	KeyExchange                KeyExchangeMethod
	// Use this paramter when using DHE key exchange, as dh has almost the same implementation to dhe
	KeyExchangeRotation             bool
	EncryptionAlgorithm             EncryptionAlgorithm
	EncryptionAlgorithmBlockMode    EncryptionAlgorithmBlockMode
	SignatureAlgorithm              SignatureAlgorithm
	ExtSignatureAlgorithmIdentifier SignatureAlgorithmIdentifier
	CompressionMethod               CompressionMethod
	IsExportable                    bool
}

type CipherDef struct {
	Keys               CipherKeys
	Spec               CipherSpec
	CipherSuite        uint16
	DhParams           DhParams
	ECDH               ECDHData
	Rsa                RsaCipher
	Dsa                DsaCipher
	PreferServerCipher bool
}

type ECDHData struct {
	// The ECDH shared secret is the result of applying the ECDH scalar	multiplication function to the secret key (into scalar input) and the peer's public key (into u-coordinate point input).  The output is used raw, with no processing.
	SharedSecret []byte
}

type RsaCipher struct {
	PrivateKey   *rsa.PrivateKey
	PublicKey    *rsa.PublicKey
	LengthRecord bool
}
type DsaCipher struct {
	PrivateKey *dsa.PrivateKey
	PublicKey  *dsa.PublicKey
}

type DhParams struct {
	P            *big.Int
	Q            *big.Int
	Private      *big.Int
	Public       *big.Int
	ClientPublic *big.Int
	Group        *DHGroups
}

type DHGroups byte

const (
	// https://www.rfc-editor.org/rfc/rfc7919.html
	// TLS1.3 TODO fill them
	DhGroupX25519 DHGroups = 0x001D
)

var SupportedGroups = map[DHGroups]struct{}{
	DhGroupX25519: {},
}

type CompressionMethod byte

const (
	CompressionAlgorithmNull    CompressionMethod = 0
	CompressionAlgorithmDeflate CompressionMethod = 1
	// I found it in seperate rfc, rfcs related to ssl 3.0 tls 1.0 etc only contain null as compression algorithm, nothing more. In tls 1.3 field is depracted
	// Deflate has vunluberity problem, here is how it works https://zlib.net/feldspar.html
	// Defalte uses loseless compression, attacker can add some data (singular letters i guess) to user's request and observe if length is changing, by doing that it can discover with letter is ocucring and which not.
)

const (
	CIPHER_SUITE_SSL_NULL_WITH_NULL_NULL            TLSCipherSuite = 0x0000
	CIPHER_SUITE_SSL_RSA_WITH_NULL_MD5              TLSCipherSuite = 0x0001
	CIPHER_SUITE_SSL_RSA_WITH_NULL_SHA              TLSCipherSuite = 0x0002
	CIPHER_SUITE_SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5 TLSCipherSuite = 0x0006
	CIPHER_SUITE_SSL_RSA_WITH_IDEA_CBC_SHA          TLSCipherSuite = 0x0007
	CIPHER_SUITE_SSL_RSA_EXPORT_WITH_DES40_CBC_SHA  TLSCipherSuite = 0x0008
	CIPHER_SUITE_SSL_RSA_WITH_DES_CBC_SHA           TLSCipherSuite = 0x0009
	CIPHER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA      TLSCipherSuite = 0x000A
	CIPHER_SUITE_SSL_RSA_WITH_AES_128_CBC_SHA       TLSCipherSuite = 0x002F
	CIPHER_SUITE_SSL_RSA_WITH_AES_256_CBC_SHA       TLSCipherSuite = 0x0035
	CIPHER_SUITE_SSL_RSA_WITH_AES_128_CBC_SHA256    TLSCipherSuite = 0x003C
	CIPHER_SUITE_SSL_RSA_WITH_AES_256_CBC_SHA256    TLSCipherSuite = 0x003D
	//Following cipher suite definition requires that server provide an rsa certificat ethat can be used for key exchange.
	CIPHER_SUITE_SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA  TLSCipherSuite = 0x000B
	CIPHER_SUITE_SSL_DH_DSS_WITH_DES_CBC_SHA           TLSCipherSuite = 0x000C
	CIPHER_SUITE_SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA      TLSCipherSuite = 0x000D
	CIPHER_SUITE_SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA  TLSCipherSuite = 0x000E
	CIPHER_SUITE_SSL_DH_RSA_WITH_DES_CBC_SHA           TLSCipherSuite = 0x000F
	CIPHER_SUITE_SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA      TLSCipherSuite = 0x0010
	CIPHER_SUITE_SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA TLSCipherSuite = 0x0011
	CIPHER_SUITE_SSL_DHE_DSS_WITH_DES_CBC_SHA          TLSCipherSuite = 0x0012
	CIPHER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA     TLSCipherSuite = 0x0013
	CIPHER_SUITE_SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA TLSCipherSuite = 0x0014
	CIPHER_SUITE_SSL_DHE_RSA_WITH_DES_CBC_SHA          TLSCipherSuite = 0x0015
	CIPHER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA     TLSCipherSuite = 0x0016
	CIPHER_SUITE_SSL_DHE_DSS_WITH_AES_256_CBC_SHA      TLSCipherSuite = 0x0038
	CIPHER_SUITE_SSL_DH_RSA_WITH_AES_128_CBC_SHA256    TLSCipherSuite = 0x003F
	CIPHER_SUITE_SSL_DHE_RSA_WITH_AES_256_CBC_SHA      TLSCipherSuite = 0x0039
	CIPHER_SUITE_SSL_DHE_DSS_WITH_AES_128_CBC_SHA256   TLSCipherSuite = 0x0040
	CIPHER_SUITE_SSL_DHE_RSA_WITH_AES_128_CBC_SHA256   TLSCipherSuite = 0x0067
	CIPHER_SUITE_SSL_DH_DSS_WITH_AES_256_CBC_SHA256    TLSCipherSuite = 0x0068
	CIPHER_SUITE_SSL_DH_RSA_WITH_AES_256_CBC_SHA256    TLSCipherSuite = 0x0069
	CIPHER_SUITE_SSL_DHE_DSS_WITH_AES_256_CBC_SHA256   TLSCipherSuite = 0x006A
	CIPHER_SUITE_SSL_DHE_RSA_WITH_AES_256_CBC_SHA256   TLSCipherSuite = 0x006B
	// Folowing cipher suited are used for server-authenticated (optianlly client) diffie-hellman. Dh denotes cipher suited in which the server-s certificate contains dh paramters signed by the  certificate authority.
	// dhe denothes ephemral diffie-hellman where dh paramters are signed by dss or rsa cerificate, which has been signed by ca. The sigin algorithm used in specified after the dh or dhepparamter.
	// In all case  the clie must have the same type of cerificate, and must use the dh paramters chosen by the server

	CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA   TLSCipherSuite = 0x001B
	CIPHER_SUITE_SSL_DH_anon_WITH_AES_128_CBC_SHA    TLSCipherSuite = 0x0034
	CIPHER_SUITE_SSL_DH_anon_WITH_AES_256_CBC_SHA    TLSCipherSuite = 0x003A
	CIPHER_SUITE_SSL_DH_anon_WITH_AES_128_CBC_SHA256 TLSCipherSuite = 0x006C
	CIPHER_SUITE_SSL_DH_anon_WITH_AES_256_CBC_SHA256 TLSCipherSuite = 0x006D
	// The following cipher suited are used for completely anonymous diffie hellman in which neither party is authenticated. Note thi is extremly vuluberable to man in the middle attackers, so its strongly discouraged to use it.
	CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_NULL_SHA         TLSCipherSuite = 0x001C
	CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA TLSCipherSuite = 0x001D
	// fortezza tokens used in the highly secure env such as goverment
	//

	// TLS 1.3 ciphers
	CIPHER_SUITE_SSL_AES_128_GCM_SHA256       TLSCipherSuite = 0x1301
	CIPHER_SUITE_SSL_AES_256_GCM_SHA384       TLSCipherSuite = 0x1302
	CIPHER_SUITE_SSL_CHACHA20_POLY1305_SHA256 TLSCipherSuite = 0x1303
	CIPHER_SUITE_SSL_AES_128_CCM_SHA256       TLSCipherSuite = 0x1304
	CIPHER_SUITE_SSL_AES_128_CCM_8_SHA256     TLSCipherSuite = 0x1305
)

// Export Ciphers: These ciphers were created to comply with U.S. regulations. As a result, export ciphers used reduced-strength encryption (e.g., 40-bit DES) and short (512-bit) RSA keys.

// Let create a simpler structure, to be easier to parse than this intresting way of nameing things :) key-exchange_cert_export-mode_algo_algo-params_hashing
var CIPHER_SUITE_NAME = map[TLSCipherSuite]string{
	CIPHER_SUITE_SSL_NULL_WITH_NULL_NULL:            "NULL_NULL_WITH_NULL_NULL_NULL",
	CIPHER_SUITE_SSL_RSA_WITH_NULL_MD5:              "RSA_RSA_WITH_NULL_NULL_MD5",
	CIPHER_SUITE_SSL_RSA_WITH_NULL_SHA:              "RSA_RSA_WITH_NULL_NULL_SHA",
	CIPHER_SUITE_SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5: "RSA_RSA_EXPORT_RC2_CBC-40_MD5",
	CIPHER_SUITE_SSL_RSA_WITH_IDEA_CBC_SHA:          "RSA_RSA_WITH_IDEA_CBC_SHA",
	CIPHER_SUITE_SSL_RSA_EXPORT_WITH_DES40_CBC_SHA:  "RSA_RSA_EXPORT_DES40_CBC_SHA",
	CIPHER_SUITE_SSL_RSA_WITH_DES_CBC_SHA:           "RSA_RSA_WITH_DES_CBC_SHA",
	CIPHER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA:      "RSA_RSA_WITH_3DES_EDE-CBC_SHA",
	CIPHER_SUITE_SSL_RSA_WITH_AES_128_CBC_SHA:       "RSA_RSA_WITH_AES_128-CBC_SHA",
	CIPHER_SUITE_SSL_RSA_WITH_AES_256_CBC_SHA:       "RSA_RSA_WITH_AES_256-CBC_SHA",
	CIPHER_SUITE_SSL_RSA_WITH_AES_128_CBC_SHA256:    "RSA_RSA_WITH_AES_128-CBC_SHA256",
	CIPHER_SUITE_SSL_RSA_WITH_AES_256_CBC_SHA256:    "RSA_RSA_WITH_AES_256-CBC_SHA256",
	//Following cipher suite definition requires that server provide an rsa certificat ethat can be used for key exchange.
	CIPHER_SUITE_SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:  "DH_DSS_EXPORT_DES40_CBC_SHA",
	CIPHER_SUITE_SSL_DH_DSS_WITH_DES_CBC_SHA:           "DH_DSS_WITH_DES_CBC_SHA",
	CIPHER_SUITE_SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA:      "DH_DSS_WITH_3DES_EDE-CBC_SHA",
	CIPHER_SUITE_SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:  "DH_RSA_EXPORT_DES40_CBC_SHA",
	CIPHER_SUITE_SSL_DH_RSA_WITH_DES_CBC_SHA:           "DH_RSA_WITH_DES_CBC_SHA",
	CIPHER_SUITE_SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA:      "DH_RSA_WITH_3DES_EDE-CBC_SHA",
	CIPHER_SUITE_SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA: "DHE_DSS_EXPORT_DES40_CBC_SHA",
	CIPHER_SUITE_SSL_DHE_DSS_WITH_DES_CBC_SHA:          "DHE_DSS_WITH_DES_CBC_SHA",
	CIPHER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA:     "DHE_DSS_WITH_3DES_EDE-CBC_SHA",
	CIPHER_SUITE_SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA: "DHE_RSA_EXPORT_DES40_CBC_SHA",
	CIPHER_SUITE_SSL_DHE_RSA_WITH_DES_CBC_SHA:          "DHE_RSA_WITH_DES_CBC_SHA",
	CIPHER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA:     "DHE_RSA_WITH_3DES_EDE-CBC_SHA",
	CIPHER_SUITE_SSL_DH_RSA_WITH_AES_128_CBC_SHA256:    "DH_RSA_WITH_AES_128-CBC_SHA256",
	CIPHER_SUITE_SSL_DHE_RSA_WITH_AES_128_CBC_SHA256:   "DHE_RSA_WITH_AES_128-CBC_SHA256",
	CIPHER_SUITE_SSL_DHE_DSS_WITH_AES_256_CBC_SHA:      "DHE_DSS_WITH_AES_256-CBC_SHA",
	CIPHER_SUITE_SSL_DHE_RSA_WITH_AES_256_CBC_SHA:      "DHE_RSA_WITH_AES_256-CBC_SHA",
	CIPHER_SUITE_SSL_DHE_DSS_WITH_AES_128_CBC_SHA256:   "DHE_DSS_WITH_AES_128-CBC_SHA256",
	CIPHER_SUITE_SSL_DH_DSS_WITH_AES_256_CBC_SHA256:    "DH_DSS_WITH_AES_256-CBC_SHA256",
	CIPHER_SUITE_SSL_DH_RSA_WITH_AES_256_CBC_SHA256:    "DH_RSA_WITH_AES_256-CBC_SHA256",
	CIPHER_SUITE_SSL_DHE_DSS_WITH_AES_256_CBC_SHA256:   "DHE_DSS_WITH_AES_256-CBC_SHA256",
	CIPHER_SUITE_SSL_DHE_RSA_WITH_AES_256_CBC_SHA256:   "DHE_RSA_WITH_AES_256-CBC_SHA256",
	// Folowing cipher suited are used for server-authenticated (optianlly client) diffie-hellman. Dh denotes cipher suited in which the server-s certificate contains dh paramters signed by the  certificate authority.
	// dhe denothes ephemral diffie-hellman where dh paramters are signed by dss or rsa cerificate, which has been signed by ca. The sigin algorithm used in specified after the dh or dhepparamter.
	// In all case  the clie must have the same type of cerificate, and must use the dh paramters chosen by the server
	CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:   "DH_anon_WITH_3DES_EDE-CBC_SHA",
	CIPHER_SUITE_SSL_DH_anon_WITH_AES_128_CBC_SHA:    "DH_anon_WITH_AES_128-CBC_SHA",
	CIPHER_SUITE_SSL_DH_anon_WITH_AES_128_CBC_SHA256: "DH_anon_WITH_AES_128-CBC_SHA256",
	CIPHER_SUITE_SSL_DH_anon_WITH_AES_256_CBC_SHA:    "DH_anon_WITH_AES_256-CBC_SHA",
	CIPHER_SUITE_SSL_DH_anon_WITH_AES_256_CBC_SHA256: "DH_anon_WITH_AES_256-CBC_SHA256",
	// The following cipher suited are used for completely anonymous diffie hellman in which neither party is authenticated. Note thi is extremly vuluberable to man in the middle attackers, so its strongly discouraged to use it.
	CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_NULL_SHA:         "FORTEZZA_FORTEZZA_KEA_WITH_NULL_SHA",
	CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA: "FORTEZZA_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA",

	// TLS 1.3
	CIPHER_SUITE_SSL_AES_128_GCM_SHA256:       "DH_anon_WITH_AES_128-GCM_SHA256",
	CIPHER_SUITE_SSL_AES_256_GCM_SHA384:       "DH_anon_WITH_AES_256-GCM_SHA384",
	CIPHER_SUITE_SSL_CHACHA20_POLY1305_SHA256: "DH_anon_WITH_CHACHA20_POLY1305_SHA256",
}

func (cipherDef *CipherDef) DecryptMessage(encryptedData []byte, writeKey, iv, seqNum, additionalData []byte) ([]byte, error) {

	var decryptedData []byte
	var err error
	switch cipherDef.Spec.EncryptionAlgorithm {
	case EncryptionAlgorithm3DES:
		decryptedData, err = Decrypt3DesMessage(encryptedData, writeKey, iv)
	case EncryptionAlgorithmDES:
		decryptedData, err = DecryptDesMessage(encryptedData, writeKey, iv)
	case EncryptionAlgorithmDES40:
		decryptedData, err = DecryptDesMessage(encryptedData, writeKey, iv)
	case EncryptionAlgorithmAES:
		decryptedData, err = cipherDef.DecryptAESMessage(encryptedData, writeKey, iv, seqNum, additionalData)
	case EncryptionAlgorithmCHACHA20:
		decryptedData, err = cipherDef.decryptChacha20(encryptedData, writeKey, iv, seqNum, additionalData)
	default:
		return []byte{}, fmt.Errorf("decryption algorithm: %v not implemented", cipherDef.Spec.EncryptionAlgorithm)
	}
	if err != nil {
		return nil, err
	}
	if cipherDef.Spec.IvAsPayload {
		// Used by tls1.1, tls 1.2
		if cipherDef.Spec.IvSize == 0 {
			return decryptedData, nil
		}
		if len(decryptedData) < cipherDef.Spec.IvSize {
			panic("decrypt data cant be shorter than iv size")
		}

		cipherDef.Keys.IVClient = decryptedData[:cipherDef.Spec.IvSize]

		return decryptedData[cipherDef.Spec.IvSize:], nil
	}
	return decryptedData, nil
}

func (cipherDef *CipherDef) EncryptMessage(data []byte, writeKey, iv, seqNum, additionalData []byte) ([]byte, error) {
	var encryptedMsg []byte
	var err error
	switch cipherDef.Spec.EncryptionAlgorithm {
	case EncryptionAlgorithm3DES:
		encryptedMsg, err = cipherDef.Encrypt3DesMessage(data, writeKey, iv)
	case EncryptionAlgorithmDES:
		encryptedMsg, err = cipherDef.EncryptDesMessage(data, writeKey, iv)
	case EncryptionAlgorithmDES40:
		encryptedMsg, err = cipherDef.EncryptDesMessage(data, writeKey, iv)
	case EncryptionAlgorithmAES:
		encryptedMsg, err = cipherDef.EncryptAESMessage(data, writeKey, iv, seqNum, additionalData)
	case EncryptionAlgorithmCHACHA20:
		encryptedMsg, err = cipherDef.encryptChacha20(data, writeKey, iv, seqNum, additionalData)
	default:
		return []byte{}, fmt.Errorf("encryption algorithm: %v not implemented", cipherDef.Spec.EncryptionAlgorithm)
	}

	return encryptedMsg, err
}

func (cipherDef *CipherDef) ComputeMasterSecret(data []byte) ([]byte, error) {
	var preMasterSecret []byte
	switch cipherDef.Spec.KeyExchange {
	case KeyExchangeMethodDH:
		clientPublicKeyLength := binary.BigEndian.Uint16(data[:2])
		clientPublicKey := data[2 : 2+clientPublicKeyLength]
		clinetPublicKeyInt := new(big.Int).SetBytes(clientPublicKey)
		cipherDef.DhParams.ClientPublic = clinetPublicKeyInt
		preMasterSecret = cipherDef.DhParams.ComputePreMasterSecret().Bytes()
	case KeyExchangeMethodRSA:
		// Starting from tls 1.0 there is additional length before rsa signed data
		if cipherDef.Rsa.LengthRecord {
			keyLength := binary.BigEndian.Uint16(data[:2])
			if int(keyLength) != len(data)-2 {
				return nil, fmt.Errorf("invalid content length, expected: %v, got: %v", int(keyLength), len(data)-2)
			}
			data = data[2:]
		}
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, cipherDef.Rsa.PrivateKey, data)
		if err != nil {
			return nil, fmt.Errorf("couldnt decrypt rsa, err: %v", err)
		}
		preMasterSecret = decrypted
	default:
		return nil, fmt.Errorf("key exchange method: %v not implmeneted yet", cipherDef.Spec.KeyExchange)
	}

	return preMasterSecret, nil

}

type DSA_SIG struct {
	R *big.Int
	S *big.Int
}

func (cipherDef *CipherDef) GenerateServerKeyExchange() ([]byte, error) {

	switch cipherDef.Spec.KeyExchange {
	case KeyExchangeMethodDH:
		return cipherDef.DhParams.GenerateDhParams(cipherDef.Spec.KeyExchangeRotation)
	case KeyExchangeMethodRSA:
		return []byte{}, nil
	default:
		return nil, fmt.Errorf("Key exchange parameters not implemented for: %v", cipherDef.Spec.KeyExchange)
	}
}

func (cipherDef *CipherDef) TLS13SignData(data []byte) ([]byte, error) {
	// Hash the data using SHA-256
	hasher := sha256.New()
	_, err := hasher.Write(data)
	if err != nil {
		return nil, fmt.Errorf("failed to hash data: %v", err)
	}
	hashed := hasher.Sum(nil)

	// Set salt length to the hash size (32 bytes for SHA-256)
	saltLength := hasher.Size()

	// Sign the hash using RSA-PSS with MGF1 using SHA-256
	signature, err := rsa.SignPSS(rand.Reader, cipherDef.Rsa.PrivateKey, crypto.SHA256, hashed, &rsa.PSSOptions{
		SaltLength: saltLength,
		Hash:       crypto.SHA256,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %v", err)
	}

	// Return the base64-encoded signature
	return signature, nil
}

func (cipherDef *CipherDef) SignData(hash []byte) ([]byte, error) {
	switch cipherDef.Spec.SignatureAlgorithm {
	case SignatureAlgorithmAnonymous:
		return []byte{}, nil
	case SignatureAlgorithmRSA:
		if cipherDef.Rsa.PrivateKey == nil {
			return nil, fmt.Errorf("\n Cant find rsa private key")
		}

		cryptoHash := crypto.Hash(0)
		if cipherDef.Spec.HashBasedSigning {
			switch cipherDef.Spec.ExtHashAlgorithmIdentifier {
			case HashAlgorithmNumberNone:
				return nil, fmt.Errorf("key exchange should be hashed, we got value none hash algorithm")
			case HashAlgorithmNumberMd5:
				cryptoHash = crypto.MD5
			case HashAlgorithmNumberSha1:
				cryptoHash = crypto.SHA1
			case HashAlgorithmNumberSha224:
				cryptoHash = crypto.SHA224
			case HashAlgorithmNumberSha256:
				cryptoHash = crypto.SHA256
			case HashAlgorithmNumberSha384:
				cryptoHash = crypto.SHA384
			case HashAlgorithmNumberSha512:
				cryptoHash = crypto.SHA512
			default:
				return nil, fmt.Errorf("hash algorithm not implemented in singData, trying to use: %v", cipherDef.Spec.ExtHashAlgorithmIdentifier)
			}
		}
		signature, err := rsa.SignPKCS1v15(rand.Reader, cipherDef.Rsa.PrivateKey, cryptoHash, hash)

		if err != nil {
			return nil, fmt.Errorf("\n problem ecnrypting data, err: %v", err)
		}

		return signature, nil

	case SignatureAlgorithmDSA:
		if cipherDef.Dsa.PrivateKey == nil {
			return nil, fmt.Errorf("\n Cant find dsa private key")
		}
		r, s, err := dsa.Sign(rand.Reader, cipherDef.Dsa.PrivateKey, hash)
		if err != nil {
			return nil, fmt.Errorf("\n error while singing, err: %v", err)
		}
		signature, err := asn1.Marshal(DSA_SIG{R: r, S: s})
		if err != nil {
			return nil, fmt.Errorf("\n error occured while marshal r,s to anc1 structure, err:%v", err)
		}
		return signature, nil

	default:
		return nil, fmt.Errorf("unsupported Algorithm: %v", cipherDef.Spec.SignatureAlgorithm)
	}

}

func (cipherDef *CipherDef) VerifySignedData(hash, signature []byte) error {
	var err error
	switch cipherDef.Spec.SignatureAlgorithm {
	case SignatureAlgorithmAnonymous:
	case SignatureAlgorithmRSA:
		err = rsa.VerifyPKCS1v15(cipherDef.Rsa.PublicKey, crypto.Hash(0), hash, signature)

	case SignatureAlgorithmDSA:
		var params DSA_SIG

		_, err := asn1.Unmarshal(signature, &params)
		if err != nil {
			return fmt.Errorf("\n error unmarshaling, err: %v", err)
		}

		ok := dsa.Verify(cipherDef.Dsa.PublicKey, hash, params.R, params.S)
		if !ok {
			return fmt.Errorf("cant verify dsa signature")
		}

	default:
		return fmt.Errorf("unsupported Algorithm: %v", cipherDef.Spec.SignatureAlgorithm)
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

// Sweet32 attacks on cipher block 64 bytes (des, 3des, blow fish)
// The DES ciphers (and triple-DES) only have a 64-bit block size. ciphers are mostly vulnerable to birthday attacks when the message is 2n/2 block of messages. This enables an attacker to run JavaScript in a browser and send large amounts of traffic during the same TLS connection, creating a collision. With this collision, the attacker is able to retrieve information from a session cookie.
// Due to a flaw in the algorithm, there will be a situation where two block has the same key. An attacker can access the information by using XOR operation on the blocks to reveal the plain text.
// This vulnerability could be used by a man-in-the-middle attacker to recover some plaintext data. The attacker is able to intercept vast volumes of encrypted traffic between the client and the TLS/SSL server.
// Sweet32 can break 3des in matter of minutes or even seconds

// blow fish - faster than 3des, but still vulnerable to sweet32, probably that's why was never used in ssl/tls. Moreover short afrer bf release AES was published

// AES - is consider secure, tls 1.3 can be confirmation of it as it is still using it as recommended cipher.
// https://www.baeldung.com/cs/des-vs-3des-vs-blowfish-vs-aes according to this source where 3des was broken in 800, for aes we need >13 bilion years.
// TODO: update list
var serverCipherPreferences = []TLSCipherSuite{
	CIPHER_SUITE_SSL_AES_256_GCM_SHA384,
	CIPHER_SUITE_SSL_AES_128_GCM_SHA256,
	CIPHER_SUITE_SSL_CHACHA20_POLY1305_SHA256,
	CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA,
	CIPHER_SUITE_SSL_DHE_DSS_WITH_AES_256_CBC_SHA256,
	CIPHER_SUITE_SSL_DHE_RSA_WITH_AES_256_CBC_SHA256,
	CIPHER_SUITE_SSL_DHE_DSS_WITH_AES_256_CBC_SHA,
	CIPHER_SUITE_SSL_DHE_RSA_WITH_AES_256_CBC_SHA,
	CIPHER_SUITE_SSL_DHE_RSA_WITH_AES_128_CBC_SHA256,
	CIPHER_SUITE_SSL_DHE_DSS_WITH_AES_128_CBC_SHA256,
	CIPHER_SUITE_SSL_DHE_RSA_WITH_AES_128_CBC_SHA256,
	CIPHER_SUITE_SSL_DH_DSS_WITH_AES_256_CBC_SHA256,
	CIPHER_SUITE_SSL_DH_RSA_WITH_AES_256_CBC_SHA256,
	CIPHER_SUITE_SSL_DH_RSA_WITH_AES_128_CBC_SHA256,
	CIPHER_SUITE_SSL_RSA_WITH_AES_256_CBC_SHA256,
	CIPHER_SUITE_SSL_RSA_WITH_AES_128_CBC_SHA256,
	CIPHER_SUITE_SSL_RSA_WITH_AES_256_CBC_SHA,
	CIPHER_SUITE_SSL_RSA_WITH_AES_128_CBC_SHA,
	CIPHER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA,
	CIPHER_SUITE_SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA,
	CIPHER_SUITE_SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA,
	CIPHER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	CIPHER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
	CIPHER_SUITE_SSL_RSA_WITH_DES_CBC_SHA,
	CIPHER_SUITE_SSL_DHE_DSS_WITH_DES_CBC_SHA,
	CIPHER_SUITE_SSL_DHE_RSA_WITH_DES_CBC_SHA,
	CIPHER_SUITE_SSL_DH_DSS_WITH_DES_CBC_SHA,
	CIPHER_SUITE_SSL_DH_RSA_WITH_DES_CBC_SHA,
	CIPHER_SUITE_SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,
	CIPHER_SUITE_SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
	CIPHER_SUITE_SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
	CIPHER_SUITE_SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
	CIPHER_SUITE_SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
	CIPHER_SUITE_SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	CIPHER_SUITE_SSL_RSA_WITH_IDEA_CBC_SHA,
	CIPHER_SUITE_SSL_DH_anon_WITH_AES_256_CBC_SHA256,
	CIPHER_SUITE_SSL_DH_anon_WITH_AES_128_CBC_SHA256,
	CIPHER_SUITE_SSL_DH_anon_WITH_AES_256_CBC_SHA,
	CIPHER_SUITE_SSL_DH_anon_WITH_AES_128_CBC_SHA,
	CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA,
	CIPHER_SUITE_SSL_RSA_WITH_NULL_SHA,
	CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_NULL_SHA,
	CIPHER_SUITE_SSL_RSA_WITH_NULL_MD5,
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

func zerosPadding(src []byte, blockSize int) []byte {
	paddingLen := blockSize - len(src)%blockSize

	padtext := bytes.Repeat([]byte{0}, paddingLen-1)
	padtext = append(padtext, byte(paddingLen-1))
	return append(src, padtext...)
}

func LengthPadding(src []byte, blockSize int) []byte {
	paddingLen := blockSize - len(src)%blockSize

	padtext := bytes.Repeat([]byte{byte(paddingLen - 1)}, paddingLen-1)
	padtext = append(padtext, byte(paddingLen-1))
	return append(src, padtext...)
}

func (cipherDef *CipherDef) addPadding(src []byte, blockSize int) []byte {

	return LengthPadding(src, blockSize)
}

func (cipherDef *CipherDef) GetCipherSpecInfo() error {
	cipherSuite := CIPHER_SUITE_NAME[TLSCipherSuite(cipherDef.CipherSuite)]
	cipherSuitParts := strings.Split(cipherSuite, "_")
	if len(cipherSuitParts) < 6 {
		panic("These suit should never have less than 6 parts")
	}
	keyExchange := cipherSuitParts[0]
	singinAlgorithm := cipherSuitParts[1]
	encryptionAlgorithm := cipherSuitParts[3]
	encryptionAlgorithmParams := strings.Split(cipherSuitParts[4], "-")
	encryptionAlgorithmWithParams := []string{encryptionAlgorithm}
	encryptionAlgorithmWithParams = append(encryptionAlgorithmWithParams, encryptionAlgorithmParams...)
	hashingMethod := cipherSuitParts[5]

	switch keyExchange {
	case "DH":
		cipherDef.Spec.KeyExchange = KeyExchangeMethodDH
	case "DHE":
		cipherDef.Spec.KeyExchange = KeyExchangeMethodDH
		cipherDef.Spec.KeyExchangeRotation = true
	case "RSA":
		cipherDef.Spec.KeyExchange = KeyExchangeMethodRSA
	default:
		fmt.Printf("\n key exchange method not implemented: %v", keyExchange)
		os.Exit(1)
	}

	switch encryptionAlgorithm {
	case "3DES":
		cipherDef.Spec.KeyMaterial = 24
		cipherDef.Spec.ExportKeyMaterial = 24
		cipherDef.Spec.IvSize = 8
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithm3DES
	case "DES":
		cipherDef.Spec.KeyMaterial = 8
		cipherDef.Spec.ExportKeyMaterial = 8
		cipherDef.Spec.IvSize = 8
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithmDES
	case "DES40":
		// wekening key https://datatracker.ietf.org/doc/html/draft-hoffman-des40-03
		cipherDef.Spec.KeyMaterial = 5
		cipherDef.Spec.ExportKeyMaterial = 8
		cipherDef.Spec.IvSize = 8
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithmDES40
	case "RC4":
		cipherDef.Spec.IvSize = 0
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithmRC4
	case "RC2":
		cipherDef.Spec.IvSize = 8
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithmRC2
	case "AES":
	case "CHACHA20":
		// Just for sake not backward compability breaking
	default:
		fmt.Printf("\n encryption algorithm not implemented: %v", encryptionAlgorithm)
		os.Exit(1)
	}

	for _, param := range encryptionAlgorithmParams {
		switch param {
		case "CBC":
			// TODO: implement this, we use cbc by default everywhere
		case "EDE":
		case "128":
			cipherDef.Spec.KeyMaterial = 16
			cipherDef.Spec.ExportKeyMaterial = 16
		case "40":
			cipherDef.Spec.KeyMaterial = 5
			cipherDef.Spec.ExportKeyMaterial = 16
		case "256":
		case "GCM":
			// "For IVs, it is recommended that implementations restrict support to the length of 96 bits, to promote interoperability, efficiency, and simplicity of design"
			// https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf?utm_source=chatgpt.com
			cipherDef.Spec.IvSize = 12
			cipherDef.Spec.EncryptionAlgorithmBlockMode = EncryptionAlgorithmBlockModeGCM
		case "POLY1305":
			// "For IVs, it is recommended that implementations restrict support to the length of 96 bits, to promote interoperability, efficiency, and simplicity of design"
			// https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf?utm_source=chatgpt.com
			cipherDef.Spec.IvSize = 12
		default:
			fmt.Printf("\n encryption param not implemented %v", param)
			os.Exit(1)
		}
	}

	// TODO: even though above one is working i think rewrite is needed, there is no assurances that i will cover all cases, new implementations follow rfc docs representation

	//                         Key      IV   Block
	// Cipher        Type    Material  Size  Size
	// ------------  ------  --------  ----  -----
	// NULL          Stream      0       0    N/A
	// RC4_128       Stream     16       0    N/A
	// 3DES_EDE_CBC  Block      24       8      8
	// AES_128_CBC   Block      16      16     16
	// AES_256_CBC   Block      32      16     16
	switch strings.Join(encryptionAlgorithmWithParams, "_") {
	case "AES_128_CBC":
		cipherDef.Spec.IvSize = 16
		cipherDef.Spec.KeyMaterial = 16
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithmAES
	case "AES_128_GCM":

		cipherDef.Spec.KeyMaterial = 16
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithmAES
	case "AES_256_GCM":
		cipherDef.Spec.KeyMaterial = 32
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithmAES
	case "CHACHA20_POLY1305":
		cipherDef.Spec.KeyMaterial = 32
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithmCHACHA20
	case "AES_256_CBC":
		cipherDef.Spec.IvSize = 16
		cipherDef.Spec.KeyMaterial = 32
		cipherDef.Spec.EncryptionAlgorithm = EncryptionAlgorithmAES
	}
	switch hashingMethod {
	case "SHA":
		cipherDef.Spec.HashAlgorithm = sha1.New
		cipherDef.Spec.HashSize = 20
		cipherDef.Spec.ExtHashAlgorithmIdentifier = HashAlgorithmNumberSha1
	case "MD5":
		cipherDef.Spec.HashAlgorithm = md5.New
		cipherDef.Spec.ExtHashAlgorithmIdentifier = HashAlgorithmNumberMd5
		cipherDef.Spec.HashSize = 16
	case "SHA256":
		cipherDef.Spec.HashAlgorithm = sha256.New
		cipherDef.Spec.HashSize = 32
		cipherDef.Spec.ExtHashAlgorithmIdentifier = HashAlgorithmNumberSha256
	case "SHA384":
		cipherDef.Spec.HashAlgorithm = sha512.New384
		cipherDef.Spec.HashSize = 48
		cipherDef.Spec.ExtHashAlgorithmIdentifier = HashAlgorithmNumberSha384
	default:
		fmt.Printf("\n hashing method not implemented: %v", hashingMethod)
		os.Exit(1)
	}

	switch singinAlgorithm {
	case "DSS":
		cipherDef.Spec.SignatureAlgorithm = SignatureAlgorithmDSA
		cipherDef.Spec.ExtSignatureAlgorithmIdentifier = SignatureAlgorithmNumberDsa
	case "RSA":
		cipherDef.Spec.SignatureAlgorithm = SignatureAlgorithmRSA
		cipherDef.Spec.ExtSignatureAlgorithmIdentifier = SignatureAlgorithmNumberRsa
	case "anon":
		cipherDef.Spec.SignatureAlgorithm = SignatureAlgorithmAnonymous
		cipherDef.Spec.ExtSignatureAlgorithmIdentifier = SignatureAlgorithmNumberAnonymous
	default:
		fmt.Printf("\n singinAlgorithm not implemented: %v", singinAlgorithm)
		os.Exit(1)
	}

	// If the client does not send the signature_algorithms extension, the
	// server MUST do the following:

	// -  If the negotiated key exchange algorithm is one of (RSA, DHE_RSA,
	//    DH_RSA, RSA_PSK, ECDH_RSA, ECDHE_RSA), behave as if client had
	//    sent the value {sha1,rsa}.

	// -  If the negotiated key exchange algorithm is one of (DHE_DSS,
	//    DH_DSS), behave as if the client had sent the value {sha1,dsa}.

	// -  If the negotiated key exchange algorithm is one of (ECDH_ECDSA,
	//    ECDHE_ECDSA), behave as if the client had sent value {sha1,ecdsa}.

	// Default hashAlgorithmvalue for Signature Algorithms extenstion type 13, signature algorithm is implemented in "switch singinAlgorithm"

	cipherDef.Spec.ExtHashAlgorithmIdentifier = HashAlgorithmNumberSha1

	return nil
}

func findMax(arr []byte) byte {
	if len(arr) == 0 {
		panic("Array passed to findMax is empty")
	}

	max := arr[0]
	for _, value := range arr {
		if value > max {
			max = value
		}
	}
	return max
}

func (cipherDef *CipherDef) ExtSetSignatureAlgorithms(data []byte) error {
	if len(data)%2 != 0 {
		return fmt.Errorf("data length should be an odd value, as its key pair: hash algorithm, signature")
	}

	// 	  Because DSA signatures do not contain any secure indication of hash
	//    algorithm, there is a risk of hash substitution if multiple hashes
	//    may be used with any key.  Currently, DSA [DSS] may only be used with
	//    SHA-1.  Future revisions of DSS [DSS-3] are expected to allow the use
	//    of other digest algorithms with DSA.

	if cipherDef.Spec.SignatureAlgorithm == SignatureAlgorithmDSA {
		cipherDef.Spec.ExtHashAlgorithmIdentifier = HashAlgorithmNumberSha1
		return nil
	}

	singnaturesHashMap := make(map[byte][]byte)
	for i := 0; i < len(data); i += 2 {
		hashAlgorithm := data[i]
		signatureAlgorithm := data[i+1]
		newVal := singnaturesHashMap[signatureAlgorithm]
		newVal = append(newVal, hashAlgorithm)
		singnaturesHashMap[signatureAlgorithm] = newVal
	}

	hashAvailable := singnaturesHashMap[byte(cipherDef.Spec.ExtHashAlgorithmIdentifier)]

	if len(hashAvailable) == 0 {
		return fmt.Errorf("no hash algorithms available for singature: %v", cipherDef.Spec.ExtHashAlgorithmIdentifier)
	}

	maxValue := findMax(hashAvailable)

	cipherDef.Spec.ExtHashAlgorithmIdentifier = HashAlgorithmIdentifier(maxValue)

	return nil
}
