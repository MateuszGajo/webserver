package cipher

import (
	"crypto/cipher"
	"crypto/dsa"
	"crypto/rc4"
	"crypto/rsa"
	"math/big"
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
	HashAlgorithmSHA HashAlgorithm = "SHA"
	HashAlgorithmMD5 HashAlgorithm = "MD5"
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
	EncryptionAlgorithmFortezza EncryptionAlgorithm = "FORTEZZA"
)

type SignatureAlgorithm string

const (
	SignatureAlgorithmRSA       SignatureAlgorithm = "signatureRSA"
	SignatureAlgorithmDSA       SignatureAlgorithm = "signatureDSA" // DSS is standard developved by nist, DSA is algorithm defines within for creating and veryfin digital signatures
	SignatureAlgorithmAnonymous SignatureAlgorithm = "signatureAnonymous"
)

type CipherSpec struct {
	HashSize          int
	KeyMaterial       int
	ExportKeyMaterial int
	IvSize            int
	HashAlgorithm     HashAlgorithm
	KeyExchange       KeyExchangeMethod
	// Use this paramter when using DHE key exchange, as dh has almost the same implementation to dhe
	KeyExchangeRotation bool
	EncryptionAlgorithm EncryptionAlgorithm
	SignatureAlgorithm  SignatureAlgorithm
	CompressionMethod   CompressionMethod
	IsExportable        bool
}

type CipherDef struct {
	Keys               CipherKeys
	Spec               CipherSpec
	CipherSuite        uint16
	DhParams           DhParams
	Rsa                RsaCipher
	Dsa                DsaCipher
	Rc4                RC4Cipher
	Rc2                RC2Cipherr
	PreferServerCipher bool
}

type RC4Cipher struct {
	EncryptCipher *rc4.Cipher
	DecryptCipher *rc4.Cipher
}

type RC2Cipherr struct {
	EncryptCipher *cipher.Block
	DecryptCipher *cipher.Block
}

type RsaCipher struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
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
	TLS_CIPHER_SUITE_SSL_NULL_WITH_NULL_NULL            TLSCipherSuite = 0x0000
	TLS_CIPHER_SUITE_SSL_RSA_WITH_NULL_MD5              TLSCipherSuite = 0x0001
	TLS_CIPHER_SUITE_SSL_RSA_WITH_NULL_SHA              TLSCipherSuite = 0x0002
	TLS_CIPHER_SUITE_SSL_RSA_EXPORT_WITH_RC4_40_MD5     TLSCipherSuite = 0x0003
	TLS_CIPHER_SUITE_SSL_RSA_WITH_RC4_128_MD5           TLSCipherSuite = 0x0004
	TLS_CIPHER_SUITE_SSL_RSA_WITH_RC4_128_SHA           TLSCipherSuite = 0x0005
	TLS_CIPHER_SUITE_SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5 TLSCipherSuite = 0x0006
	TLS_CIPHER_SUITE_SSL_RSA_WITH_IDEA_CBC_SHA          TLSCipherSuite = 0x0007
	TLS_CIPHER_SUITE_SSL_RSA_EXPORT_WITH_DES40_CBC_SHA  TLSCipherSuite = 0x0008
	TLS_CIPHER_SUITE_SSL_RSA_WITH_DES_CBC_SHA           TLSCipherSuite = 0x0009
	TLS_CIPHER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA      TLSCipherSuite = 0x000A
	//Following cipher suite definition requires that server provide an rsa certificat ethat can be used for key exchange.
	TLS_CIPHER_SUITE_SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA  TLSCipherSuite = 0x000B
	TLS_CIPHER_SUITE_SSL_DH_DSS_WITH_DES_CBC_SHA           TLSCipherSuite = 0x000C
	TLS_CIPHER_SUITE_SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA      TLSCipherSuite = 0x000D
	TLS_CIPHER_SUITE_SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA  TLSCipherSuite = 0x000E
	TLS_CIPHER_SUITE_SSL_DH_RSA_WITH_DES_CBC_SHA           TLSCipherSuite = 0x000F
	TLS_CIPHER_SUITE_SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA      TLSCipherSuite = 0x0010
	TLS_CIPHER_SUITE_SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA TLSCipherSuite = 0x0011
	TLS_CIPHER_SUITE_SSL_DHE_DSS_WITH_DES_CBC_SHA          TLSCipherSuite = 0x0012
	TLS_CIPHER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA     TLSCipherSuite = 0x0013
	TLS_CIPHER_SUITE_SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA TLSCipherSuite = 0x0014
	TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_DES_CBC_SHA          TLSCipherSuite = 0x0015
	TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA     TLSCipherSuite = 0x0016
	// Folowing cipher suited are used for server-authenticated (optianlly client) diffie-hellman. Dh denotes cipher suited in which the server-s certificate contains dh paramters signed by the  certificate authority.
	// dhe denothes ephemral diffie-hellman where dh paramters are signed by dss or rsa cerificate, which has been signed by ca. The sigin algorithm used in specified after the dh or dhepparamter.
	// In all case  the clie must have the same type of cerificate, and must use the dh paramters chosen by the server

	TLS_CIPHER_SUITE_SSL_DH_anon_EXPORT_WITH_RC4_40_MD5    TLSCipherSuite = 0x0017
	TLS_CIPHER_SUITE_SSL_DH_anon_WITH_RC4_128_MD5          TLSCipherSuite = 0x0018
	TLS_CIPHER_SUITE_SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA TLSCipherSuite = 0x0019
	TLS_CIPHER_SUITE_SSL_DH_anon_WITH_DES_CBC_SHA          TLSCipherSuite = 0x001A
	TLS_CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA     TLSCipherSuite = 0x001B
	// The following cipher suited are used for completely anonymous diffie hellman in which neither party is authenticated. Note thi is extremly vuluberable to man in the middle attackers, so its strongly discouraged to use it.
	TLS_CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_NULL_SHA         TLSCipherSuite = 0x001C
	TLS_CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA TLSCipherSuite = 0x001D
	TLS_CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA      TLSCipherSuite = 0x001E
	// fortezza tokens used in the highly secure env such as goverment
	//
)

// Export Ciphers: These ciphers were created to comply with U.S. regulations. As a result, export ciphers used reduced-strength encryption (e.g., 40-bit DES) and short (512-bit) RSA keys.

var CIPHER_SUITE_NAME = map[TLSCipherSuite]string{
	TLS_CIPHER_SUITE_SSL_NULL_WITH_NULL_NULL:            "NULL_WITH_NULL_NULL",
	TLS_CIPHER_SUITE_SSL_RSA_WITH_NULL_MD5:              "RSA_WITH_NULL_MD5",
	TLS_CIPHER_SUITE_SSL_RSA_WITH_NULL_SHA:              "RSA_WITH_NULL_SHA",
	TLS_CIPHER_SUITE_SSL_RSA_EXPORT_WITH_RC4_40_MD5:     "RSA_EXPORT_WITH_RC4_40_MD5",
	TLS_CIPHER_SUITE_SSL_RSA_WITH_RC4_128_MD5:           "RSA_WITH_RC4_128_MD5",
	TLS_CIPHER_SUITE_SSL_RSA_WITH_RC4_128_SHA:           "RSA_WITH_RC4_128_SHA",
	TLS_CIPHER_SUITE_SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5: "RSA_EXPORT_WITH_RC2_CBC_40_MD5",
	TLS_CIPHER_SUITE_SSL_RSA_WITH_IDEA_CBC_SHA:          "RSA_WITH_IDEA_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_RSA_EXPORT_WITH_DES40_CBC_SHA:  "RSA_EXPORT_WITH_DES40_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_RSA_WITH_DES_CBC_SHA:           "RSA_WITH_DES_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA:      "RSA_WITH_3DES_EDE_CBC_SHA",
	//Following cipher suite definition requires that server provide an rsa certificat ethat can be used for key exchange.
	TLS_CIPHER_SUITE_SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA:  "DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_DH_DSS_WITH_DES_CBC_SHA:           "DH_DSS_WITH_DES_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA:      "DH_DSS_WITH_3DES_EDE_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA:  "DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_DH_RSA_WITH_DES_CBC_SHA:           "DH_RSA_WITH_DES_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA:      "DH_RSA_WITH_3DES_EDE_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA: "DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_DHE_DSS_WITH_DES_CBC_SHA:          "DHE_DSS_WITH_DES_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA:     "DHE_DSS_WITH_3DES_EDE_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA: "DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_DES_CBC_SHA:          "DHE_RSA_WITH_DES_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA:     "DHE_RSA_WITH_3DES_EDE_CBC_SHA",
	// Folowing cipher suited are used for server-authenticated (optianlly client) diffie-hellman. Dh denotes cipher suited in which the server-s certificate contains dh paramters signed by the  certificate authority.
	// dhe denothes ephemral diffie-hellman where dh paramters are signed by dss or rsa cerificate, which has been signed by ca. The sigin algorithm used in specified after the dh or dhepparamter.
	// In all case  the clie must have the same type of cerificate, and must use the dh paramters chosen by the server

	TLS_CIPHER_SUITE_SSL_DH_anon_EXPORT_WITH_RC4_40_MD5:    "DH_anon_EXPORT_WITH_RC4_40_MD5",
	TLS_CIPHER_SUITE_SSL_DH_anon_WITH_RC4_128_MD5:          "DH_anon_WITH_RC4_128_MD5",
	TLS_CIPHER_SUITE_SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA: "DH_anon_EXPORT_WITH_DES40_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_DH_anon_WITH_DES_CBC_SHA:          "DH_anon_WITH_DES_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA:     "DH_anon_WITH_3DES_EDE_CBC_SHA",
	// The following cipher suited are used for completely anonymous diffie hellman in which neither party is authenticated. Note thi is extremly vuluberable to man in the middle attackers, so its strongly discouraged to use it.
	TLS_CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_NULL_SHA:         "FORTEZZA_KEA_WITH_NULL_SHA",
	TLS_CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA: "FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA",
	TLS_CIPHER_SUITE_SSL_FORTEZZA_KEA_WITH_RC4_128_SHA:      "FORTEZZA_KEA_WITH_RC4_128_SHA",
}
