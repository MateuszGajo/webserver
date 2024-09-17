package cipher

import (
	"crypto/dsa"
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
	KeyExchangeMethodDHE KeyExchangeMethod = "dhe"
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
	HashSize            int
	KeyMaterial         int
	IvSize              int
	HashAlgorithm       HashAlgorithm
	KeyExchange         KeyExchangeMethod
	EncryptionAlgorithm EncryptionAlgorithm
	SignatureAlgorithm  SignatureAlgorithm
}

type CipherDef struct {
	Keys              CipherKeys
	Spec              CipherSpec
	CipherSuite       uint16
	CompressionMethod byte
	DhParams          DhParams
	rsa               RsaCipher
	dsa               DsaCipher
}

type RsaCipher struct {
	privateKey rsa.PrivateKey
}

type DsaCipher struct {
	privateKey dsa.PrivateKey
}

type DhParams struct {
	P            *big.Int
	Q            *big.Int
	Private      *big.Int
	Public       *big.Int
	ClientPublic *big.Int
}

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
