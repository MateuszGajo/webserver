package handshake

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"handshakeServer/cipher"
	"handshakeServer/helpers"
)

func (serverData *ServerData) T12GetServerKeyExchangeMessage() ([]byte, error) {

	keyExchangeParams, err := serverData.CipherDef.GenerateServerKeyExchange()
	if err != nil {
		return nil, err
	}

	hash := []byte{}

	var hashAlgorithm = sha1.New()

	switch serverData.CipherDef.Spec.ExtHashAlgorithmIdentifier {
	case cipher.HashAlgorithmNumberNone:
		return nil, fmt.Errorf("key exchange should be hashed, we got value none hash algorithm")
	case cipher.HashAlgorithmNumberMd5:
		hashAlgorithm = md5.New()
	case cipher.HashAlgorithmNumberSha1:
		hashAlgorithm = sha1.New()
	case cipher.HashAlgorithmNumberSha224:
		hashAlgorithm = sha256.New224()
	case cipher.HashAlgorithmNumberSha256:
		hashAlgorithm = sha256.New()
	case cipher.HashAlgorithmNumberSha384:
		hashAlgorithm = sha512.New384()
	case cipher.HashAlgorithmNumberSha512:
		hashAlgorithm = sha512.New()
	default:
		return nil, fmt.Errorf("hash algorithm not implemented in keyExchange, trying to use: %v", serverData.CipherDef.Spec.ExtHashAlgorithmIdentifier)
	}
	switch serverData.CipherDef.Spec.SignatureAlgorithm {
	case cipher.SignatureAlgorithmAnonymous:
	case cipher.SignatureAlgorithmRSA, cipher.SignatureAlgorithmDSA:
		hash = signatureHash(hashAlgorithm, serverData.ClientRandom, serverData.ServerRandom, keyExchangeParams)
	default:
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
		return nil, fmt.Errorf("unsupported Algorithm: %v", serverData.CipherDef.Spec.SignatureAlgorithm)
	}

	signedParams, err := serverData.CipherDef.SignData(hash)
	signatureLength := helpers.Int32ToBigEndian(len(signedParams))

	if err != nil {
		serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionInternalError)
		return nil, fmt.Errorf("problem with singin data, err: %v", err)
	}

	keyExchangeData := []byte{}
	keyExchangeData = append(keyExchangeData, keyExchangeParams...)

	if len(signedParams) > 0 {
		keyExchangeData = append(keyExchangeData, byte(serverData.CipherDef.Spec.ExtHashAlgorithmIdentifier))
		keyExchangeData = append(keyExchangeData, byte(serverData.CipherDef.Spec.ExtSignatureAlgorithmIdentifier))

		keyExchangeData = append(keyExchangeData, signatureLength...)
		keyExchangeData = append(keyExchangeData, signedParams...)
	}

	return keyExchangeData, nil
}

func (serverData *ServerData) T12GenerateFinishedHandshakeMac(label []byte, handshakeMessages []byte) []byte {
	// TODO: tls 1.0 implement this
	// Legacy thing with fixed number of 48 bytes

	// In previous versions of TLS, the verify_data was always 12 octets
	// long.  In the current version of TLS, it depends on the cipher
	// suite.  Any cipher suite which does not explicitly specify
	// verify_data_length has a verify_data_length equal to 12.  This
	// includes all existing cipher suites.  Note that this
	// representation has the same encoding as with previous versions.
	// Future cipher suites MAY specify other lengths but such length
	// MUST be at least 12 bytes.
	defaultVerifyDataLength := 12
	// RFC 5246
	//Hash denotes a Hash of the handshake messages.  For the PRF
	//defined in Section 5, the Hash MUST be the Hash used as the basis
	//for the PRF.  Any cipher suite which defines a different PRF MUST
	//also define the Hash to use in the Finished computation.
	//   -  The MD5/SHA-1 combination in the pseudorandom function (PRF) has
	//been replaced with cipher-suite-specified PRFs.  All cipher suites
	//in this document use P_SHA256.

	// TODO: Verify it but it looks like i can hardcode sha256 for tls 1.2? Maybe if cipher uses >sha256 i need to use it stronger algorithm

	sha256Func := sha256.New()

	sha256Func.Write(handshakeMessages)
	sha256Hash := sha256Func.Sum(nil)

	seed := label
	seed = append(seed, sha256Hash...)

	verifyData := T12Prf(serverData.MasterKey, seed, defaultVerifyDataLength)

	return verifyData
}

// HMAC is a MAC based on cryptografic hash function, with stronger security compared to tradtional mac
// Hmac is resitent against length-exetention attack which can be used to forge valid mac
// MAC(message) = hash(key || message) - will reveal information about internal state, if attacker knows about original message and the resulting hash they can use length extenstion attack
// msg := "attack at down"
// secret = "secret"
// mac = sha(key || msg)
// Since the attacker can predict the padding and knows the intermediate hash state, they can compute:
// new_MAC = SHA-1(intermediate_state || ", let's retreat" || new_padding)
// In HMAC the inner hash by itself would be vulnerable to a length-extension attack and the attacker could successfully calculate a valid inner hash digest without access to the key. However, the outer hash isn't vulnerable to a length-extension attack since the client performing the HMAC authentication is only going to input the fixed length string key || inner_hash into it. The attacker only controls variable-length input to the inner hash, not the outer hash.
// The role of inner function is to provider collision-resistance (to compress a long message down to a short fingerprint, in a way so that someone who does not know the key cannot find a paira of messages with the same fingeprint)
// Why xor? Two differents keys could in some cases producte the same internal state when hashed with the message, leading to a mac collision, This is because concatenation does not ensure a unifoorm distrubtion of key bits across blocks.
// https://crypto.stackexchange.com/questions/12680/how-does-the-secret-key-in-an-hmac-prevent-modification-of-the-hmac

func T12PHash(hash func() hash.Hash, secret, seed []byte, length int) []byte {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)
	sum := []byte{}

	for {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		sum = append(sum, h.Sum(nil)...)

		if len(sum) >= length {
			return sum
		}

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
	// return sum
}

func T12Prf(secret, seed []byte, req_len int) []byte {

	return T12PHash(sha512.New384, secret, seed, req_len)[:req_len]

}

func (serverData *ServerData) T12GenerateStreamCipher(dataCompressedType, sslCompressData []byte, seqNum, mac []byte) []byte {
	// TODO: TLS1.0 verify this function now
	// 	stream-ciphered struct {
	// 		opaque content[SSLCompressed.length];
	// 		opaque MAC[CipherSpec.hash_size];
	// 	} GenericStreamCipher;

	// The MAC is generated as:

	// HMAC_hash(MAC_write_secret, seq_num + TLSCompressed.type +
	// 	TLSCompressed.version + TLSCompressed.length +
	// 	TLSCompressed.fragment));
	var hashFunc hash.Hash

	switch serverData.CipherDef.Spec.HashAlgorithm {
	case cipher.HashAlgorithmMD5:
		hashFunc = hmac.New(md5.New, mac)
	case cipher.HashAlgorithmSHA:
		hashFunc = hmac.New(sha1.New, mac)
	case cipher.HashAlgorithmSHA256:
		hashFunc = hmac.New(sha256.New, mac)
	default:
		panic("wrong algorithm used can't use: " + serverData.CipherDef.Spec.HashAlgorithm)
	}

	sslCompressLength := helpers.Int32ToBigEndian(len(sslCompressData))

	hashFunc.Write(seqNum)
	hashFunc.Write(dataCompressedType)
	hashFunc.Write(serverData.Version)
	hashFunc.Write(sslCompressLength)
	hashFunc.Write(sslCompressData)

	return hashFunc.Sum(nil)
}
