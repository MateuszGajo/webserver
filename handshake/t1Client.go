package handshake

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"handshakeServer/cipher"
	"handshakeServer/helpers"
	"hash"
)

func (serverData *ServerData) T1GenerateFinishedHandshakeMac(label []byte, handshakeMessages [][]byte) []byte {
	// TODO: tls 1.0 implement this
	// Legacy thing with fixed number of 48 bytes
	allHandskaedMessageCombined := []byte{}

	for _, v := range handshakeMessages {
		allHandskaedMessageCombined = append(allHandskaedMessageCombined, v...)
	}

	md5 := md5.New()
	sha := sha1.New()

	md5.Write(allHandskaedMessageCombined)
	sha.Write(allHandskaedMessageCombined)
	md5Hash := md5.Sum(nil)
	shaHash := sha.Sum(nil)

	seed := label
	seed = append(seed, md5Hash...)
	seed = append(seed, shaHash...)

	verifyData := T1Prf(serverData.MasterKey, seed, 12)

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

func pHash(hash func() hash.Hash, secret, seed []byte, length int) []byte {
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

func T1Prf(secret, seed []byte, req_len int) []byte {
	secretHalfLength := (len(secret) + 1) / 2
	firstHalfSecret := secret[:secretHalfLength]
	if len(secret)%2 == 1 {
		secretHalfLength--
	}
	secondHalfSecret := secret[secretHalfLength:]

	md5Hash := pHash(md5.New, firstHalfSecret, seed, req_len)
	shaHash := pHash(sha1.New, secondHalfSecret, seed, req_len)

	for i := range md5Hash[:req_len] {
		md5Hash[i] ^= shaHash[i]
	}

	return md5Hash[:req_len]
}

func (serverData *ServerData) T1GenerateStreamCipher(dataCompressedType, sslCompressData []byte, seqNum, mac []byte) []byte {
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
