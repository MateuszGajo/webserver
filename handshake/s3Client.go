package handshake

import (
	"crypto/md5"
	"crypto/sha1"
	"fmt"
	"hash"

	"handshakeServer/cipher"
	"handshakeServer/helpers"
)

var pad1 = []byte{
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
	0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36}

// for sha
var pad2 = []byte{
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
	0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c}

func (serverData *ServerData) S3GetServerKeyExchangeMessage() ([]byte, error) {

	keyExchangeParams, err := serverData.CipherDef.GenerateServerKeyExchange()
	if err != nil {
		return nil, err
	}
	hash := []byte{}
	switch serverData.CipherDef.Spec.SignatureAlgorithm {
	case cipher.SignatureAlgorithmAnonymous:
	case cipher.SignatureAlgorithmRSA:
		md5Hash := signatureHash(md5.New(), serverData.ClientRandom, serverData.ServerRandom, keyExchangeParams)
		shaHash := signatureHash(sha1.New(), serverData.ClientRandom, serverData.ServerRandom, keyExchangeParams)
		hash = append(hash, md5Hash...)
		hash = append(hash, shaHash...)

	case cipher.SignatureAlgorithmDSA:

		shaHash := signatureHash(sha1.New(), serverData.ClientRandom, serverData.ServerRandom, keyExchangeParams)
		hash = append(hash, shaHash...)
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
	// SignatureAndHashAlgorithm, what the fuck, we have signature and hash algorithm, not not really specified, actually there is describe in 4.7.  Cryptographic Attributes :))))

	if len(signedParams) > 0 {

		keyExchangeData = append(keyExchangeData, signatureLength...)
		keyExchangeData = append(keyExchangeData, signedParams...)
	}

	return keyExchangeData, nil
}

func (serverData *ServerData) S3GenerateFinishedHandshakeMac(hashingAlgorithm hash.Hash, sender []byte, handshakeMessages []byte) []byte {
	n := hashingAlgorithm.Size()
	// Legacy thing with fixed number of 48 bytes
	npad := (48 / n) * n

	pad1Arr := pad1[:npad]
	pad2Arr := pad2[:npad]

	hashingAlgorithm.Write(handshakeMessages)
	hashingAlgorithm.Write(sender)
	hashingAlgorithm.Write(serverData.MasterKey)
	hashingAlgorithm.Write(pad1Arr)

	tmp := hashingAlgorithm.Sum(nil)
	hashingAlgorithm.Reset()

	hashingAlgorithm.Write(serverData.MasterKey)
	hashingAlgorithm.Write(pad2Arr)
	hashingAlgorithm.Write(tmp)

	return hashingAlgorithm.Sum(nil)
}

func s3_prf(secret, seed []byte, req_len int) []byte {
	hashSHA1 := sha1.New()
	hashMD5 := md5.New()
	result := []byte{}

	rounds := (req_len + hashMD5.Size() - 1) / hashMD5.Size()

	labelArr := [][]byte{{'A'}, {'B', 'B'}, {'C', 'C', 'C'}, {'D', 'D', 'D', 'D'}, {'E', 'E', 'E', 'E', 'E'}, {'F', 'F', 'F', 'F', 'F', 'F'}, {'G', 'G', 'G', 'G', 'G', 'G', 'G'}}

	for i := 0; i < rounds; i++ {
		label := labelArr[i]

		hashSHA1.Reset()
		hashSHA1.Write(label)
		hashSHA1.Write(secret)
		hashSHA1.Write(seed)
		digest := hashSHA1.Sum(nil)

		hashMD5.Reset()
		hashMD5.Write(secret)
		hashMD5.Write(digest)
		md5Digest := hashMD5.Sum(nil)

		result = append(result, md5Digest...)
	}

	return result
}

func (serverData *ServerData) S3generateStreamCipher(dataCompressedType, sslCompressData []byte, seqNum, mac []byte) []byte {
	// TODO: TLS1.0 verify this function now
	// 	stream-ciphered struct {
	// 		opaque content[SSLCompressed.length];
	// 		opaque MAC[CipherSpec.hash_size];
	// 	} GenericStreamCipher;

	// The MAC is generated as:

	// 	hash(MAC_write_secret + pad_2 +
	// 		 hash(MAC_write_secret + pad_1 + seq_num +
	// 			  SSLCompressed.type + SSLCompressed.length +
	// 			  SSLCompressed.fragment));
	var nPad int
	var hashFunc = serverData.CipherDef.Spec.HashAlgorithm()

	ssl3Pad1Sha := pad1[:nPad]
	ssl3Pad2Sha := pad2[:nPad]

	sslCompressLength := helpers.Int32ToBigEndian(len(sslCompressData))

	hashFunc.Write(mac)
	hashFunc.Write(ssl3Pad1Sha)
	hashFunc.Write(seqNum)
	hashFunc.Write(dataCompressedType)
	hashFunc.Write(sslCompressLength)
	hashFunc.Write(sslCompressData)

	tmp := hashFunc.Sum(nil)
	hashFunc.Reset()

	hashFunc.Write(mac)
	hashFunc.Write(ssl3Pad2Sha)
	hashFunc.Write(tmp)

	return hashFunc.Sum(nil)
}
