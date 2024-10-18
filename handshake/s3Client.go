package handshake

import (
	"crypto/md5"
	"crypto/sha1"
	"handshakeServer/cipher"
	"handshakeServer/helpers"
	"hash"
)

func (serverData *ServerData) S3GenerateFinishedHandshakeMac(hashingAlgorithm hash.Hash, sender []byte, handshakeMessages [][]byte) []byte {
	n := hashingAlgorithm.Size()
	// Legacy thing with fixed number of 48 bytes
	npad := (48 / n) * n

	pad1Arr := pad1[:npad]
	pad2Arr := pad2[:npad]

	allHandskaedMessageCombined := []byte{}

	for _, v := range handshakeMessages {
		allHandskaedMessageCombined = append(allHandskaedMessageCombined, v...)
	}

	hashingAlgorithm.Write(allHandskaedMessageCombined)
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
	var hashFunc hash.Hash

	switch serverData.CipherDef.Spec.HashAlgorithm {
	case cipher.HashAlgorithmMD5:
		nPad = 48
		hashFunc = md5.New()
	case cipher.HashAlgorithmSHA:
		nPad = 40
		hashFunc = sha1.New()
	default:
		panic("wrong algorithm used can't use: " + serverData.CipherDef.Spec.HashAlgorithm)
	}

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
