package cipher

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"os"
)

func Decrypt3DESCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)

	if err != nil {
		return nil, err
	}

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext should be multiplier of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	return decrypted, nil
}

func Encrypt3DESCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)

	if err != nil {
		return nil, err
	}

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext should be multiplier of block size")
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(encrypted, ciphertext)

	return encrypted, nil
}

func removeCustomPadding(src []byte, blockSize int) ([]byte, error) {
	paddingLen := int(src[len(src)-1]) + 1 // openssl did it this way, len of padding is -1

	fmt.Println("padding len")
	fmt.Println(paddingLen)

	if paddingLen < 1 || paddingLen > blockSize {
		return nil, fmt.Errorf("invalid padding length")
	}

	// for i := 0; i < paddingLen-1; i++ {
	// 	if src[len(src)-paddingLen+i] != 0 {
	// 		return nil, fmt.Errorf("invalid padding byte")
	// 	}
	// }

	return src[:len(src)-paddingLen], nil
}

func DecryptDesMessage(recordLayerData, encryptedData, writeKey, iv []byte) []byte {
	encryptedMessage := encryptedData

	fmt.Println("IV")
	for _, v := range iv {
		fmt.Printf(" %02X", v)
	}

	decodedMsg, err := Decrypt3DESCBC(writeKey, iv, encryptedMessage)
	if err != nil {
		fmt.Println("problem decrypting data")
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("encrypted data")
	fmt.Println(decodedMsg)

	fmt.Printf("\n encrypted data len: %v \n", len(decodedMsg))
	decodedMsgWithoutPadding, err := removeCustomPadding(decodedMsg, len(encryptedData))
	if err != nil {
		fmt.Println("problem removing padding")
		fmt.Println(err)
		os.Exit(1)
	}
	decryptedClientHello := []byte{}
	decryptedClientHello = append(decryptedClientHello, recordLayerData...)
	decryptedClientHello = append(decryptedClientHello, decodedMsgWithoutPadding...)

	return decryptedClientHello
}
