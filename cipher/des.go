package cipher

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"os"
)

var PADDING_LENGTH = 8

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

func addCustomPadding(src []byte, blockSize int) []byte {
	paddingLen := blockSize - len(src)%blockSize

	padtext := bytes.Repeat([]byte{0}, paddingLen-1)
	// This how openssl implemented this len -1, https://crypto.stackexchange.com/questions/98917/on-the-correctness-of-the-padding-example-of-rfc-5246
	padtext = append(padtext, byte(paddingLen-1))
	return append(src, padtext...)
}

func removeCustomPadding(src []byte, blockSize int) ([]byte, error) {
	paddingLen := int(src[len(src)-1]) + 1 // openssl did it this way, len of padding is -1

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

func DecryptDesMessage(encryptedData, writeKey, iv []byte) []byte {
	encryptedMessage := encryptedData
	fmt.Println("decrypted data?")
	fmt.Println(encryptedData)

	decodedMsg, err := Decrypt3DESCBC(writeKey, iv, encryptedMessage)
	if err != nil {
		fmt.Println("problem decrypting data")
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("decoded msg")
	fmt.Println(decodedMsg)
	fmt.Println(len(decodedMsg))

	decodedMsgWithoutPadding, err := removeCustomPadding(decodedMsg, len(encryptedData))
	if err != nil {
		fmt.Println("problem removing padding")
		fmt.Println(err)
		os.Exit(1)
	}

	return decodedMsgWithoutPadding
}

func roundUpToMultiple(length, multiple int) int {
	if length%multiple == 0 {
		return length + multiple
	}
	return ((length / multiple) + 1) * multiple
}

func EncryptDesMessage(data, writeKey, iv []byte) []byte {
	padLength := roundUpToMultiple(len(data), PADDING_LENGTH)

	dataPadded := addCustomPadding(data, padLength)

	encryptedMsg, err := Encrypt3DESCBC(writeKey, iv, dataPadded)
	if err != nil {
		fmt.Println("problem decrypting data")
		fmt.Println(err)
		os.Exit(1)
	}

	return encryptedMsg
}
