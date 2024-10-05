package cipher

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"os"
)

var PADDING_LENGTH = 8

func Decrypt3Des(key, iv, ciphertext []byte) ([]byte, error) {
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

func Encrypt3Des(key, iv, ciphertext []byte) ([]byte, error) {
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
	// This how openssl implemented this len of padding -1, https://crypto.stackexchange.com/questions/98917/on-the-correctness-of-the-padding-example-of-rfc-5246
	padtext = append(padtext, byte(paddingLen-1))
	return append(src, padtext...)
}

func removeCustomPadding(src []byte, blockSize int) ([]byte, error) {
	paddingLen := int(src[len(src)-1]) + 1 // openssl did it this way, len of padding -1

	if paddingLen < 1 || paddingLen > blockSize {
		return nil, fmt.Errorf("invalid padding length")
	}

	return src[:len(src)-paddingLen], nil
}

func Decrypt3DesMessage(encryptedData, writeKey, iv []byte) []byte {
	encryptedMessage := encryptedData
	decodedMsg, err := Decrypt3Des(writeKey, iv, encryptedMessage)
	if err != nil {
		fmt.Println("problem decrypting data")
		fmt.Println(err)
		os.Exit(1)
	}

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

func Encrypt3DesMessage(data, writeKey, iv []byte) []byte {
	// PADDING_LENGTH = BLOCK SIZE IN TRIPED DES IS 8 BYTES (64-bits)
	padLength := roundUpToMultiple(len(data), des.BlockSize)

	dataPadded := addCustomPadding(data, padLength)

	encryptedMsg, err := Encrypt3Des(writeKey, iv, dataPadded)
	if err != nil {
		fmt.Println("problem decrypting data")
		fmt.Println(err)
		os.Exit(1)
	}

	return encryptedMsg
}
