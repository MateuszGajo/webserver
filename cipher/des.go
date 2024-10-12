package cipher

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

var PADDING_LENGTH = 8

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

func roundUpToMultiple(length, multiple int) int {
	if length%multiple == 0 {
		return length + multiple
	}
	return ((length / multiple) + 1) * multiple
}

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

func Decrypt3DesMessage(encryptedData, writeKey, iv []byte) ([]byte, error) {
	encryptedMessage := encryptedData
	decodedMsg, err := Decrypt3Des(writeKey, iv, encryptedMessage)
	if err != nil {
		return nil, fmt.Errorf("problem decrypting data: %v", err)
	}

	decodedMsgWithoutPadding, err := removeCustomPadding(decodedMsg, len(encryptedData))
	if err != nil {

		return nil, fmt.Errorf("problem removing padding: %v", err)
	}

	return decodedMsgWithoutPadding, nil
}

func Encrypt3DesMessage(data, writeKey, iv []byte) ([]byte, error) {
	padLength := roundUpToMultiple(len(data), des.BlockSize)

	dataPadded := addCustomPadding(data, padLength)

	encryptedMsg, err := Encrypt3Des(writeKey, iv, dataPadded)
	if err != nil {
		return nil, fmt.Errorf("problem Encrypting data: %v", err)
	}

	return encryptedMsg, nil
}

func DecryptDes(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := des.NewCipher(key)

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

func EncryptDes(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := des.NewCipher(key)

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

func DecryptDesMessage(encryptedData, writeKey, iv []byte) ([]byte, error) {
	encryptedMessage := encryptedData
	decodedMsg, err := DecryptDes(writeKey, iv, encryptedMessage)

	if err != nil {
		return nil, fmt.Errorf("Problem decrypting data: %v", err)
	}

	decodedMsgWithoutPadding, err := removeCustomPadding(decodedMsg, len(encryptedData))
	if err != nil {
		return nil, fmt.Errorf("Problem removing padding: %v", err)
	}

	return decodedMsgWithoutPadding, nil
}

func EncryptDesMessage(data, writeKey, iv []byte) ([]byte, error) {
	padLength := roundUpToMultiple(len(data), des.BlockSize)

	dataPadded := addCustomPadding(data, padLength)

	encryptedMsg, err := EncryptDes(writeKey, iv, dataPadded)
	if err != nil {
		return nil, fmt.Errorf("Problem ecrypting data: %v", err)
	}

	return encryptedMsg, nil
}
