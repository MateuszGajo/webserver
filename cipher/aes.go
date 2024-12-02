package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)


func DecryptAES(key, iv, ciphertext []byte) ([]byte, error) {
	fmt.Println("phase one")
	fmt.Println("key")
	fmt.Println(key)
	block, err := aes.NewCipher(key)
	if err != nil { 
		return nil, err 
	}

	fmt.Println("phase two") 
	fmt.Println("ciphertext")
	fmt.Println(len(ciphertext))
	fmt.Println(ciphertext)
 
	
	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext should be multiplier of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	return decrypted, nil
}

func EncryptAES(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)

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

func DecryptAESMessage(encryptedData, writeKey, iv []byte) ([]byte, error) {
	encryptedMessage := encryptedData
	decodedMsg, err := DecryptAES(writeKey, iv, encryptedMessage)
	if err != nil {
		return nil, fmt.Errorf("problem decrypting data: %v", err)
	}
	fmt.Println("decoded msg", decodedMsg)

	decodedMsgWithoutPadding, err := removeCustomPadding(decodedMsg, len(encryptedData))
	if err != nil {

		return nil, fmt.Errorf("problem removing padding: %v", err)
	}

	return decodedMsgWithoutPadding, nil
}

func (cipherDef *CipherDef) EncryptAESMessage(data, writeKey, iv []byte) ([]byte, error) {
	padLength := roundUpToMultiple(len(data), aes.BlockSize)

	dataPadded := cipherDef.addPadding(data, padLength)

	encryptedMsg, err := EncryptAES(writeKey, iv, dataPadded)
	if err != nil {
		return nil, fmt.Errorf("problem Encrypting data: %v", err)
	}

	return encryptedMsg, nil
}

