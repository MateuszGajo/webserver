package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func DecryptAES(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

func CBCBlock(block cipher.Block, ciphertext, iv []byte) ([]byte, error) {

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext should be multiplier of block size")
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(encrypted, ciphertext)

	return encrypted, nil
}

func (cipherDef *CipherDef) GCMBlock(block cipher.Block, ciphertext, iv, sequenceNumber, additionalData []byte) ([]byte, error) {

	SequenceNumberLength := 8

	// Derive per-record nonce
	perRecordNonce := make([]byte, cipherDef.Spec.IvSize)
	copy(perRecordNonce[cipherDef.Spec.IvSize-SequenceNumberLength:], sequenceNumber) // Pad to ivLength

	for i := 0; i < cipherDef.Spec.IvSize; i++ {
		perRecordNonce[i] ^= iv[i]
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	encrypted := aesGCM.Seal(nil, perRecordNonce, ciphertext, additionalData)

	return encrypted, nil
}

func (cipherDef *CipherDef) EncryptAES(key, iv, ciphertext, seqNum, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)

	if err != nil {
		return nil, err
	}

	var encrypted []byte

	if cipherDef.Spec.EncryptionAlgorithmBlockMode == EncryptionAlgorithmBlockModeGCM {
		encrypted, err = cipherDef.GCMBlock(block, ciphertext, iv, seqNum, additionalData)
	} else {
		padLength := roundUpToMultiple(len(ciphertext), aes.BlockSize)

		dataPadded := cipherDef.addPadding(ciphertext, padLength)
		encrypted, err = CBCBlock(block, dataPadded, iv)
	}

	if err != nil {
		return nil, err
	}

	return encrypted, nil
}

func DecryptAESMessage(encryptedData, writeKey, iv []byte) ([]byte, error) {
	encryptedMessage := encryptedData
	decodedMsg, err := DecryptAES(writeKey, iv, encryptedMessage)
	if err != nil {
		return nil, fmt.Errorf("problem decrypting data: %v", err)
	}

	decodedMsgWithoutPadding, err := removeCustomPadding(decodedMsg, len(encryptedData))
	if err != nil {

		return nil, fmt.Errorf("problem removing padding: %v", err)
	}

	return decodedMsgWithoutPadding, nil
}

func (cipherDef *CipherDef) EncryptAESMessage(data, writeKey, iv, seqNum, additionalData []byte) ([]byte, error) {

	encryptedMsg, err := cipherDef.EncryptAES(writeKey, iv, data, seqNum, additionalData)
	if err != nil {
		return nil, fmt.Errorf("problem Encrypting data: %v", err)
	}

	return encryptedMsg, nil
}
