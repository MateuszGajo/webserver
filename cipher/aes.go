package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func (cipherDef *CipherDef) DecryptAES(key, iv, ciphertext, seqNum, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var decodedMsg []byte

	if cipherDef.Spec.EncryptionAlgorithmBlockMode == EncryptionAlgorithmBlockModeGCM {
		decodedMsg, err = cipherDef.DecryptGCMBlock(block, ciphertext, iv, seqNum, additionalData)
	} else {
		decoded, err := cipherDef.DecryptCBCBlock(block, ciphertext, iv)

		if err != nil {
			return nil, err
		}

		decodedMsg, err = removeCustomPadding(decoded, len(decoded))
		if err != nil {

			return nil, fmt.Errorf("problem removing padding: %v", err)
		}
	}

	return decodedMsg, err

}

func (cipherDef *CipherDef) DecryptCBCBlock(block cipher.Block, ciphertext, iv []byte) ([]byte, error) {

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("ciphertext should be multiplier of block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	return decrypted, nil
}

func (cipherDef *CipherDef) DecryptGCMBlock(block cipher.Block, ciphertext, iv, sequenceNumber, additionalData []byte) ([]byte, error) {

	SequenceNumberLength := 8

	perRecordNonce := make([]byte, cipherDef.Spec.IvSize)
	copy(perRecordNonce[cipherDef.Spec.IvSize-SequenceNumberLength:], sequenceNumber) // Pad to ivLength

	for i := 0; i < cipherDef.Spec.IvSize; i++ {
		perRecordNonce[i] ^= iv[i]
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	encrypted, err := aesGCM.Open(nil, perRecordNonce, ciphertext, additionalData)

	return encrypted, err
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

func (cipherDef *CipherDef) DecryptAESMessage(encryptedData, writeKey, iv, seqNum, additionalData []byte) ([]byte, error) {
	encryptedMessage := encryptedData
	decodedMsg, err := cipherDef.DecryptAES(writeKey, iv, encryptedMessage, seqNum, additionalData)
	if err != nil {
		return nil, fmt.Errorf("problem decrypting data: %v", err)
	}

	return decodedMsg, nil
}

func (cipherDef *CipherDef) EncryptAESMessage(data, writeKey, iv, seqNum, additionalData []byte) ([]byte, error) {

	encryptedMsg, err := cipherDef.EncryptAES(writeKey, iv, data, seqNum, additionalData)
	if err != nil {
		return nil, fmt.Errorf("problem Encrypting data: %v", err)
	}

	return encryptedMsg, nil
}
