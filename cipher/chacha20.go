package cipher

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

func (cipherDef *CipherDef) encryptChacha20(data, writeKey, iv, seqNum, additionalData []byte) ([]byte, error) {

	aead, err := chacha20poly1305.New(writeKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create AEAD: %v", err)
	}

	SequenceNumberLength := 8
	perRecordNonce := make([]byte, cipherDef.Spec.IvSize)
	copy(perRecordNonce[cipherDef.Spec.IvSize-SequenceNumberLength:], seqNum)

	for i := 0; i < cipherDef.Spec.IvSize; i++ {
		perRecordNonce[i] ^= iv[i]
	}

	ciphertext := aead.Seal(nil, perRecordNonce, data, additionalData)

	fmt.Printf("Ciphertext: %x\n", ciphertext)

	return ciphertext, nil
}

func (cipherDef *CipherDef) decryptChacha20(data, writeKey, iv, seqNum, additionalData []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(writeKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to create AEAD: %v", err)
	}

	SequenceNumberLength := 8
	perRecordNonce := make([]byte, cipherDef.Spec.IvSize)
	copy(perRecordNonce[cipherDef.Spec.IvSize-SequenceNumberLength:], seqNum)

	for i := 0; i < cipherDef.Spec.IvSize; i++ {
		perRecordNonce[i] ^= iv[i]
	}

	decrypted, err := aead.Open(nil, perRecordNonce, data, additionalData)
	if err != nil {
		return nil, fmt.Errorf("Failed to decrypt: %v", err)
	}

	return decrypted, nil
}
