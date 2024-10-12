package cipher

import (
	"crypto/rc4"
	"fmt"
)

func (cipherDef *CipherDef) EncryptRC4(data, key []byte) ([]byte, error) {
	var err error
	if cipherDef.Rc4.EncryptCipher == nil {
		cipherDef.Rc4.EncryptCipher, err = rc4.NewCipher(key)
	}

	if err != nil {
		return nil, fmt.Errorf("problem encrypting data: %v", err)
	}

	encryptedText := make([]byte, len(data))
	cipherDef.Rc4.EncryptCipher.XORKeyStream(encryptedText, data)

	return encryptedText, nil
}

func (cipherDef *CipherDef) DecryptRC4(data, key []byte) ([]byte, error) {
	var err error
	if cipherDef.Rc4.DecryptCipher == nil {
		cipherDef.Rc4.DecryptCipher, err = rc4.NewCipher(key)
	}

	if err != nil {
		return nil, fmt.Errorf("problem decrypting data: %v", err)
	}

	decrypted := make([]byte, len(data))

	cipherDef.Rc4.DecryptCipher.XORKeyStream(decrypted, data)

	return decrypted, nil
}
