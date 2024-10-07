package cipher

import (
	"crypto/rc4"
	"fmt"
	"os"
)

func (cipherDef *CipherDef) EncryptRC(data, key []byte) []byte {
	var err error
	if cipherDef.Rc4.EncryptCipher == nil {
		cipherDef.Rc4.EncryptCipher, err = rc4.NewCipher(key)
	}

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	encryptedText := make([]byte, len(data))
	cipherDef.Rc4.EncryptCipher.XORKeyStream(encryptedText, data)

	return encryptedText
}

func (cipherDef *CipherDef) DecryptRC(data, key []byte) []byte {
	var err error
	if cipherDef.Rc4.DecryptCipher == nil {
		cipherDef.Rc4.DecryptCipher, err = rc4.NewCipher(key)
	}

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	decrypted := make([]byte, len(data))

	cipherDef.Rc4.DecryptCipher.XORKeyStream(decrypted, data)

	return decrypted
}
