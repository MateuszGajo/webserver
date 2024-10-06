package cipher

import "crypto/rc4"

func EncryptRC(key, data []byte) ([]byte, error) {
	rcCipher, err := rc4.NewCipher(key)

	if err != nil {
		return []byte{}, err
	}

	encryptedText := []byte{}

	rcCipher.XORKeyStream(encryptedText, data)

	return encryptedText, nil
}
