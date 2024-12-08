package helpers

import "crypto/rand"

func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes) // Fill bytes with random data
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
