package helpers

import (
	"encoding/binary"
	"fmt"
)

func IntTo3BytesBigEndian(n int) ([]byte, error) {
	// Ensure the integer fits within 3 bytes
	if n < 0 || n > 16777215 {
		return nil, fmt.Errorf("integer out of range for 3 bytes")
	}

	// Create a byte slice of length 3
	bytes := make([]byte, 3)

	// Assign the bytes in big-endian order
	bytes[0] = byte((n >> 16) & 0xFF)
	bytes[1] = byte((n >> 8) & 0xFF)
	bytes[2] = byte(n & 0xFF)

	return bytes, nil
}

func Int32ToBigEndian(val int) []byte {
	bytes := make([]byte, 2)
	unit16value := uint16(val)

	binary.BigEndian.PutUint16(bytes, unit16value)

	return bytes
}

func Int64ToBIgEndian(val int64) []byte {
	bytes := make([]byte, 4)
	unit16value := uint32(val)

	binary.BigEndian.PutUint32(bytes, unit16value)

	return bytes
}
