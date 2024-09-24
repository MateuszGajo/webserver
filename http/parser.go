package http

import (
	"encoding/binary"
	"errors"
	"fmt"
)

func Parser(clientHello []byte) (output [][]byte, rest []byte, err error) {
	// validate content typ
	// validate ssl version
	// validate if length is good

	for len(clientHello) > 0 {
		if len(clientHello) < 5 {
			rest = clientHello

			return output, rest, err
		}

		contentType := clientHello[0]
		if contentType < byte(TLSContentTypeChangeCipherSpec) || contentType > byte(TLSContentTypeApplicationData) {
			// TODO send alert here
			fmt.Println(clientHello)
			err = errors.New("invalid content type")
			return output, rest, err
		}

		version := binary.BigEndian.Uint16(clientHello[1:3])
		// lets assume we only support ssl 3.0
		if version != 0x0300 {
			err = errors.New("unsported ssl version, ssl 3.0 its the only supported")
			return output, rest, err
		}
		length := binary.BigEndian.Uint16(clientHello[3:5])

		if len(clientHello) < 5+int(length) {
			return output, clientHello, err
		}

		output = append(output, clientHello[:5+length])

		clientHello = clientHello[5+length:]

	}

	return output, rest, err

}
