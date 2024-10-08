package handshake

import (
	"encoding/binary"
	"fmt"
)

func (serverData *ServerData) Parser(clientHello []byte) (output [][]byte, rest []byte, err error) {

	for len(clientHello) > 0 {
		if len(clientHello) < 5 {
			rest = clientHello

			return output, rest, err
		}

		contentType := clientHello[0]
		if contentType < byte(TLSContentTypeChangeCipherSpec) || contentType > byte(TLSContentTypeApplicationData) {
			return output, rest, fmt.Errorf("invalid content type, content type: %v", contentType)
		}

		version := binary.BigEndian.Uint16(clientHello[1:3])
		// lets assume we only support ssl 3.0
		if version != binary.BigEndian.Uint16(serverData.SSLVersion) {
			return output, rest, fmt.Errorf("unsported ssl version, ssl 3.0 its the only supported")
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
