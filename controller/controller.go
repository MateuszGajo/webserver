package controller

import (
	"fmt"
	"net"
)

func HangleRootGet(conn net.Conn) {
	_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))

	if err != nil {
		fmt.Printf("problem returning response: %v", err)
	}
}
