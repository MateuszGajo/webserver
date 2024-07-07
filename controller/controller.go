package controller

import (
	"fmt"
	"net"
)

func HangleRootGet(conn net.Conn) {
	_, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\nContent-Length: 4\r\nAccess-Control-Allow-Origin: http://localhost:5500\r\n\r\nabcd"))

	if err != nil {
		fmt.Printf("problem returning response: %v", err)
	}
}
