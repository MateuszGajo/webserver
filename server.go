package main

import (
	"fmt"
	"net"
)

func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:4221")

	if err != nil {
		fmt.Printf("cannt listen to port 4221: %v", err)
	}

	conn, err := listener.Accept()

	if err != nil {
		fmt.Printf("cannot accept connection: %v", err)
	}

	_, err = conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))

	if err != nil {
		fmt.Printf("problem returning response: %v", err)
	}
}
