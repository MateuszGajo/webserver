package server

import (
	"fmt"
	"net"
	. "webserver/http"
	. "webserver/parser"
)

func RunServer(address, port string) {
	listener, err := net.Listen("tcp", fmt.Sprintf("%v:%v", address, port))

	if err != nil {
		fmt.Printf("cannt listen to port 4221: %v", err)
	}

	for {

		conn, err := listener.Accept()

		if err != nil {
			fmt.Printf("cannot accept connection: %v", err)
			conn.Close()
			continue
		}

		handleConnection(conn)
	}

}

func handleConnection(conn net.Conn) {
	defer func(conn net.Conn) {
		err := conn.Close()

		if err != nil {
			fmt.Printf("Problem with closing connectin, err: %v", err)
		}
	}(conn)

	buf := make([]byte, 2048)

	n, err := conn.Read(buf)

	if err != nil {
		fmt.Printf("problem reading data, %v", err)
	}

	msg := string(buf[:n])

	resp := ParseRequest(msg)

	RunHandler(resp.RequestLine.Path, resp.RequestLine.ReqType, conn)

}
