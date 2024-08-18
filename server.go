package main

import (
	"fmt"
	"net"
	"webserver/http"
)

func main() {
	// http.Cors("http://localhost:5501")

	// server := server.CreateServer()
	// server.RunServer()

	listener, err := net.Listen("tcp", "127.0.0.1:4221")

	if err != nil {
		fmt.Println("errr has occured trying while trying to connect")
		fmt.Println(err)
	}

	conn, err := listener.Accept()

	if err != nil {
		fmt.Println("errr has occured trying while trying to connect")
		fmt.Println(err)
	}

	if err != nil {
		fmt.Println("errr has occured trying while accepting connection")
		fmt.Println(err)
	}

	http.HandleConnection(conn)

}
