package main

import (
	"fmt"
	"math/big"
	"net"
	"webserver/http"
)

type ServerData struct {
	isEncrypted      bool
	p                *big.Int
	q                *big.Int
	private          *big.Int
	public           *big.Int
	shared           *big.Int
	clientRandom     []byte
	serverRandom     []byte
	allMessagesShort [][]byte
	masterKey        []byte
	macClient        []byte
	macServer        []byte
	writeKeyClient   []byte
	writeKeyServer   []byte
	IVClient         []byte
	IVServer         []byte
	seqNum           int
}

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
