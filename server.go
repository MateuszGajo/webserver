package main

import (
	"flag"
	"fmt"
	"handshakeServer/handshake"
	"os"
	"os/signal"
)

func loadParams() *handshake.HttpServerCertParam {
	cert := flag.String("cert", "", "Server certificate")
	key := flag.String("key", "", "Cert private key")
	flag.Parse()

	if *cert == "" || *key == "" {
		return nil
	}
	pwd, err := os.Getwd()

	if err != nil {
		fmt.Printf("\n cannot get root path, err:%v", err)
		os.Exit(1)
	}

	return &handshake.HttpServerCertParam{
		CertPath: pwd + *cert,
		KeyPath:  pwd + *key,
	}
}

func main() {
	certParams := loadParams()

	server, err := handshake.CreateServer(
		handshake.WithAddress("127.0.0.1", "4221"),
		handshake.WithCertificate(certParams),
	)

	if err != nil {
		fmt.Printf("\n couldnt create server listener, err: %v", err)
		os.Exit(1)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	server.CloseHttpServer()

}
