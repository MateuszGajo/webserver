package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"handshakeServer/handshake"
	"os"
	"os/signal"
)

type params struct {
	version handshake.Version
	cert    *handshake.HttpServerCertParam
}

func loadParams() params {
	// TODO: implement this
	cert := flag.String("cert", "", "Server certificate")
	key := flag.String("key", "", "Cert private key")
	ssl3Version := flag.Bool("ssl3", false, "ssl 3.0")
	tls10Version := flag.Bool("tls1", false, "tls 1.0")
	tls11Version := flag.Bool("tls1_1", false, "tls 1.1")
	tls12Version := flag.Bool("tls1_2", false, "tls 1.2")
	flag.Parse()

	var certParam *handshake.HttpServerCertParam
	pwd, err := os.Getwd()
	if *cert == "" || *key == "" {
		certParam = nil
	} else {
		certParam = &handshake.HttpServerCertParam{
			CertPath: pwd + *cert,
			KeyPath:  pwd + *key,
		}
	}

	var version handshake.Version
	if *tls12Version {
		fmt.Println("tls 1.2")
		version = handshake.TLS12Version
	}else if *tls11Version {
		fmt.Println("tls 1.1")
		version = handshake.TLS11Version
	} else if *tls10Version {
		fmt.Println("tls 1.0")
		version = handshake.TLS10Version
	} else if *ssl3Version {
		version = handshake.SSL30Version
	} else {
		version = handshake.TLS10Version
	}

	if err != nil {
		fmt.Printf("\n cannot get root path, err:%v", err)
		os.Exit(1)
	}

	return params{
		cert:    certParam,
		version: version,
	}
}

func main() {
	params := loadParams()
	sslVersionBinary := make([]byte, 2)
	binary.BigEndian.PutUint16(sslVersionBinary, uint16(params.version))

	server, err := handshake.CreateServer(
		handshake.WithAddress("127.0.0.1", "4221"),
		handshake.WithCertificate(params.cert),
		handshake.WithSSLVersion(sslVersionBinary),
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
