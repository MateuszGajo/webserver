package main

import (
	"flag"
	"fmt"
	"os"
	"sync"
	"webserver/global"
	"webserver/handshake"
)

func loadParams() *global.Params {
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

	return &global.Params{
		CertPath: pwd + *cert,
		KeyPath:  pwd + *key,
	}
}

func main() {
	// http.Cors("http://localhost:5501")

	// server := server.CreateServer()
	// server.RunServer()
	params := loadParams()

	var wg sync.WaitGroup
	wg.Add(1)

	server := global.Server{
		Wg: &wg,
	}

	handshake.StartHttpServer(params, &server)

}
