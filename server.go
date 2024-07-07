package main

import (
	"webserver/http"
	"webserver/server"
)

func main() {
	http.Cors("http://localhost:5501")

	server := server.CreateServer()
	server.RunServer()

}
