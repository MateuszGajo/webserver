package main

import (
	. "webserver/controller"
	. "webserver/http"
	"webserver/server"
)

func main() {

	AddHandler("/", string(GET), HangleRootGet)
	server.RunServer("127.0.0.1", "4221")

}
