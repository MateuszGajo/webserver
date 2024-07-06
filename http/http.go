package http

import (
	"fmt"
	"net"
)

type handlerFunc func(conn net.Conn)

type RequestType string

const (
	GET RequestType = "GET"
)

var handlers map[string]map[string]handlerFunc = make(map[string]map[string]handlerFunc)

func AddHandler(route, method string, handler handlerFunc) {

	if handlers[method] == nil {
		handlers[method] = make(map[string]handlerFunc)
	}

	handlers[method][route] = handler
}

func RunHandler(route, method string, conn net.Conn) {
	handler, ok := handlers[method][route]

	if !ok || handler == nil {
		fmt.Print("err")
		conn.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
		return
	}

	handler(conn)
}
