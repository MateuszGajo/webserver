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

type Response struct {
	Headers map[string]string
}

func AddHandler(route, method string, handler handlerFunc) {

	if handlers[method] == nil {
		handlers[method] = make(map[string]handlerFunc)
	}

	handlers[method][route] = handler
}

func RunHandler(route, method string, conn net.Conn) Response {
	handler, ok := handlers[method][route]

	if !ok || handler == nil {
		fmt.Print("err")
		conn.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\n"))
		return Response{}
	}

	handler(conn)

	header := make(map[string]string)
	header["Keep-Alive"] = "timeout=5"

	return Response{
		Headers: header,
	}
}
