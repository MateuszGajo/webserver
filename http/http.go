package http

import (
	"fmt"
	"net"
	"strconv"
)

type handlerFunc func(resp HandlerResponse)

type RequestType string

const (
	GET RequestType = "GET"
)

var handlers map[string]map[string]handlerFunc = make(map[string]map[string]handlerFunc)

type Response struct {
	Headers map[ResponseHeaderField]string
}

type RequestHeaderField string

type ResponseHeaderField string

const (
	CONNECTION RequestHeaderField = "Connection"
)

const (
	KEEP_ALIVE                  ResponseHeaderField = "Keep-Alive"
	CONTENT_LENGTH              ResponseHeaderField = "Content-Length"
	CONTENT_TYPE                ResponseHeaderField = "Content-Type"
	ACCESS_CONTROL_ALLOW_ORIGIN ResponseHeaderField = "Access-Control-Allow-Origin"
)

var globalHeaders = make(map[ResponseHeaderField]string)

type Details struct {
	Protocol string
}

type HandlerResponse struct {
	SetHeader func(key, value string)
	SetCode   func(code int)
	Send      func(msg string)
}

type HttpConfig struct {
	Protocol        string
	ResponseHeaders map[ResponseHeaderField]string
}

func AddHandler(route, method string, handler handlerFunc) {

	if handlers[method] == nil {
		handlers[method] = make(map[string]handlerFunc)
	}

	handlers[method][route] = handler
}

type ContentType string

const (
	APPLICATION_JSON ContentType = "application/json"
)

func getCodeMsgForCode(code int) string {
	switch code {
	case 200:
		return "OK"
	case 404:
		return "Not Found"
	default:
		return "Server Error"
	}

}

func Cors(address string) {
	globalHeaders[ACCESS_CONTROL_ALLOW_ORIGIN] = address
}

func RunHandler(route, method string, conn net.Conn, config HttpConfig) Response {
	handler, ok := handlers[method][route]

	if !ok || handler == nil {
		fmt.Print("err")
		conn.Write([]byte(fmt.Sprintf("%v 404 Not Found\r\n\r\n", config.Protocol)))
		return Response{}
	}

	code := 500
	codeMsg := "Server Error"
	msg := "Server Error"
	headers := globalHeaders

	for key, value := range config.ResponseHeaders {
		headers[key] = value
	}

	SetCode := func(newCode int) {
		code = newCode
		codeMsg = getCodeMsgForCode(newCode)
	}

	SetHeader := func(key, value string) {
		headers[ResponseHeaderField(key)] = value
	}

	Send := func(newMsg string) {
		msg = newMsg
	}

	handlerResp := HandlerResponse{
		SetHeader: SetHeader,
		SetCode:   SetCode,
		Send:      Send,
	}

	handler(handlerResp)

	headers[CONTENT_LENGTH] = strconv.Itoa(len(msg))
	headers[CONTENT_TYPE] = "text/plain"

	requestLineResp := fmt.Sprintf("%v %v %v\r\n", config.Protocol, code, codeMsg)
	headerOutput := ""

	for key, value := range headers {
		headerOutput += fmt.Sprintf("%v: %v\r\n", key, value)
	}

	resp := requestLineResp + headerOutput + "\r\n" + msg

	_, err := conn.Write([]byte(resp))

	if err != nil {
		fmt.Printf("problem sending request back to client: %v", err)
	}

	return Response{
		Headers: headers,
	}
}
