package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"webserver/controller"
	"webserver/http"
	"webserver/parser"
)

type RequestHeaderField string

type ResponseHeaderField string

const (
	CONNECTION RequestHeaderField = "Connection"
)

const (
	KEEP_ALIVE ResponseHeaderField = "Keep-Alive"
)

func RunServer(address, port string) {
	http.AddHandler("/", string(http.GET), controller.HangleRootGet)
	listener, err := net.Listen("tcp", fmt.Sprintf("%v:%v", address, port))

	if err != nil {
		fmt.Printf("cannt listen to port 4221: %v", err)
	}

	for {

		conn, err := listener.Accept()

		if err != nil {
			fmt.Printf("cannot accept connection: %v", err)
			conn.Close()
			continue
		}

		go handleConnection(conn)
	}

}

func handleConnection(conn net.Conn) {
	defer func(conn net.Conn) {
		err := conn.Close()
		fmt.Print("closing connection")

		if err != nil {
			fmt.Printf("Problem with closing connectin, err: %v", err)
		}
	}(conn)
	count := 0
	var timeout *time.Time = nil
	for {

		if timeout != nil {
			fmt.Println("timeout??")
			fmt.Println(timeout.UnixMilli())
			fmt.Println(time.Now().UnixMilli())
			if timeout.UnixMilli() <= time.Now().UnixMilli() {
				fmt.Print("close first point")
				return
			}
		}
		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		buf := make([]byte, 2048)

		n, err := conn.Read(buf)

		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Read timeout reached:", err)
			continue
		} else if err != nil {
			fmt.Printf("problem reading data, %v", err)
			return
		}

		msg := string(buf[:n])

		req := parser.ParseRequest(msg)

		resp := http.RunHandler(req.RequestLine.Path, req.RequestLine.ReqType, conn)

		if val, ok := req.Headers[string(CONNECTION)]; !ok || val != "keep-alive" {
			fmt.Print("close third point")
			return
		}
		// Keep-Alive: timeout=5, max=1000

		keepAliveHeader, ok := resp.Headers[string(KEEP_ALIVE)]

		if !ok {
			continue
		}

		keepAliveHeaderValues := strings.Split(keepAliveHeader, ",")

		if len(keepAliveHeaderValues) == 0 {
			continue
		}

		keepAliveFields := make(map[string]string)
		for _, v := range keepAliveHeaderValues {
			keyValue := strings.Split(v, "=")
			keepAliveFields[keyValue[0]] = keyValue[1]
		}

		if val, ok := keepAliveFields["timeout"]; ok && timeout == nil {
			valInt, err := strconv.Atoi(val)
			if err != nil {
				fmt.Printf("Wrong value in keep alive timeout, we got:%q", valInt)
				continue
			}

			timeoutVar := time.Now().Add(time.Duration(valInt) * time.Second)

			timeout = &timeoutVar
		}

		if val, ok := keepAliveFields["max"]; ok {
			valInt, err := strconv.Atoi(val)
			if err != nil {
				fmt.Printf("Wrong value in Keep alive max, we got:%q", valInt)
				continue
			}
			if count >= valInt {
				fmt.Print("close seconds point")
				return
			}
			count++
		}

	}

}
