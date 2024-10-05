package server

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"webserver/controller"
	"webserver/http"
	"webserver/httpParser"
)

type ServerConfig struct {
	address  string
	port     string
	quit     chan interface{}
	wg       sync.WaitGroup
	listener net.Listener
}

type Server struct {
	HttpConfig   http.HttpConfig
	serverConfig ServerConfig
}

type ServerOptions func(s *Server)

func WithAddress(address, port string) ServerOptions {
	return func(s *Server) {
		s.serverConfig.address = address
		s.serverConfig.port = port
	}
}

func WithHeader(key http.ResponseHeaderField, value string) ServerOptions {
	return func(s *Server) {
		s.HttpConfig.ResponseHeaders[key] = value
	}
}

func CreateServer(options ...ServerOptions) *Server {
	server := &Server{
		serverConfig: ServerConfig{
			address: "127.0.0.1",
			port:    "4221",
			quit:    make(chan interface{}),
		},
		HttpConfig: http.HttpConfig{
			Protocol: "HTTP/1.1",
			ResponseHeaders: map[http.ResponseHeaderField]string{
				http.KEEP_ALIVE: "timeout=5",
			},
		},
	}

	for _, option := range options {
		option(server)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%v:%v", server.serverConfig.address, server.serverConfig.port))

	if err != nil {
		fmt.Printf("cannt listen to port 4221: %v", err)
	}
	server.serverConfig.listener = listener
	server.serverConfig.wg.Add(1)

	return server
}

func (s *Server) CloseServer() {
	close(s.serverConfig.quit)
	err := s.serverConfig.listener.Close()
	if err != nil {
		fmt.Printf("problem closing server: %v", err)
	}

	s.serverConfig.wg.Wait()

}

func (s *Server) RunServer() {
	defer s.serverConfig.wg.Done()
	http.AddHandler("/", string(http.GET), controller.HangleRootGet)

	for {

		conn, err := s.serverConfig.listener.Accept()

		if err != nil {
			select {
			case <-s.serverConfig.quit:
				return
			default:
				fmt.Print("problem accepting connection")
			}
		} else {
			s.serverConfig.wg.Add(1)
			go func() {
				s.handleConnection(conn)
				s.serverConfig.wg.Done()
			}()
		}

	}

}

func (s *Server) handleConnection(conn net.Conn) {
	defer func(conn net.Conn) {
		err := conn.Close()
		fmt.Print("closing connection")

		if err != nil {
			fmt.Printf("Problem with closing connectin, err: %v", err)
		}
	}(conn)
	keepAliveCount := 0
	var timeout *time.Time = nil
	for {

		if timeout != nil {
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

		req := httpParser.ParseRequest(msg)

		resp := http.RunHandler(req.RequestLine.Path, req.RequestLine.ReqType, conn, s.HttpConfig)

		if val, ok := req.Headers[string(http.CONNECTION)]; !ok || val != "keep-alive" {
			fmt.Print("close third point")
			return
		}

		keepAliveHeader, ok := resp.Headers[http.KEEP_ALIVE]

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
			if keepAliveCount >= valInt {
				fmt.Print("close seconds point")
				return
			}
			keepAliveCount++
		}

	}

}
