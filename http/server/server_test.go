package server

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
	"webserver/http"
)

func CleanUp(conn net.Conn, server *Server) {
	err := conn.Close()

	if err != nil {
		fmt.Printf("Problem with closing connection, %v", err)
	}

	server.CloseServer()
}

func StartWebServer(options ...ServerOptions) *Server {
	var wg sync.WaitGroup
	var server *Server

	wg.Add(1)

	go func() {
		server = CreateServer(options...)
		wg.Done()
		server.RunServer()
	}()

	wg.Wait()

	return server
}

func TestShouldKeepAlive(t *testing.T) {
	server := StartWebServer()

	conn, err := net.Dial("tcp", "127.0.0.1:4221")

	if err != nil {
		t.Fatal("can't connect to web server on address 127.0.0.1:4221")
	}

	req := "GET / HTTP/1.1\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n"
	conn.Write([]byte(req))
	buff := make([]byte, 1024)
	_, err = conn.Read(buff)

	if err != nil {
		t.Fatalf("connection should be open, we got err: %v", err)
	}

	conn.Write([]byte(req))
	_, err = conn.Read(buff)
	if err != nil {
		t.Fatalf("connection should be open, we got err: %v", err)
	}

	defer CleanUp(conn, server)
}

func TestCloseConectionAfterRequest(t *testing.T) {
	server := StartWebServer()

	conn, err := net.Dial("tcp", "127.0.0.1:4221")

	if err != nil {
		t.Fatal("can't connect to web server on address 127.0.0.1:4221")
	}

	req := "GET / HTTP/1.1\r\n" +
		"\r\n"
	conn.Write([]byte(req))
	buff := make([]byte, 1024)
	_, err = conn.Read(buff)

	if err != nil {
		t.Fatalf("connection should be open, we got err: %v", err)
	}

	conn.Write([]byte(req))
	_, err = conn.Read(buff)
	if err == nil {
		t.Fatalf("connection should be closed, we got err: %v", err)
	}
	defer CleanUp(conn, server)
}

func TestCloseConectionAfterTimeout(t *testing.T) {

	timeoutSec := 1
	propgatationDelayS := 0.1

	server := StartWebServer(WithHeader(http.KEEP_ALIVE, fmt.Sprintf("timeout=%v", timeoutSec)))

	conn, err := net.Dial("tcp", "127.0.0.1:4221")

	if err != nil {
		t.Fatal("can't connect to web server on address 127.0.0.1:4221")
	}

	req := "GET / HTTP/1.1\r\n" +
		"Connection: keep-alive\r\n" +
		"\r\n"
	conn.Write([]byte(req))
	buff := make([]byte, 1024)
	_, err = conn.Read(buff)

	if err != nil {
		t.Fatalf("connection should be open, we got err: %v", err)
	}

	time.Sleep((time.Duration(timeoutSec*1000) + time.Duration(propgatationDelayS*1000)) * time.Millisecond)

	conn.Write([]byte(req))
	_, err = conn.Read(buff)
	if err == nil {
		t.Fatalf("connection should be closed, we got err: %v", err)
	}
	defer CleanUp(conn, server)
}
