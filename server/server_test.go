package server

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestShouldKeepAlive(t *testing.T) {

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		wg.Done()
		RunServer("127.0.0.1", "4221")
	}()

	wg.Wait()

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
}

func TestCloseConectionAfterRequest(t *testing.T) {

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		wg.Done()
		RunServer("127.0.0.1", "4221")
	}()

	wg.Wait()

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

}

// Hardcoded timeout 5 seconds

func TestCloseConectionAfterTimeout(t *testing.T) {

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		wg.Done()
		RunServer("127.0.0.1", "4221")
	}()

	wg.Wait()

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

	time.Sleep(6 * time.Second)

	conn.Write([]byte(req))
	_, err = conn.Read(buff)
	if err == nil {
		t.Fatalf("connection should be closed, we got err: %v", err)
	}

}
