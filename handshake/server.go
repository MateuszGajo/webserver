package handshake

import (
	"fmt"
	"handshakeServer/cipher"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type HttpServer struct {
	Listener  net.Listener
	Wg        *sync.WaitGroup
	CertParam *HttpServerCertParam
	address   string
	port      string
	quit      chan interface{}
	Version   []byte
}

type HttpServerCertParam struct {
	CertPath string
	KeyPath  string
}

type ExtHeartBeat struct {
	quit        chan struct{}
	once        sync.Once
	lastAct     *time.Time
	lastPayload []byte
}

type ServerData struct {
	IsClientEncrypted bool
	IsServerEncrypted bool
	PreMasterSecret   []byte
	ClientRandom      []byte
	ServerRandom      []byte
	Version           []byte
	HandshakeMessages [][]byte
	MasterKey         []byte
	CipherDef         cipher.CipherDef
	ServerSeqNum      []byte
	ClientSeqNum      []byte
	conn              net.Conn
	wBuff             []byte
	cert              []byte
	session           []byte
	reuseSession      bool
	extHeartBeat      *ExtHeartBeat
}

type HttpServerOptions func(s *HttpServer)

func WithAddress(address, port string) HttpServerOptions {
	return func(s *HttpServer) {
		s.address = address
		s.port = port
	}
}

func WithCertificate(certParams *HttpServerCertParam) HttpServerOptions {
	return func(s *HttpServer) {
		s.CertParam = certParams
	}
}

func WithSSLVersion(version []byte) HttpServerOptions {
	return func(s *HttpServer) {
		s.Version = version
	}
}

func CreateServer(options ...HttpServerOptions) (*HttpServer, error) {
	var wg sync.WaitGroup

	httpServer := &HttpServer{
		Wg:   &wg,
		quit: make(chan interface{}),
	}

	for _, option := range options {
		option(httpServer)
	}

	if httpServer.address == "" {
		return nil, fmt.Errorf("there is no address passed")
	}

	if httpServer.port == "" {
		return nil, fmt.Errorf("there is no port passed")
	}

	listener, err := net.Listen("tcp", httpServer.address+":"+httpServer.port)

	fmt.Printf("server is listening on:%v", httpServer.address+":"+httpServer.port)

	if err != nil {
		return nil, err
	}

	httpServer.Listener = listener
	httpServer.Wg.Add(1)
	go httpServer.startHttpServer()

	return httpServer, nil
}

func (httpServer *HttpServer) startHttpServer() {
	defer httpServer.Wg.Done()
	for {

		serverData := ServerData{ServerSeqNum: []byte{0, 0, 0, 0, 0, 0, 0, 0}, Version: httpServer.Version, ClientSeqNum: []byte{0, 0, 0, 0, 0, 0, 0, 0}, CipherDef: cipher.CipherDef{}}

		if (httpServer.CertParam) != nil {

			err := serverData.loadCert(httpServer.CertParam.CertPath, httpServer.CertParam.KeyPath)

			if err != nil {
				fmt.Printf("\n problem loading certificate, err :%v", err)
				break
			}
		}

		conn, err := httpServer.Listener.Accept()

		serverData.conn = conn

		if err != nil {
			select {
			case <-httpServer.quit:
				return
			default:
				fmt.Printf("errr has occured trying while trying to connect, err :%v", err)
			}
		} else {
			httpServer.Wg.Add(1)
			go func() {
				httpServer.handleConnection(conn, &serverData)
				httpServer.Wg.Done()
			}()
		}

	}
}

func (httpServer *HttpServer) CloseHttpServer() {
	close(httpServer.quit)
	err := httpServer.Listener.Close()

	if err != nil {
		fmt.Printf("problem closing server: %v", err)
	}

	httpServer.Wg.Wait()
}

func (httpServer *HttpServer) handleConnection(conn net.Conn, serverData *ServerData) {
	defer serverData.closeHandshakeConn()

	bufInit := []byte{}

Loop:
	for {
		select {
		case <-httpServer.quit:
			return
		default:
			buff := make([]byte, 1024)
			conn.SetDeadline(time.Now().Add(650 * time.Millisecond))
			n, err := conn.Read(buff)
			if err != nil {
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					continue Loop
				} else if err != io.EOF {
					log.Println("read error", err)
					return
				}
			}
			if n == 0 {
				return
			}
			msg := buff[:n]

			input := append(bufInit, msg...)
			msgs, partial, err := serverData.Parser(input)
			bufInit = partial

			if err != nil {
				fmt.Printf("\n parser error: %v", err)
				serverData.sendAlertMsg(AlertLevelfatal, AlertDescriptionHandshakeFailure)
			}

			for _, msg := range msgs {
				err := handleMessage(msg, serverData)
				if err != nil {
					fmt.Println(err)
					break Loop
				}
			}
		}
	}

}
