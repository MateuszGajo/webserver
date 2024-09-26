package global

import (
	"net"
	"sync"
)

type Params struct {
	CertPath string
	KeyPath  string
}

type Server struct {
	Conn net.Listener
	Wg   *sync.WaitGroup
}
