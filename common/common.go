package common

import "math/big"

type ServerData struct {
	IsEncrypted         bool
	P                   *big.Int
	Q                   *big.Int
	Private             *big.Int
	Public              *big.Int
	Shared              *big.Int
	ClientRandom        []byte
	ServerRandom        []byte
	AllMessagesShort    [][]byte
	MasterKey           []byte
	MacClient           []byte
	MacServer           []byte
	WriteKeyClient      []byte
	WriteKeyServer      []byte
	IVClient            []byte
	IVServer            []byte
	SeqNum              int
	SelectedCipherSuite uint16
}
