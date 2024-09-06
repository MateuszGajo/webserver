package http

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
	"webserver/cipher"
	"webserver/helpers"
)

func startServer() net.Conn {
	listener, err := net.Listen("tcp", "127.0.0.1:4221")

	if err != nil {
		fmt.Println("errr has occured trying while trying to connect")
		fmt.Println(err)
	}

	conn, err := listener.Accept()

	if err != nil {
		fmt.Println("errr has occured trying while trying to connect")
		fmt.Println(err)
	}

	if err != nil {
		fmt.Println("errr has occured trying while accepting connection")
		fmt.Println(err)
	}

	return conn

}

func readNMessage(n int, conn net.Conn) ([][]byte, error) {
	messages := [][]byte{}
	for len(messages) < n {
		fmt.Println(len(messages))
		fmt.Println(messages)
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)

		if err != nil {
			return [][]byte{}, errors.New("cant read message")

		}

		// TODO improve reading
		// create a func read n message pass we want 3 message have readed, serverHello, serverKeyExchange, serverHelloDOne

		data, _, _ := Parser(buf[:n])
		fmt.Println("hello message", data)
		messages = append(messages, data...)
	}

	return messages, nil
}

func readBigEndianN(data []byte) *big.Int {
	z := new(big.Int)
	z.SetBytes(data)

	return z
}

func TestHandshakeTripleDes(t *testing.T) {
	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		wg.Done()
		HandleConnection(startServer())
	}()

	wg.Wait()

	conn, err := net.Dial("tcp", "127.0.0.1:4221")

	if err != nil {
		t.Error("problem connectin to server")
	}

	handshakeMessages := [][]byte{}

	clientRandomBytes := []byte{102, 213, 128, 42, 254, 171, 56, 146, 68, 181, 149, 44, 224, 124, 234, 207, 212, 237, 164, 74, 10, 169, 28, 204, 174, 157, 81, 130, 0, 0, 0, 0}
	// TODO: fix becasue it was  passing even we pass mor ethan 32 bytes of random bytes

	clientHello := []byte{22, 3, 0, 0, 45, 1, 0, 0, 41, 3, 0}
	clientHello = append(clientHello, clientRandomBytes...)
	clientHello = append(clientHello, []byte{0, 0, 2}...)
	clientHello = append(clientHello, []byte{0, 27, 1, 0}...)

	handshakeMessages = append(handshakeMessages, clientHello[5:])

	_, err = conn.Write(clientHello)

	data, err := readNMessage(3, conn)
	serverHello := data[0]
	serverKeyExchange := data[1]
	serverHelloDone := data[2]

	handshakeMessages = append(handshakeMessages, serverHello[5:])
	handshakeMessages = append(handshakeMessages, serverKeyExchange[5:])
	handshakeMessages = append(handshakeMessages, serverHelloDone[5:])

	fmt.Println("messages")
	fmt.Println(data)

	if err != nil {
		t.Error("error!!!")
	}

	recType := serverHello[0]
	sslVersion := binary.BigEndian.Uint16((serverHello[1:3]))
	recLength := binary.BigEndian.Uint16((serverHello[3:5]))
	handshakeType := serverHello[5]
	handshakeLength := uint32(serverHello[6])<<16 | uint32(serverHello[7])<<8 | uint32(serverHello[8])
	handshakeRandomTime := binary.BigEndian.Uint32((serverHello[11:15]))
	handshakeRandomBytes := serverHello[11:43]

	// 2 for protocol version
	// client random 32
	// 1 for session id
	handshakeAlgorithm := binary.BigEndian.Uint16((serverHello[44:46]))
	handshakeCompression := serverHello[46]

	if recType != byte(TLSContentTypeHandshake) {
		t.Error("should return tls handshake type")
	}

	if sslVersion != SSL30Version {
		t.Error("version should be ssl 3.0")
	}

	if recLength != 42 {
		t.Error("Record length shuld be 42")
	}

	if handshakeType != byte(TLSHandshakeMessageServerHello) {
		t.Error("Handshake type should be server hello")
	}

	if handshakeLength != 38 {
		t.Error("Handshake length should be 38")
	}

	currentTime := time.Now().Unix()

	if int64(handshakeRandomTime)-int64(currentTime) > 1000 {
		t.Error("Handshkae invalid time, or really slow response")
	}

	if handshakeAlgorithm != uint16(cipher.TLS_CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA) {
		t.Errorf("Expected algorithm: %v, got:%v", cipher.TLS_CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA, handshakeAlgorithm)
	}

	if handshakeCompression != 0 {
		t.Error("expected no compression")
	}

	recType = serverKeyExchange[0]
	sslVersion = binary.BigEndian.Uint16((serverKeyExchange[1:3]))
	recLength = binary.BigEndian.Uint16((serverKeyExchange[3:5]))
	handshakeType = serverKeyExchange[5]
	handshakeLength = uint32(serverKeyExchange[6])<<16 | uint32(serverKeyExchange[7])<<8 | uint32(serverKeyExchange[8])

	//0 1 3 0 1 2 0 1 2
	index := 9
	dhParams := []*big.Int{}
	for i := 0; i < 3; i++ {
		length := binary.BigEndian.Uint16(serverKeyExchange[index : index+2])
		index += 2
		number := readBigEndianN(serverKeyExchange[index : index+int(length)])
		index += int(length)

		dhParams = append(dhParams, number)
	}
	p := dhParams[0]
	q := dhParams[1]
	serverPublic := dhParams[2]

	if index > len(serverKeyExchange) {
		t.Errorf("Server key exchange is longer than it supposed to be, message: %v, len:%v, expected len: %v ", serverKeyExchange, len(serverKeyExchange), index)
	}

	if recType != byte(TLSContentTypeHandshake) {
		t.Error("should return tls handshake type")
	}

	if sslVersion != SSL30Version {
		t.Error("version should be ssl 3.0")
	}

	if handshakeType != byte(TLSHandshakeMessageServerKeyExchange) {
		t.Error("Handshake type should be server key exchange")
	}

	expectedRecLength := len(serverKeyExchange) - 5
	expectedHandshakeLength := len(serverKeyExchange) - 5 - 4 // 5: 1 bytes rec type, 2 bytes ssl version, 2 bytes rec length, 4: 1 bytes hadnshake type, 3 bytes handshake length

	if expectedRecLength != int(recLength) {
		t.Errorf("Expected rec length: %v, but got: %v", expectedRecLength, recLength)
	}

	if expectedHandshakeLength != int(handshakeLength) {
		t.Errorf("Expected handshake length: %v, but got: %v", expectedHandshakeLength, handshakeLength)
	}

	recType = serverHelloDone[0]
	sslVersion = binary.BigEndian.Uint16((serverHelloDone[1:3]))
	recLength = binary.BigEndian.Uint16((serverHelloDone[3:5]))
	handshakeType = serverHelloDone[5]
	handshakeLength = uint32(serverHelloDone[6])<<16 | uint32(serverHelloDone[7])<<8 | uint32(serverHelloDone[8])

	if recType != byte(TLSContentTypeHandshake) {
		t.Error("should return tls handshake type")
	}

	if sslVersion != SSL30Version {
		t.Error("version should be ssl 3.0")
	}

	if recLength != 4 {
		t.Error("Record length shuld be 4")
	}

	if handshakeType != byte(TLSHandshakeMessageServerHelloDone) {
		t.Error("Handshake type should be server hello")
	}

	if handshakeLength != 0 {
		t.Error("Handshake length should be 0")
	}

	private := big.NewInt(3)

	serverData := ServerData{
		CipherDef: cipher.CipherDef{
			Spec: cipher.CipherSpec{
				HashAlgorithm: cipher.HashAlgorithmSHA,
			},
			DhParams: cipher.DhParams{
				P:            p,
				Q:            q,
				Private:      private,
				ClientPublic: serverPublic, // TODO to fix itin this case server public
			},
		},
	}

	preMasterSecret := serverData.CipherDef.DhParams.ComputePreMasterSecret()

	tripledDesHashSize := 20
	tripledDesKeyMaterialSize := 24
	tripledDesIvSize := 8

	masterKeySeed := []byte{}
	masterKeySeed = append(masterKeySeed, clientRandomBytes...)
	masterKeySeed = append(masterKeySeed, handshakeRandomBytes...)

	keyBlockSeed := []byte{}
	keyBlockSeed = append(keyBlockSeed, handshakeRandomBytes...)
	keyBlockSeed = append(keyBlockSeed, clientRandomBytes...)

	keyBlockLen := tripledDesHashSize*2 + tripledDesKeyMaterialSize*2 + tripledDesIvSize*2

	fmt.Println("master key seed")
	fmt.Println(masterKeySeed)

	masterKey := ssl_prf(preMasterSecret.Bytes(), masterKeySeed, MASTER_SECRET_LENGTH)

	fmt.Println("master key")
	fmt.Println(masterKey)
	keyBlock := ssl_prf(masterKey, keyBlockSeed, keyBlockLen)

	macEndIndex := tripledDesHashSize * 2
	writeKeyEndIndex := macEndIndex + tripledDesKeyMaterialSize*2

	cipherDefKeys := cipher.CipherKeys{
		MacClient:      keyBlock[:tripledDesHashSize],
		MacServer:      keyBlock[tripledDesHashSize:macEndIndex],
		WriteKeyClient: keyBlock[macEndIndex : macEndIndex+tripledDesKeyMaterialSize],
		WriteKeyServer: keyBlock[tripledDesHashSize*2+tripledDesKeyMaterialSize : writeKeyEndIndex],
		IVClient:       keyBlock[writeKeyEndIndex : writeKeyEndIndex+tripledDesIvSize],
		IVServer:       keyBlock[writeKeyEndIndex+tripledDesIvSize : writeKeyEndIndex+tripledDesIvSize*2],
	}
	fmt.Println("cipher def keys")
	fmt.Printf("\n %+v", cipherDefKeys)

	clientKeyExchangeMsg := []byte{22, 3, 0, 0, 7, 16, 0, 0, 3, 0, 1, 2}
	clientChangeCipher := []byte{20, 3, 0, 0, 1, 1}

	conn.Write(clientKeyExchangeMsg)
	conn.Write(clientChangeCipher)

	handshakeMessages = append(handshakeMessages, clientKeyExchangeMsg[5:])

	clientBytes := helpers.Int64ToBIgEndian(int64(ClientSender))
	md5Hash := generate_finished_handshake_mac(md5.New(), masterKey, clientBytes, handshakeMessages) // -1 without last message witch is client verify
	shaHash := generate_finished_handshake_mac(sha1.New(), masterKey, clientBytes, handshakeMessages)

	hashMessages := append(md5Hash, shaHash...)

	seqNum := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	msg := []byte{20, 0, 0, 36}
	msg = append(msg, hashMessages...)

	handshakeMessages = append(handshakeMessages, msg)

	streamCipher := serverData.generateStreamCipher([]byte{byte(TLSContentTypeHandshake)}, msg, seqNum, cipherDefKeys.MacClient)

	msg = append(msg, streamCipher...)

	encrypted := cipher.EncryptDesMessage(msg, cipherDefKeys.WriteKeyClient, cipherDefKeys.IVClient)

	finishedMsg := []byte{22, 3, 0, 0, 64}
	finishedMsg = append(finishedMsg, encrypted...)

	fmt.Println("whole msg")
	fmt.Println(finishedMsg)

	_, err = conn.Write(finishedMsg)

	if err != nil {
		t.Errorf("Problem writing client finished messgae :%v", err)
	}

	data, err = readNMessage(2, conn)

	serverChangeCipher := data[0]
	serverFinished := data[1]

	changeCipherContentType := serverChangeCipher[0]
	changeCipherContentSslVersion := binary.BigEndian.Uint16(serverChangeCipher[1:3])
	changeCipherContentLength := binary.BigEndian.Uint16(serverChangeCipher[3:5])
	changeCipherContentData := serverChangeCipher[5]

	if changeCipherContentType != byte(TLSContentTypeChangeCipherSpec) {
		t.Error("should return tls change cipher type type")
	}

	if changeCipherContentSslVersion != SSL30Version {
		t.Error("version should be ssl 3.0")
	}

	if changeCipherContentLength != 1 {
		t.Error("Record length shuld be 1")
	}

	if changeCipherContentData != 1 {
		t.Error("Data of change cipher should be 1")
	}

	if err != nil {
		t.Errorf("Problem reading server finished :%v", err)
	}

	encryptedServerFinishedData := serverFinished[5:]
	decryptedServerFinishedData := cipher.DecryptDesMessage(encryptedServerFinishedData, cipherDefKeys.WriteKeyServer, cipherDefKeys.IVServer)
	decryptedServerFinishedDataNoHeader := decryptedServerFinishedData[4:]

	serverBytes := helpers.Int64ToBIgEndian(int64(serverSender))
	serverMd5Hash := decryptedServerFinishedDataNoHeader[:16]
	serverShaHash := decryptedServerFinishedDataNoHeader[16:36]
	serverCipher := decryptedServerFinishedDataNoHeader[36:]

	md5Hash = generate_finished_handshake_mac(md5.New(), masterKey, serverBytes, handshakeMessages) // -1 without last message witch is client verify
	shaHash = generate_finished_handshake_mac(sha1.New(), masterKey, serverBytes, handshakeMessages)
	cipherData := decryptedServerFinishedData[:4]
	cipherData = append(cipherData, md5Hash...)
	cipherData = append(cipherData, shaHash...)
	streamCipher = serverData.generateStreamCipher([]byte{byte(TLSContentTypeHandshake)}, cipherData, seqNum, cipherDefKeys.MacServer)

	fmt.Println("``````")
	fmt.Println(cipherData)
	fmt.Println(seqNum)
	fmt.Println(cipherDefKeys.MacServer)

	if !reflect.DeepEqual(serverMd5Hash, md5Hash) {
		t.Errorf("Server finished md5 is diffrent than computed expected: %v, got: %v", md5Hash, serverMd5Hash)
	}

	if !reflect.DeepEqual(serverShaHash, shaHash) {
		t.Errorf("Server finished sha is diffrent than computed expected: %v, got: %v", shaHash, serverShaHash)
	}

	if !reflect.DeepEqual(serverCipher, streamCipher) {
		t.Errorf("Server finished cipher is diffrent than computed expected: %v, got: %v", streamCipher, serverCipher)
	}

}
