package http

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
	"webserver/cipher"
	"webserver/global"
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
	leftovers := []byte{}
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
		fmt.Println("```````")
		fmt.Println("```````")
		fmt.Println("data")
		fmt.Println(buf[:n])
		fmt.Println("```````")
		input := []byte{}
		input = append(input, leftovers...)
		input = append(input, buf[:n]...)
		data, rest, err := Parser(input)
		leftovers = rest
		if err != nil {
			fmt.Println("problem parsing")
			fmt.Println(err)
			os.Exit(1)
		}
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

func (serverData *ServerData) generateClientHello() []byte {
	clientRandomBytes := serverData.ClientRandom
	if clientRandomBytes == nil {
		clientRandomBytes = []byte{102, 213, 128, 42, 254, 171, 56, 146, 68, 181, 149, 44, 224, 124, 234, 207, 212, 237, 164, 74, 10, 169, 28, 204, 174, 157, 81, 130, 0, 0, 0, 0}
	}
	// TODO: fix becasue it was  passing even we pass mor ethan 32 bytes of random bytes
	sslVersion := []byte{3, 0}

	if serverData.SSLVersion != nil {
		sslVersion = serverData.SSLVersion
	}

	clientHello := []byte{22}
	clientHello = append(clientHello, sslVersion...)
	// TODO change hardcoded length of record layer and content
	clientHello = append(clientHello, []byte{0, 45, 1, 0, 0, 41}...)
	clientHello = append(clientHello, sslVersion...)
	clientHello = append(clientHello, clientRandomBytes...)
	clientHello = append(clientHello, []byte{0, 0, 2}...)
	cipher := []byte{0, 27}
	if serverData.CipherDef.CipherSuite != 0 {
		cipher = helpers.Int32ToBigEndian(int(serverData.CipherDef.CipherSuite))
	}
	clientHello = append(clientHello, cipher...)
	clientHello = append(clientHello, []byte{1, 0}...)

	return clientHello
}

func (serverData *ServerData) verifyServerHello(data []byte) error {
	recType := data[0]
	sslVersion := binary.BigEndian.Uint16((data[1:3]))
	recLength := binary.BigEndian.Uint16((data[3:5]))
	handshakeType := data[5]
	handshakeLength := uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])
	handshakeRandomTime := binary.BigEndian.Uint32((data[11:15]))
	handshakeRandomBytes := data[11:43]
	serverData.ServerRandom = handshakeRandomBytes

	// 2 for protocol version
	// client random 32
	// 1 for session id
	handshakeAlgorithm := binary.BigEndian.Uint16((data[44:46]))
	handshakeCompression := data[46]

	if recType != byte(TLSContentTypeHandshake) {
		return fmt.Errorf("should return tls handshake type")
	}

	if sslVersion != SSL30Version {
		return fmt.Errorf("version should be ssl 3.0")
	}

	if recLength != 42 {
		return fmt.Errorf("Record length shuld be 42")
	}

	if handshakeType != byte(TLSHandshakeMessageServerHello) {
		return fmt.Errorf("Handshake type should be server hello")
	}

	if handshakeLength != 38 {
		return fmt.Errorf("Handshake length should be 38")
	}

	currentTime := time.Now().Unix()

	if int64(handshakeRandomTime)-int64(currentTime) > 1000 {
		return fmt.Errorf("Handshkae invalid time, or really slow response")
	}

	if handshakeAlgorithm != uint16(serverData.CipherDef.CipherSuite) {
		return fmt.Errorf("Expected algorithm: %v, got:%v", cipher.TLS_CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA, handshakeAlgorithm)
	}

	if handshakeCompression != 0 {
		return fmt.Errorf("expected no compression")
	}

	return nil

}

func (serverData *ServerData) verifyServerKeyExchange(data []byte) error {
	recType := data[0]
	sslVersion := binary.BigEndian.Uint16((data[1:3]))
	recLength := binary.BigEndian.Uint16((data[3:5]))
	handshakeType := data[5]
	handshakeLength := uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])

	//0 1 3 0 1 2 0 1 2

	if recType != byte(TLSContentTypeHandshake) {
		return fmt.Errorf("should return tls handshake type")
	}

	if sslVersion != SSL30Version {
		return fmt.Errorf("version should be ssl 3.0")
	}

	if handshakeType != byte(TLSHandshakeMessageServerKeyExchange) {
		return fmt.Errorf("Handshake type should be server key exchange")
	}

	expectedRecLength := len(data) - 5
	expectedHandshakeLength := len(data) - 5 - 4 // 5: 1 bytes rec type, 2 bytes ssl version, 2 bytes rec length, 4: 1 bytes hadnshake type, 3 bytes handshake length

	if expectedRecLength != int(recLength) {
		return fmt.Errorf("Expected rec length: %v, but got: %v", expectedRecLength, recLength)
	}

	if expectedHandshakeLength != int(handshakeLength) {
		return fmt.Errorf("Expected handshake length: %v, but got: %v", expectedHandshakeLength, handshakeLength)
	}
	var err error

	switch serverData.CipherDef.Spec.KeyExchange {
	case cipher.KeyExchangeMethodDH:
		err = serverData.verifyServerKeyExchangeDHParams(data[9:])
	case cipher.KeyExchangeMethodDHE:
		err = serverData.verifyServerKeyExchangeDHParams(data[9:])
	default:
		fmt.Println("unsported key exchange")
		os.Exit(1)
	}

	return err

}

func (serverData *ServerData) verifyServerKeyExchangeDHParams(data []byte) error {
	index := 0
	dhParams := []*big.Int{}
	for i := 0; i < 3; i++ {
		length := binary.BigEndian.Uint16(data[index : index+2])
		index += 2
		number := readBigEndianN(data[index : index+int(length)])
		index += int(length)

		dhParams = append(dhParams, number)
	}

	if index > len(data) {
		return fmt.Errorf("Server key exchange is longer than it supposed to be, message: %v, len:%v, expected len: %v ", data, len(data), index)
	}

	fmt.Println("servery key exchange")
	fmt.Println("servery key exchange")
	fmt.Println("servery key exchange")

	p := dhParams[0]
	q := dhParams[1]
	serverPublic := dhParams[2]

	fmt.Println(p)
	fmt.Println(q)
	fmt.Println(serverPublic)

	serverData.CipherDef.DhParams = cipher.DhParams{
		P:            p,
		Q:            q,
		ClientPublic: serverPublic, // TODO to fix itin this case server public
	}

	return nil
}

func (serverData *ServerData) verifyServerHelloDone(data []byte) error {
	recType := data[0]
	sslVersion := binary.BigEndian.Uint16((data[1:3]))
	recLength := binary.BigEndian.Uint16((data[3:5]))
	handshakeType := data[5]
	handshakeLength := uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])

	if recType != byte(TLSContentTypeHandshake) {
		return fmt.Errorf("should return tls handshake type")
	}

	if sslVersion != SSL30Version {
		return fmt.Errorf("version should be ssl 3.0")
	}

	if recLength != 4 {
		return fmt.Errorf("Record length shuld be 4")
	}

	if handshakeType != byte(TLSHandshakeMessageServerHelloDone) {
		return fmt.Errorf("Handshake type should be server hello")
	}

	if handshakeLength != 0 {
		return fmt.Errorf("Handshake length should be 0")
	}
	return nil
}

func (serverData *ServerData) computeKeys(data []byte) {
	fmt.Println("before pre master")
	preMasterSecret := serverData.CipherDef.ComputerMasterSecret(data)
	fmt.Println("after pre master")
	fmt.Println(preMasterSecret)

	tripledDesHashSize := serverData.CipherDef.Spec.HashSize
	tripledDesKeyMaterialSize := serverData.CipherDef.Spec.KeyMaterial
	tripledDesIvSize := serverData.CipherDef.Spec.IvSize

	masterKeySeed := []byte{}
	masterKeySeed = append(masterKeySeed, serverData.ClientRandom...)
	masterKeySeed = append(masterKeySeed, serverData.ServerRandom...)

	keyBlockSeed := []byte{}
	keyBlockSeed = append(keyBlockSeed, serverData.ServerRandom...)
	keyBlockSeed = append(keyBlockSeed, serverData.ClientRandom...)

	keyBlockLen := tripledDesHashSize*2 + tripledDesKeyMaterialSize*2 + tripledDesIvSize*2

	fmt.Println("master key seed")
	fmt.Println(masterKeySeed)

	masterKey := ssl_prf(preMasterSecret, masterKeySeed, MASTER_SECRET_LENGTH)

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

	serverData.CipherDef.Keys = cipherDefKeys

	serverData.MasterKey = masterKey
}

func (serverData *ServerData) verifyServerChangeCipher(data []byte) error {
	changeCipherContentType := data[0]
	changeCipherContentSslVersion := binary.BigEndian.Uint16(data[1:3])
	changeCipherContentLength := binary.BigEndian.Uint16(data[3:5])
	changeCipherContentData := data[5]

	if changeCipherContentType != byte(TLSContentTypeChangeCipherSpec) {
		return fmt.Errorf("should return tls change cipher type type")
	}

	if changeCipherContentSslVersion != SSL30Version {
		return fmt.Errorf("version should be ssl 3.0")
	}

	if changeCipherContentLength != 1 {
		return fmt.Errorf("Record length shuld be 1")
	}

	if changeCipherContentData != 1 {
		return fmt.Errorf("Data of change cipher should be 1")
	}

	return nil
}

func (serverData *ServerData) verifyServerFinished(data []byte) error {
	encryptedServerFinishedData := data[5:]
	decryptedServerFinishedData := serverData.CipherDef.DecryptMessage(encryptedServerFinishedData, serverData.CipherDef.Keys.WriteKeyServer, serverData.CipherDef.Keys.IVServer)

	decryptedServerFinishedDataNoHeader := decryptedServerFinishedData[4:]

	serverBytes := helpers.Int64ToBIgEndian(int64(serverSender))
	serverMd5Hash := decryptedServerFinishedDataNoHeader[:16]
	serverShaHash := decryptedServerFinishedDataNoHeader[16:36]
	serverCipher := decryptedServerFinishedDataNoHeader[36:]

	md5Hash := generate_finished_handshake_mac(md5.New(), serverData.MasterKey, serverBytes, serverData.HandshakeMessages) // -1 without last message witch is client verify
	shaHash := generate_finished_handshake_mac(sha1.New(), serverData.MasterKey, serverBytes, serverData.HandshakeMessages)
	cipherData := decryptedServerFinishedData[:4]
	cipherData = append(cipherData, md5Hash...)
	cipherData = append(cipherData, shaHash...)
	streamCipher := serverData.generateStreamCipher([]byte{byte(TLSContentTypeHandshake)}, cipherData, serverData.ClientSeqNum, serverData.CipherDef.Keys.MacServer)

	if !reflect.DeepEqual(serverMd5Hash, md5Hash) {
		return fmt.Errorf("Server finished md5 is diffrent than computed expected: %v, got: %v", md5Hash, serverMd5Hash)
	}

	if !reflect.DeepEqual(serverShaHash, shaHash) {
		return fmt.Errorf("Server finished sha is diffrent than computed expected: %v, got: %v", shaHash, serverShaHash)
	}

	if !reflect.DeepEqual(serverCipher, streamCipher) {
		return fmt.Errorf("Server finished cipher is diffrent than computed expected: %v, got: %v", streamCipher, serverCipher)
	}

	return nil
}

func (serverData *ServerData) generateClientFinishedMsg() []byte {

	clientBytes := helpers.Int64ToBIgEndian(int64(ClientSender))
	md5Hash := generate_finished_handshake_mac(md5.New(), serverData.MasterKey, clientBytes, serverData.HandshakeMessages) // -1 without last message witch is client verify
	shaHash := generate_finished_handshake_mac(sha1.New(), serverData.MasterKey, clientBytes, serverData.HandshakeMessages)

	hashMessages := append(md5Hash, shaHash...)

	msg := []byte{20, 0, 0, 36}
	msg = append(msg, hashMessages...)

	fmt.Println("handshake msgs")
	fmt.Println(serverData.HandshakeMessages)

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, msg)

	streamCipher := serverData.generateStreamCipher([]byte{byte(TLSContentTypeHandshake)}, msg, serverData.ClientSeqNum, serverData.CipherDef.Keys.MacClient)

	msg = append(msg, streamCipher...)

	fmt.Println("encrypt with")
	fmt.Println("encrypt with")
	fmt.Println("encrypt with")
	fmt.Println("encrypt with")
	fmt.Println(serverData.CipherDef.Keys.WriteKeyClient)
	fmt.Println(serverData.CipherDef.Keys.IVClient)

	encrypted := cipher.EncryptDesMessage(msg, serverData.CipherDef.Keys.WriteKeyClient, serverData.CipherDef.Keys.IVClient)

	finishedMsg := []byte{22, 3, 0, 0, 64}
	finishedMsg = append(finishedMsg, encrypted...)

	return finishedMsg

}

func generateRandBytes(len int) []byte {
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	return b

}

// lets end tihs

func generateDSsCert() (*global.Params, error) {
	cwd, err := os.Getwd()

	if err != nil {
		return nil, fmt.Errorf("Cant get root path, err: %v", err)
	}
	parentDir := filepath.Dir(cwd) + "/cert/dsa_test"

	_, err = os.Stat(parentDir)

	if err != nil {
		err = os.Mkdir(parentDir, 0775)
		if err != nil {
			fmt.Printf("problem creating folder, err: %v", err)
		}
	}

	cmd := exec.Command("openssl", "dsaparam", "-out", "dsa_param.pem", "2048")

	cmd.Dir = parentDir

	// Run the command and capture output (if needed)
	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error running openssl command: %v\n", err)
		fmt.Printf("Output: %s\n", string(output))
		return nil, nil
	}

	return nil, nil
}

// Go doesnt support really dss, lets create alternative with terminal
// func generateDssCert() (*global.Params, error) {
// 	cwd, err := os.Getwd()

// 	if err != nil {
// 		return nil, fmt.Errorf("Cant get root path, err: %v", err)
// 	}

// 	parentDir := filepath.Dir(cwd)

// 	var params dsa.Parameters

// 	err = dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N224)

// 	if err != nil {
// 		return nil, fmt.Errorf("problem generting dss params, err: %v", err)
// 	}

// 	var privateKey dsa.PrivateKey

// 	privateKey.Parameters = params

// 	dsa.GenerateKey(&privateKey, rand.Reader)

// 	privateKeyAsn1, err := asn1.Marshal(privateKey)

// 	if err != nil {
// 		return nil, fmt.Errorf("cant convert dsa private key to pkcs8, err:%v", err)
// 	}

// 	if _, err := os.Stat(parentDir + "/cert/dsa_test"); os.IsNotExist(err) {
// 		// 2. Folder does not exist, create it
// 		err := os.Mkdir(parentDir+"/cert/dsa_test", 0755) // Permission mode: 0755 allows read/write/execute for owner and read/execute for others.
// 		if err != nil {
// 			return nil, fmt.Errorf("Error creating folder: %v", err)
// 		}
// 		fmt.Println("Folder created: dsa test")
// 	}

// 	keyFile, err := os.Create(parentDir + "/cert/dsa_test/" + "dsa.pem")

// 	defer keyFile.Close()

// 	pem.Encode(keyFile, &pem.Block{
// 		Type:  "DSA PRIVATE KEY",
// 		Bytes: privateKeyAsn1,
// 	})

// 	template := x509.Certificate{
// 		SerialNumber: big.NewInt(1), // Serial number for the certificate
// 		Subject: pkix.Name{
// 			Organization: []string{"Your Company"},
// 			CommonName:   "localhost",
// 		},
// 		NotBefore:             time.Now(),
// 		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
// 		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
// 		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
// 		BasicConstraintsValid: true,
// 		IsCA:                  true, // Certificate Authority (CA)
// 	}

// 	certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)

// 	if err != nil {
// 		return nil, fmt.Errorf("Problem generting cert der, err: %v", err)
// 	}

// 	certFile, err := os.Create(parentDir + "/cert/dsa_test/" + "cer.pem")

// 	defer keyFile.Close()

// 	pem.Encode(certFile, &pem.Block{
// 		Type:  "CERTIFICATE",
// 		Bytes: certDer,
// 	})

// 	return nil, nil
// }

func generateRsaCert() (*global.Params, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("Problem gettimg root path, err: %v", err)
	}
	parentDir := filepath.Dir(cwd)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("Problem generting rsa private key, err: %v", err)
	}

	if _, err := os.Stat(parentDir + "/cert"); os.IsNotExist(err) {
		// 2. Folder does not exist, create it
		err := os.Mkdir(parentDir+"/cert", 0755) // Permission mode: 0755 allows read/write/execute for owner and read/execute for others.
		if err != nil {
			return nil, fmt.Errorf("Error creating folder: %v", err)
		}
		fmt.Println("Folder created: cert")
	}

	if _, err := os.Stat(parentDir + "/cert/rsa_test"); os.IsNotExist(err) {
		// 2. Folder does not exist, create it
		err := os.Mkdir(parentDir+"/cert/rsa_test", 0755) // Permission mode: 0755 allows read/write/execute for owner and read/execute for others.
		if err != nil {
			return nil, fmt.Errorf("Error creating folder: %v", err)
		}
		fmt.Println("Folder created: rsa test")
	}

	keyFile, err := os.Create(parentDir + "/cert/rsa_test/" + "server.key")

	if err != nil {
		return nil, fmt.Errorf("Problem creating file for key err: %v", err)
	}

	defer keyFile.Close()

	pem.Encode(keyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	fmt.Println("cert created?")

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), // Serial number for the certificate
		Subject: pkix.Name{
			Organization: []string{"Your Company"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // Certificate Authority (CA)
	}

	certDer, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)

	if err != nil {
		return nil, fmt.Errorf("Problem generting cert der, err: %v", err)
	}

	certFile, err := os.Create(parentDir + "/cert/rsa_test/" + "server.crt")

	if err != nil {
		return nil, fmt.Errorf("Problem creating file for cert, err: %v", err)
	}

	defer certFile.Close()

	pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	})

	return &global.Params{
		CertPath: parentDir + "/cert/rsa_test/server.crt",
		KeyPath:  parentDir + "/cert/rsa_test/server.key",
	}, nil

}

func TestHandshake_ADH_DES_CBC3_SHA(t *testing.T) {
	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		StartHttpServer(nil, &wg)
	}()

	wg.Wait()

	conn, err := net.Dial("tcp", "127.0.0.1:4221")

	if err != nil {
		t.Error("problem connectin to server")
	}

	serverData := &ServerData{
		ClientRandom: generateRandBytes(32),
		SSLVersion:   []byte{3, 0},
		CipherDef: cipher.CipherDef{
			Spec: cipher.CipherSpec{
				HashAlgorithm:       cipher.HashAlgorithmSHA,
				KeyExchange:         cipher.KeyExchangeMethodDH,
				HashSize:            20,
				KeyMaterial:         24,
				IvSize:              8,
				EncryptionAlgorithm: cipher.EncryptionAlgorithm3DES,
			},
			CipherSuite: 0x001B,
		},
		ClientSeqNum: []byte{0, 0, 0, 0, 0, 0, 0, 0},
	}
	// TODO: fix becasue it was  passing even we pass mor ethan 32 bytes of random bytes

	clientHello := serverData.generateClientHello()

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientHello[5:])

	_, err = conn.Write(clientHello)

	data, err := readNMessage(3, conn)
	serverHello := data[0]
	serverKeyExchange := data[1]
	serverHelloDone := data[2]

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHello[5:])
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverKeyExchange[5:])
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHelloDone[5:])

	fmt.Println("messages")
	fmt.Println(data)

	err = serverData.verifyServerHello(serverHello)

	if err != nil {
		t.Errorf("\n Problem with serverHello msg, err: %v", err)
	}

	err = serverData.verifyServerKeyExchange(serverKeyExchange)

	if err != nil {
		t.Errorf("\n Problem with serverKeyExchange msg, err: %v", err)
	}

	err = serverData.verifyServerHelloDone(serverHelloDone)

	if err != nil {
		t.Errorf("\n Problem with serverKeyExchange msg, err: %v", err)
	}

	private := big.NewInt(3)

	serverData.CipherDef.DhParams.Private = private

	serverData.computeKeys([]byte{0, 1, 2})

	clientKeyExchangeMsg := []byte{22, 3, 0, 0, 7, 16, 0, 0, 3, 0, 1, 2}
	clientChangeCipher := []byte{20, 3, 0, 0, 1, 1}

	conn.Write(clientKeyExchangeMsg)
	conn.Write(clientChangeCipher)

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientKeyExchangeMsg[5:])

	finishedMsg := serverData.generateClientFinishedMsg()
	fmt.Println("generate client finished msg")
	_, err = conn.Write(finishedMsg)

	if err != nil {
		t.Errorf("Problem writing client finished messgae :%v", err)
	}

	data, err = readNMessage(2, conn)

	serverChangeCipher := data[0]
	serverFinished := data[1]

	err = serverData.verifyServerChangeCipher(serverChangeCipher)

	if err != nil {
		t.Errorf("Problem with verify server change cipher msg:%v", err)
	}

	err = serverData.verifyServerFinished(serverFinished)

	if err != nil {
		t.Errorf("Problem with verify server finished %v", err)
	}
}

func (serverData *ServerData) verifyCertificate(data []byte) (*x509.Certificate, error) {

	// 22 3 0 3 63 11 0 3 59 0 3 56 0 3 53 48
	recType := data[0]
	sslVersion := binary.BigEndian.Uint16((data[1:3]))
	// recLength := binary.BigEndian.Uint16((data[3:5]))
	handshakeType := data[5]
	// recordLength := uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])
	// certsLength := uint32(data[9])<<16 | uint32(data[10])<<8 | uint32(data[11])
	certLength := uint32(data[12])<<16 | uint32(data[13])<<8 | uint32(data[14])
	certificate := data[15 : 15+certLength]

	cert, err := x509.ParseCertificate(certificate)

	if err != nil {
		return nil, err
	}

	fmt.Println("yey parsed cert")
	switch serverData.CipherDef.Spec.SignatureAlgorithm {
	case cipher.SignatureAlgorithmRSA:
		if cert.PublicKeyAlgorithm != x509.RSA {
			return nil, errors.New("Wring encryptiuon algo")
		}
	default:
		fmt.Println("unsported singature in paersing cert")
		os.Exit(1)
	}

	if recType != byte(TLSContentTypeHandshake) {
		return nil, fmt.Errorf("should return tls handshake type")
	}

	if sslVersion != SSL30Version {
		return nil, fmt.Errorf("version should be ssl 3.0")
	}

	if handshakeType != byte(TLSHandshakeMessageCertificate) {
		return nil, fmt.Errorf("Handshake type should be server hello")
	}

	//TODO add condition checking bytes length

	return cert, nil
}

func TestHandshake_EDH_RSA_DES_CBC3_SHA(t *testing.T) {
	var wg sync.WaitGroup

	params, err := generateRsaCert()

	if err != nil {
		t.Errorf("\n problem generating rsa cert, err: %v", err)
	}

	wg.Add(1)

	go func() {
		StartHttpServer(params, &wg)
	}()

	wg.Wait()

	fmt.Println("lets connect?s")
	fmt.Println("lets connect?")
	fmt.Println("lets connect?")
	fmt.Println("lets connect?")

	conn, err := net.Dial("tcp", "127.0.0.1:4221")

	if err != nil {
		t.Error("problem connectin to server")
	}

	serverData := &ServerData{
		ClientRandom: generateRandBytes(32),
		SSLVersion:   []byte{3, 0},
		CipherDef: cipher.CipherDef{
			Spec: cipher.CipherSpec{
				HashAlgorithm:       cipher.HashAlgorithmSHA,
				KeyExchange:         cipher.KeyExchangeMethodDH,
				HashSize:            20,
				KeyMaterial:         24,
				IvSize:              8,
				EncryptionAlgorithm: cipher.EncryptionAlgorithm3DES,
				SignatureAlgorithm:  cipher.SignatureAlgorithmRSA,
			},
			CipherSuite: uint16(cipher.TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA),
		},
		ClientSeqNum: []byte{0, 0, 0, 0, 0, 0, 0, 0},
	}
	// TODO: fix becasue it was  passing even we pass mor ethan 32 bytes of random bytes

	clientHello := serverData.generateClientHello()

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientHello[5:])

	_, err = conn.Write(clientHello)

	if err != nil {
		t.Errorf("Problem writing client hello, err: %v", err)
	}

	data, err := readNMessage(4, conn)

	if err != nil {
		t.Errorf("Problem reading server hello msgs, expected to read 4 messages, err: %v", err)
	}

	serverHello := data[0]
	certificate := data[1]

	serverKeyExchange := data[2]
	serverHelloDone := data[3]

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHello[5:])
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, certificate[5:])
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverKeyExchange[5:])
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHelloDone[5:])

	fmt.Println("messages")
	fmt.Println(data)

	err = serverData.verifyServerHello(serverHello)

	fmt.Println("after verify client hello")

	if err != nil {
		t.Errorf("\n Problem with serverHello msg, err: %v", err)
	}

	_, err = serverData.verifyCertificate(certificate)

	if err != nil {
		t.Errorf("\n Problem with cserver ertificate msg, err: %v", err)
	}

	// TODO: we're missing singature verification
	err = serverData.verifyServerKeyExchange(serverKeyExchange)
	fmt.Println("after verify server key exchange")

	if err != nil {
		t.Errorf("\n Problem with serverKeyExchange msg, err: %v", err)
	}

	err = serverData.verifyServerHelloDone(serverHelloDone)
	fmt.Println("after server hello done")
	if err != nil {
		t.Errorf("\n Problem with serverKeyExchange msg, err: %v", err)
	}

	private := big.NewInt(3)

	serverData.CipherDef.DhParams.Private = private
	fmt.Println("before compute")

	fmt.Println("after ocmpute")

	clientKeyExchangeMsg := []byte{22, 3, 0, 0, 7, 16, 0, 0, 3, 0, 1, 2}
	serverData.computeKeys([]byte{0, 1, 2})
	clientChangeCipher := []byte{20, 3, 0, 0, 1, 1}

	conn.Write(clientKeyExchangeMsg)
	fmt.Println("client key exchange")
	conn.Write(clientChangeCipher)
	fmt.Println("change cipoher")

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientKeyExchangeMsg[5:])

	finishedMsg := serverData.generateClientFinishedMsg()
	fmt.Println("generate client finished msg")
	_, err = conn.Write(finishedMsg)
	fmt.Println("sent client finished")
	if err != nil {
		t.Errorf("Problem writing client finished messgae :%v", err)
	}

	data, err = readNMessage(2, conn)
	if err != nil {
		t.Errorf("Problem reading server chage cipher and server finished msgs, err: %v", err)
	}

	fmt.Println("parsing next")
	serverChangeCipher := data[0]
	serverFinished := data[1]

	err = serverData.verifyServerChangeCipher(serverChangeCipher)

	if err != nil {
		t.Errorf("Problem with verify server change cipher msg:%v", err)
	}

	err = serverData.verifyServerFinished(serverFinished)

	if err != nil {
		t.Errorf("Problem with verify server finished %v", err)
	}

}

func TestHandshake_RSA_DES_CBC3_SHA(t *testing.T) {
	var wg sync.WaitGroup

	params, err := generateRsaCert()

	if err != nil {
		t.Errorf("\n problem generating rsa cert, err: %v", err)
	}

	wg.Add(1)

	go func() {
		StartHttpServer(params, &wg)
	}()

	wg.Wait()

	conn, err := net.Dial("tcp", "127.0.0.1:4221")

	if err != nil {
		t.Error("problem connectin to server")
	}

	serverData := &ServerData{
		ClientRandom: generateRandBytes(32),
		SSLVersion:   []byte{3, 0},
		CipherDef: cipher.CipherDef{
			Spec: cipher.CipherSpec{
				HashAlgorithm:       cipher.HashAlgorithmSHA,
				KeyExchange:         cipher.KeyExchangeMethodRSA,
				HashSize:            20,
				KeyMaterial:         24,
				IvSize:              8,
				EncryptionAlgorithm: cipher.EncryptionAlgorithm3DES,
				SignatureAlgorithm:  cipher.SignatureAlgorithmRSA,
			},
			CipherSuite: uint16(cipher.TLS_CIPHER_SUITE_SSL_RSA_WITH_3DES_EDE_CBC_SHA),
		},
		ClientSeqNum: []byte{0, 0, 0, 0, 0, 0, 0, 0},
	}

	_, err = serverData.ParseCertificate(params.CertPath, params.KeyPath)

	if err != nil {
		t.Errorf("\n cant parse ceritifcate, err: %v", err)
	}

	// TODO: fix becasue it was  passing even we pass mor ethan 32 bytes of random bytes

	clientHello := serverData.generateClientHello()

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientHello[5:])

	_, err = conn.Write(clientHello)

	if err != nil {
		t.Errorf("Problem writing client hello, err: %v", err)
	}

	data, err := readNMessage(3, conn)

	if err != nil {
		t.Errorf("Problem reading server hello msgs, expected to read 4 messages, err: %v", err)
	}

	serverHello := data[0]
	certificate := data[1]

	// serverKeyExchange := data[2]
	serverHelloDone := data[2]

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHello[5:])
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, certificate[5:])
	// serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverKeyExchange[5:])
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHelloDone[5:])

	fmt.Println("messages")
	fmt.Println(data)

	err = serverData.verifyServerHello(serverHello)

	fmt.Println("after verify client hello")

	if err != nil {
		t.Errorf("\n Problem with serverHello msg, err: %v", err)
	}

	cert, err := serverData.verifyCertificate(certificate)

	if err != nil {
		t.Errorf("\n Problem with cserver ertificate msg, err: %v", err)
	}

	err = serverData.verifyServerHelloDone(serverHelloDone)
	fmt.Println("after server hello done")
	if err != nil {
		t.Errorf("\n Problem with serverKeyExchange msg, err: %v", err)
	}

	pubKey := cert.PublicKey

	pubRsaKey, ok := pubKey.(*rsa.PublicKey)

	if !ok {
		t.Errorf("\n can't convert pubKey to rsa pub key, err: %v", err)
	}

	preMasterKey := []byte{3, 0}
	preMasterKey = append(preMasterKey, generateRandBytes(46)...)

	fmt.Println("premasterkey")
	fmt.Println(preMasterKey)

	decrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pubRsaKey, preMasterKey)

	if err != nil {
		t.Errorf("cant encrypted pre masterkey, err: %v", err)
	}

	clientKeyExchangeMsg := []byte{22, 3, 0}
	recordLength := helpers.Int32ToBigEndian(len(decrypted) + 4)
	clientKeyExchangeMsg = append(clientKeyExchangeMsg, recordLength...)
	clientKeyExchangeMsg = append(clientKeyExchangeMsg, 16)
	contentLength, err := helpers.IntTo3BytesBigEndian(len(decrypted))
	if err != nil {
		t.Errorf("cant convert decrypted len to big endian, err:%v", err)
	}
	clientKeyExchangeMsg = append(clientKeyExchangeMsg, contentLength...)
	clientKeyExchangeMsg = append(clientKeyExchangeMsg, decrypted...)
	clientChangeCipher := []byte{20, 3, 0, 0, 1, 1}
	serverData.computeKeys(clientKeyExchangeMsg[9:])

	conn.Write(clientKeyExchangeMsg)
	fmt.Println("client key exchange")
	conn.Write(clientChangeCipher)
	fmt.Println("change cipoher")

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientKeyExchangeMsg[5:])

	finishedMsg := serverData.generateClientFinishedMsg()
	fmt.Println("generate client finished msg")
	_, err = conn.Write(finishedMsg)
	fmt.Println("sent client finished")
	if err != nil {
		t.Errorf("Problem writing client finished messgae :%v", err)
	}

	data, err = readNMessage(2, conn)
	if err != nil {
		t.Errorf("Problem reading server chage cipher and server finished msgs, err: %v", err)
	}

	fmt.Println("parsing next")
	serverChangeCipher := data[0]
	serverFinished := data[1]

	err = serverData.verifyServerChangeCipher(serverChangeCipher)

	if err != nil {
		t.Errorf("Problem with verify server change cipher msg:%v", err)
	}

	err = serverData.verifyServerFinished(serverFinished)

	if err != nil {
		t.Errorf("Problem with verify server finished %v", err)
	}

}

func TestHandshake_EDH_DSS_DES_CBC3_SHA(t *testing.T) {
	// var wg sync.WaitGroup

	_, err := generateDSsCert()
	if err != nil {
		t.Error(err)
	}
	t.Error("fd")

	// if err != nil {
	// 	t.Errorf("\n problem generating rsa cert, err: %v", err)
	// }

	// wg.Add(1)

	// go func() {
	// 	StartHttpServer(params, &wg)
	// }()

	// wg.Wait()

	// fmt.Println("lets connect?s")
	// fmt.Println("lets connect?")
	// fmt.Println("lets connect?")
	// fmt.Println("lets connect?")

	// conn, err := net.Dial("tcp", "127.0.0.1:4221")

	// if err != nil {
	// 	t.Error("problem connectin to server")
	// }

	// serverData := &ServerData{
	// 	ClientRandom: generateRandBytes(32),
	// 	SSLVersion:   []byte{3, 0},
	// 	CipherDef: cipher.CipherDef{
	// 		Spec: cipher.CipherSpec{
	// 			HashAlgorithm:       cipher.HashAlgorithmSHA,
	// 			KeyExchange:         cipher.KeyExchangeMethodDH,
	// 			HashSize:            20,
	// 			KeyMaterial:         24,
	// 			IvSize:              8,
	// 			EncryptionAlgorithm: cipher.EncryptionAlgorithm3DES,
	// 			SignatureAlgorithm:  cipher.SignatureAlgorithmRSA,
	// 		},
	// 		CipherSuite: uint16(cipher.TLS_CIPHER_SUITE_SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA),
	// 	},
	// 	ClientSeqNum: []byte{0, 0, 0, 0, 0, 0, 0, 0},
	// }
	// // TODO: fix becasue it was  passing even we pass mor ethan 32 bytes of random bytes

	// clientHello := serverData.generateClientHello()

	// serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientHello[5:])

	// _, err = conn.Write(clientHello)

	// if err != nil {
	// 	t.Errorf("Problem writing client hello, err: %v", err)
	// }

	// data, err := readNMessage(4, conn)

	// if err != nil {
	// 	t.Errorf("Problem reading server hello msgs, expected to read 4 messages, err: %v", err)
	// }

	// serverHello := data[0]
	// certificate := data[1]

	// serverKeyExchange := data[2]
	// serverHelloDone := data[3]

	// serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHello[5:])
	// serverData.HandshakeMessages = append(serverData.HandshakeMessages, certificate[5:])
	// serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverKeyExchange[5:])
	// serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHelloDone[5:])

	// fmt.Println("messages")
	// fmt.Println(data)

	// err = serverData.verifyServerHello(serverHello)

	// fmt.Println("after verify client hello")

	// if err != nil {
	// 	t.Errorf("\n Problem with serverHello msg, err: %v", err)
	// }

	// _, err = serverData.verifyCertificate(certificate)

	// if err != nil {
	// 	t.Errorf("\n Problem with cserver ertificate msg, err: %v", err)
	// }

	// // TODO: we're missing singature verification
	// err = serverData.verifyServerKeyExchange(serverKeyExchange)
	// fmt.Println("after verify server key exchange")

	// if err != nil {
	// 	t.Errorf("\n Problem with serverKeyExchange msg, err: %v", err)
	// }

	// err = serverData.verifyServerHelloDone(serverHelloDone)
	// fmt.Println("after server hello done")
	// if err != nil {
	// 	t.Errorf("\n Problem with serverKeyExchange msg, err: %v", err)
	// }

	// private := big.NewInt(3)

	// serverData.CipherDef.DhParams.Private = private
	// fmt.Println("before compute")

	// fmt.Println("after ocmpute")

	// clientKeyExchangeMsg := []byte{22, 3, 0, 0, 7, 16, 0, 0, 3, 0, 1, 2}
	// serverData.computeKeys([]byte{0, 1, 2})
	// clientChangeCipher := []byte{20, 3, 0, 0, 1, 1}

	// conn.Write(clientKeyExchangeMsg)
	// fmt.Println("client key exchange")
	// conn.Write(clientChangeCipher)
	// fmt.Println("change cipoher")

	// serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientKeyExchangeMsg[5:])

	// finishedMsg := serverData.generateClientFinishedMsg()
	// fmt.Println("generate client finished msg")
	// _, err = conn.Write(finishedMsg)
	// fmt.Println("sent client finished")
	// if err != nil {
	// 	t.Errorf("Problem writing client finished messgae :%v", err)
	// }

	// data, err = readNMessage(2, conn)
	// if err != nil {
	// 	t.Errorf("Problem reading server chage cipher and server finished msgs, err: %v", err)
	// }

	// fmt.Println("parsing next")
	// serverChangeCipher := data[0]
	// serverFinished := data[1]

	// err = serverData.verifyServerChangeCipher(serverChangeCipher)

	// if err != nil {
	// 	t.Errorf("Problem with verify server change cipher msg:%v", err)
	// }

	// err = serverData.verifyServerFinished(serverFinished)

	// if err != nil {
	// 	t.Errorf("Problem with verify server finished %v", err)
	// }

}
