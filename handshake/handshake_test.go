package handshake

import (
	"crypto/dsa"
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
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"webserver/cipher"
	"webserver/global"
	"webserver/helpers"
)

func (serverData *ServerData) readNMessage(n int, conn net.Conn) ([][]byte, error) {
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

		input := []byte{}
		input = append(input, leftovers...)
		input = append(input, buf[:n]...)
		data, rest, err := serverData.Parser(input)
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
		clientRandomBytes = []byte{102, 213, 128, 42, 254, 171, 56, 146, 68, 181, 149, 44, 224, 124, 234, 207, 212, 237, 164, 74, 10, 169, 28, 204, 174, 157, 81, 130, 0, 0, 0, 0, 4}
	}
	sslVersion := []byte{3, 0}

	if serverData.SSLVersion != nil {
		sslVersion = serverData.SSLVersion
	}

	clientHello := []byte{22}
	clientHello = append(clientHello, sslVersion...)

	cipher := []byte{0, 27}
	if serverData.CipherDef.CipherSuite != 0 {
		cipher = helpers.Int32ToBigEndian(int(serverData.CipherDef.CipherSuite))
	}

	cipherLength := helpers.Int32ToBigEndian(len(cipher))
	sessionLength := []byte{0}
	session := []byte{}
	compressionMethodList := []byte{0}
	compressionMethodListLength := []byte{byte(len(compressionMethodList))}
	contentDataLength := len(sslVersion) + len(clientRandomBytes) + len(sessionLength) + len(session) + len(cipherLength) + len(cipher) + len(compressionMethodListLength) + len(compressionMethodList)
	contentDataBigEndian, err := helpers.IntTo3BytesBigEndian(contentDataLength)
	recordLength := helpers.Int32ToBigEndian(contentDataLength + 4)

	if err != nil {
		fmt.Printf("\n cant convert to big endian while creating client hello msg, err: %v", err)
	}

	clientHello = append(clientHello, recordLength...)
	clientHello = append(clientHello, byte(TLSHandshakeMessageClientHello))
	clientHello = append(clientHello, contentDataBigEndian...)
	clientHello = append(clientHello, sslVersion...)
	clientHello = append(clientHello, clientRandomBytes...)
	clientHello = append(clientHello, sessionLength...)
	clientHello = append(clientHello, session...)
	clientHello = append(clientHello, cipherLength...)
	clientHello = append(clientHello, cipher...)

	clientHello = append(clientHello, compressionMethodListLength...)
	clientHello = append(clientHello, compressionMethodList...)

	return clientHello
}

func (serverData *ServerData) verifyServerHello(data []byte) error {
	recType := data[0]
	sslVersion := binary.BigEndian.Uint16((data[1:3]))
	// recLength := binary.BigEndian.Uint16((data[3:5]))
	handshakeType := data[5]
	// handshakeLength := uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])
	handshakeRandomTime := binary.BigEndian.Uint32((data[11:15]))
	handshakeRandomBytes := data[11:43]
	sessionLength := data[43]
	session := data[44 : 44+sessionLength]
	algorithmIndexStart := 44 + sessionLength
	serverData.ServerRandom = handshakeRandomBytes

	fmt.Println("session")
	fmt.Println(session)

	// 2 for protocol version
	// client random 32
	// 1 for session id
	handshakeAlgorithm := binary.BigEndian.Uint16((data[algorithmIndexStart : algorithmIndexStart+2]))
	handshakeCompression := data[algorithmIndexStart+2]

	if recType != byte(TLSContentTypeHandshake) {
		return fmt.Errorf("should return tls handshake type")
	}

	if sslVersion != uint16(SSL30Version) {
		return fmt.Errorf("version should be ssl 3.0")
	}

	// if recLength != 42 {
	// 	return fmt.Errorf("Record length shuld be 42, we got: %v", recLength)
	// }

	if handshakeType != byte(TLSHandshakeMessageServerHello) {
		return fmt.Errorf("Handshake type should be server hello")
	}

	// if handshakeLength != 38 {
	// 	return fmt.Errorf("Handshake length should be 38")
	// }

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

	if recType != byte(TLSContentTypeHandshake) {
		return fmt.Errorf("should return tls handshake type")
	}

	if sslVersion != uint16(SSL30Version) {
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
	var keyExchangeBytesRead int
	switch serverData.CipherDef.Spec.KeyExchange {
	case cipher.KeyExchangeMethodDH:
		keyExchangeBytesRead, err = serverData.verifyServerKeyExchangeDHParams(data[9:])
	default:
		fmt.Println("unsported key exchange")
		os.Exit(1)
	}
	if serverData.CipherDef.Spec.SignatureAlgorithm == cipher.SignatureAlgorithmAnonymous {
		return err
	}
	signatureIndex := 9 + keyExchangeBytesRead
	keyExchangeParams := data[9:signatureIndex]
	signatureLength := int(binary.BigEndian.Uint16(data[signatureIndex : signatureIndex+2]))
	signature := data[signatureIndex+2:]

	if signatureLength != len(signature) {
		return fmt.Errorf("Expected signature length of: %v, got: %v", signatureLength, len(signature))
	}

	hash := []byte{}

	switch serverData.CipherDef.Spec.SignatureAlgorithm {
	case cipher.SignatureAlgorithmAnonymous:
	case cipher.SignatureAlgorithmRSA:
		md5Hash := signatureHash(md5.New(), serverData.ClientRandom, serverData.ServerRandom, keyExchangeParams)
		shaHash := signatureHash(sha1.New(), serverData.ClientRandom, serverData.ServerRandom, keyExchangeParams)
		hash = append(hash, md5Hash...)
		hash = append(hash, shaHash...)

	case cipher.SignatureAlgorithmDSA:

		shaHash := signatureHash(sha1.New(), serverData.ClientRandom, serverData.ServerRandom, keyExchangeParams)
		hash = append(hash, shaHash...)
	default:
		return fmt.Errorf("unsupported Algorithm: %v", serverData.CipherDef.Spec.SignatureAlgorithm)
	}

	err = serverData.CipherDef.VerifySignedData(hash, signature)

	return err
}

func (serverData *ServerData) verifyServerKeyExchangeDHParams(data []byte) (int, error) {
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
		return 0, fmt.Errorf("Server key exchange is longer than it supposed to be, message: %v, len:%v, expected len: %v ", data, len(data), index)
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

	return index, nil
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

	if sslVersion != uint16(SSL30Version) {
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

	if changeCipherContentSslVersion != uint16(SSL30Version) {
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

	encrypted := cipher.Encrypt3DesMessage(msg, serverData.CipherDef.Keys.WriteKeyClient, serverData.CipherDef.Keys.IVClient)

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

// Generated with cmd as go doesnt support dsa, can't create certificate .crt, there was crypto.Signer lacking
// TODO: we can make it better, same liens are reused over and over
func generateDSsCert() *global.Params {
	cwd, err := os.Getwd()

	if err != nil {
		fmt.Errorf("Cant get root path, err: %v", err)
		os.Exit(1)
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

	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		os.Exit(1)
	}

	cmd = exec.Command("openssl", "gendsa", "-out", "server.key", "dsa_param.pem")

	cmd.Dir = parentDir

	output, err = cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		os.Exit(1)
	}

	cmd = exec.Command("openssl", "req", "-key", "server.key", "-new", "-out", "server.csr")

	cmd.Dir = parentDir

	stdin, err := cmd.StdinPipe()

	if err != nil {
		fmt.Printf("Error opening stdin pipe: %v\n", err)
		os.Exit(1)
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, "US\n")
		io.WriteString(stdin, "California\n")
		io.WriteString(stdin, "San Francisco\n")
		io.WriteString(stdin, "My Company\n")
		io.WriteString(stdin, "San Francisco\n")
		io.WriteString(stdin, "My Company\n")
		io.WriteString(stdin, "My Unit\n")
		io.WriteString(stdin, "example.com\n")
		io.WriteString(stdin, "admin@example.com\n")
	}()

	output, err = cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		os.Exit(1)
	}

	cmd = exec.Command("openssl", "x509", "-signkey", "server.key", "-in", "server.csr", "-req", "-days", "365", "-out", "server.crt")

	cmd.Dir = parentDir

	output, err = cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		os.Exit(1)
	}

	return &global.Params{
		CertPath: parentDir + "/server.crt",
		KeyPath:  parentDir + "/server.key",
	}
}

func generateRsaCert(weak bool) *global.Params {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Problem gettimg root path, err: %v", err)
		os.Exit(1)
	}
	parentDir := filepath.Dir(cwd)

	keyLength := 2048
	if weak {
		keyLength = 512
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keyLength)
	if err != nil {
		fmt.Printf("Problem generting rsa private key, err: %v", err)
		os.Exit(1)
	}

	if _, err := os.Stat(parentDir + "/cert"); os.IsNotExist(err) {
		// 2. Folder does not exist, create it
		err := os.Mkdir(parentDir+"/cert", 0755) // Permission mode: 0755 allows read/write/execute for owner and read/execute for others.
		if err != nil {
			fmt.Printf("Error creating folder: %v", err)
			os.Exit(1)
		}
		fmt.Println("Folder created: cert")
	}

	if _, err := os.Stat(parentDir + "/cert/rsa_test"); os.IsNotExist(err) {
		// 2. Folder does not exist, create it
		err := os.Mkdir(parentDir+"/cert/rsa_test", 0755) // Permission mode: 0755 allows read/write/execute for owner and read/execute for others.
		if err != nil {
			fmt.Printf("Error creating folder: %v", err)
			os.Exit(1)
		}
		fmt.Println("Folder created: rsa test")
	}

	keyFile, err := os.Create(parentDir + "/cert/rsa_test/" + "server.key")

	if err != nil {
		fmt.Printf("Problem creating file for key err: %v", err)
		os.Exit(1)
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
		fmt.Printf("Problem generting cert der, err: %v", err)
		os.Exit(1)
	}

	certFile, err := os.Create(parentDir + "/cert/rsa_test/" + "server.crt")

	if err != nil {
		fmt.Printf("Problem creating file for cert, err: %v", err)
		os.Exit(1)
	}

	defer certFile.Close()

	pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDer,
	})

	return &global.Params{
		CertPath: parentDir + "/cert/rsa_test/server.crt",
		KeyPath:  parentDir + "/cert/rsa_test/server.key",
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
	case cipher.SignatureAlgorithmDSA:
		if cert.PublicKeyAlgorithm != x509.DSA {
			return nil, errors.New("Wring encryptiuon algo")
		}
	default:
		fmt.Println("unsported singature in paersing cert")
		os.Exit(1)
	}

	if recType != byte(TLSContentTypeHandshake) {
		return nil, fmt.Errorf("should return tls handshake type")
	}

	if sslVersion != uint16(SSL30Version) {
		return nil, fmt.Errorf("version should be ssl 3.0")
	}

	if handshakeType != byte(TLSHandshakeMessageCertificate) {
		return nil, fmt.Errorf("Handshake type should be server hello")
	}

	//TODO add condition checking bytes length

	return cert, nil
}

func startServer(params *global.Params) net.Listener {
	var wg sync.WaitGroup

	server := global.Server{
		Wg: &wg,
	}

	wg.Add(1)

	go func() {
		StartHttpServer(params, &server)
	}()

	wg.Wait()

	return server.Conn
}

func getOpenSslDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Error getting home directory: %v\n", err)
		os.Exit(1)
	}

	// TODO dont hardcoded it like this
	return filepath.Join(homeDir, "openssl-0.9.7-copy", "openssl-0.9.7e", "apps")
}

func TestHandshake_ADH_DES_CBC3_SHA(t *testing.T) {
	serverConn := startServer(nil)

	defer serverConn.Close()

	conn, err := net.Dial("tcp", "127.0.0.1:4221")

	if err != nil {
		t.Errorf("problem connecting to server, err:%v", err)
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
				SignatureAlgorithm:  cipher.SignatureAlgorithmAnonymous,
			},
			CipherSuite: 0x001B,
		},
		ClientSeqNum: []byte{0, 0, 0, 0, 0, 0, 0, 0},
	}
	clientHello := serverData.generateClientHello()

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientHello[5:])

	_, err = conn.Write(clientHello)

	if err != nil {
		t.Errorf("problem writing client hello msg, err: %v", err)
	}

	data, err := serverData.readNMessage(3, conn)

	if err != nil {
		t.Errorf("problem reading server hello messages, expected to read 3 msgs, err: %v", err)
	}

	serverHello := data[0]
	serverKeyExchange := data[1]
	serverHelloDone := data[2]

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHello[5:])
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverKeyExchange[5:])
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHelloDone[5:])

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
	_, err = conn.Write(finishedMsg)

	if err != nil {
		t.Errorf("Problem writing client finished messgae :%v", err)
	}

	data, err = serverData.readNMessage(2, conn)

	if err != nil {
		t.Errorf("Problem reading server finished and change cipher msgs, err: %v", err)
	}

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

	// For now all we test if we can pass application data
	// TODO: Comeback later as we implement newer tls, it will be easier to test it

	// applicationDataContent := []byte("string")
	// streamCipher := serverData.generateStreamCipher([]byte{byte(TLSContentTypeHandshake)}, applicationDataContent, serverData.ClientSeqNum, serverData.CipherDef.Keys.MacServer)
	// applicationDataContent = append(applicationDataContent, streamCipher...)

	// applicationDataEncrypted := cipher.Encrypt3DesMessage(applicationDataContent, serverData.CipherDef.Keys.WriteKeyClient, serverData.CipherDef.Keys.IVClient)

	// applicationData := []byte{23, 3, 0}
	// applicationDataEncryptedLength := helpers.Int32ToBigEndian(len(applicationDataEncrypted))
	// applicationData = append(applicationData, applicationDataEncryptedLength...)
	// applicationData = append(applicationData, applicationDataEncrypted...)
	// _, err = conn.Write(applicationData)

	// if err != nil {
	// 	t.Errorf("cant send application data msg, err: %v", err)
	// }
}

func TestHandshake_EDH_RSA_DES_CBC3_SHA(t *testing.T) {

	params := generateRsaCert(false)

	serverConn := startServer(params)

	defer serverConn.Close()

	conn, err := net.Dial("tcp", "127.0.0.1:4221")

	if err != nil {
		t.Errorf("problem connecting to server, err:%v", err)
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
	clientHello := serverData.generateClientHello()

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientHello[5:])

	_, err = conn.Write(clientHello)

	// t.Errorf("fdfddfs")

	if err != nil {
		t.Errorf("Problem writing client hello, err: %v", err)
	}

	data, err := serverData.readNMessage(4, conn)

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

	err = serverData.verifyServerHello(serverHello)

	if err != nil {
		t.Errorf("\n Problem with serverHello msg, err: %v", err)
	}

	cert, err := serverData.verifyCertificate(certificate)

	if err != nil {
		t.Errorf("\n Problem with cserver ertificate msg, err: %v", err)
	}

	pubKey, ok := cert.PublicKey.(*rsa.PublicKey)

	if !ok {
		t.Error("\n can convert pubkey to rsa pub key")
	}

	serverData.CipherDef.Rsa.PublicKey = *pubKey

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

	clientKeyExchangeMsg := []byte{22, 3, 0, 0, 7, 16, 0, 0, 3, 0, 1, 2}
	serverData.computeKeys([]byte{0, 1, 2})
	clientChangeCipher := []byte{20, 3, 0, 0, 1, 1}

	conn.Write(clientKeyExchangeMsg)
	conn.Write(clientChangeCipher)

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientKeyExchangeMsg[5:])

	finishedMsg := serverData.generateClientFinishedMsg()
	_, err = conn.Write(finishedMsg)
	if err != nil {
		t.Errorf("Problem writing client finished messgae :%v", err)
	}

	data, err = serverData.readNMessage(2, conn)
	if err != nil {
		t.Errorf("Problem reading server chage cipher and server finished msgs, err: %v", err)
	}

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
	params := generateRsaCert(false)

	serverConn := startServer(params)

	defer serverConn.Close()

	conn, err := net.Dial("tcp", "127.0.0.1:4221")

	if err != nil {
		t.Errorf("problem connecting to server, err:%v", err)
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

	clientHello := serverData.generateClientHello()

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientHello[5:])

	_, err = conn.Write(clientHello)

	if err != nil {
		t.Errorf("Problem writing client hello, err: %v", err)
	}

	data, err := serverData.readNMessage(3, conn)

	if err != nil {
		t.Errorf("Problem reading server hello msgs, expected to read 4 messages, err: %v", err)
	}

	serverHello := data[0]
	certificate := data[1]
	serverHelloDone := data[2]

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHello[5:])
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, certificate[5:])
	serverData.HandshakeMessages = append(serverData.HandshakeMessages, serverHelloDone[5:])

	err = serverData.verifyServerHello(serverHello)

	if err != nil {
		t.Errorf("\n Problem with serverHello msg, err: %v", err)
	}

	cert, err := serverData.verifyCertificate(certificate)

	if err != nil {
		t.Errorf("\n Problem with cserver ertificate msg, err: %v", err)
	}

	err = serverData.verifyServerHelloDone(serverHelloDone)
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
	conn.Write(clientChangeCipher)

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientKeyExchangeMsg[5:])

	finishedMsg := serverData.generateClientFinishedMsg()
	_, err = conn.Write(finishedMsg)

	if err != nil {
		t.Errorf("Problem writing client finished messgae :%v", err)
	}

	data, err = serverData.readNMessage(2, conn)
	if err != nil {
		t.Errorf("Problem reading server chage cipher and server finished msgs, err: %v", err)
	}

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
	params := generateDSsCert()

	serverConn := startServer(params)

	defer serverConn.Close()

	conn, err := net.Dial("tcp", "127.0.0.1:4221")

	if err != nil {
		t.Errorf("problem connecting to server, err:%v", err)
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
				SignatureAlgorithm:  cipher.SignatureAlgorithmDSA,
			},
			CipherSuite: uint16(cipher.TLS_CIPHER_SUITE_SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA),
		},
		ClientSeqNum: []byte{0, 0, 0, 0, 0, 0, 0, 0},
	}
	clientHello := serverData.generateClientHello()

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientHello[5:])

	_, err = conn.Write(clientHello)

	if err != nil {
		t.Errorf("Problem writing client hello, err: %v", err)
	}

	data, err := serverData.readNMessage(4, conn)

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

	err = serverData.verifyServerHello(serverHello)

	if err != nil {
		t.Errorf("\n Problem with serverHello msg, err: %v", err)
	}

	cert, err := serverData.verifyCertificate(certificate)

	if err != nil {
		t.Errorf("\n Problem with server certificate msg, err: %v", err)
	}

	pubKey, ok := cert.PublicKey.(*dsa.PublicKey)

	if !ok {
		t.Error("\n can convert pubkey to dsa pub key")
	}

	serverData.CipherDef.Dsa.PublicKey = *pubKey

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

	clientKeyExchangeMsg := []byte{22, 3, 0, 0, 7, 16, 0, 0, 3, 0, 1, 2}
	serverData.computeKeys([]byte{0, 1, 2})
	clientChangeCipher := []byte{20, 3, 0, 0, 1, 1}

	conn.Write(clientKeyExchangeMsg)
	conn.Write(clientChangeCipher)

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, clientKeyExchangeMsg[5:])

	finishedMsg := serverData.generateClientFinishedMsg()
	_, err = conn.Write(finishedMsg)
	if err != nil {
		t.Errorf("Problem writing client finished messgae :%v", err)
	}

	data, err = serverData.readNMessage(2, conn)
	if err != nil {
		t.Errorf("Problem reading server chage cipher and server finished msgs, err: %v", err)
	}

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

func TestHandshakeOpenSSL_ADH_DES_CBC3_SHA(t *testing.T) {
	params := generateRsaCert(false)

	serverConn := startServer(params)

	defer serverConn.Close()

	cmd := exec.Command("./openssl", "s_client", "-connect", "127.0.0.1:4221", "-ssl3", "-cipher", "ADH-DES-CBC3-SHA", "-reconnect")

	cmd.Dir = getOpenSslDir()

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		return
	}

	fmt.Printf("\n output: %v", string(output))

	if !strings.Contains(string(output), "New, TLSv1/SSLv3, Cipher is ADH-DES-CBC3-SHA") {
		t.Error("handshake failed")
	}

	if !strings.Contains(string(output), "Reused, TLSv1/SSLv3, Cipher is ADH-DES-CBC3-SHA") {
		t.Error("handshake failed")
	}

}
func TestHandshakeOpenSSL_ADH_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	serverConn := startServer(params)

	defer serverConn.Close()

	cmd := exec.Command("./openssl", "s_client", "-connect", "127.0.0.1:4221", "-ssl3", "-cipher", "ADH-DES-CBC-SHA", "-reconnect")

	cmd.Dir = getOpenSslDir()

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		return
	}

	fmt.Printf("\n output: %v", string(output))

	if !strings.Contains(string(output), "New, TLSv1/SSLv3, Cipher is ADH-DES-CBC-SHA") {
		t.Error("handshake failed")
	}

	if !strings.Contains(string(output), "Reused, TLSv1/SSLv3, Cipher is ADH-DES-CBC-SHA") {
		t.Error("handshake failed")
	}

}

func TestHandshakeOpenSSL_EDH_RSA_DES_CBC3_SHA(t *testing.T) {
	params := generateRsaCert(false)

	serverConn := startServer(params)

	defer serverConn.Close()

	cmd := exec.Command("./openssl", "s_client", "-connect", "127.0.0.1:4221", "-ssl3", "-cipher", "EDH-RSA-DES-CBC3-SHA", "-reconnect")

	cmd.Dir = getOpenSslDir()

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		return
	}

	if !strings.Contains(string(output), "New, TLSv1/SSLv3, Cipher is EDH-RSA-DES-CBC3-SHA") {
		t.Error("handshake failed")
	}

	if !strings.Contains(string(output), "Reused, TLSv1/SSLv3, Cipher is EDH-RSA-DES-CBC3-SHA") {
		t.Error("handshake failed")
	}

}

func TestHandshakeOpenSSL_EDH_RSA_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	serverConn := startServer(params)

	defer serverConn.Close()

	cmd := exec.Command("./openssl", "s_client", "-connect", "127.0.0.1:4221", "-ssl3", "-cipher", "EDH-RSA-DES-CBC-SHA", "-reconnect")

	cmd.Dir = getOpenSslDir()

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		return
	}

	if !strings.Contains(string(output), "New, TLSv1/SSLv3, Cipher is EDH-RSA-DES-CBC-SHA") {
		t.Error("handshake failed")
	}

	if !strings.Contains(string(output), "Reused, TLSv1/SSLv3, Cipher is EDH-RSA-DES-CBC-SHA") {
		t.Error("handshake failed")
	}

}

func TestHandshakeOpenSSL_DES_CBC3_SHA(t *testing.T) {
	params := generateRsaCert(false)

	serverConn := startServer(params)

	defer serverConn.Close()

	cmd := exec.Command("./openssl", "s_client", "-connect", "127.0.0.1:4221", "-ssl3", "-cipher", "DES-CBC3-SHA", "-reconnect")

	cmd.Dir = getOpenSslDir()

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		return
	}

	if !strings.Contains(string(output), "New, TLSv1/SSLv3, Cipher is DES-CBC3-SHA") {
		t.Error("handshake failed")
	}

	if !strings.Contains(string(output), "Reused, TLSv1/SSLv3, Cipher is DES-CBC3-SHA") {
		t.Error("handshake failed")
	}

}

func TestHandshakeOpenSSL_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	serverConn := startServer(params)

	defer serverConn.Close()

	cmd := exec.Command("./openssl", "s_client", "-connect", "127.0.0.1:4221", "-ssl3", "-cipher", "DES-CBC-SHA", "-reconnect")

	cmd.Dir = getOpenSslDir()

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		return
	}

	if !strings.Contains(string(output), "New, TLSv1/SSLv3, Cipher is DES-CBC-SHA") {
		t.Error("handshake failed")
	}

	if !strings.Contains(string(output), "Reused, TLSv1/SSLv3, Cipher is DES-CBC-SHA") {
		t.Error("handshake failed")
	}

}

func TestHandshakeOpenSSL_EDH_DSS_DES_CBC3_SHA(t *testing.T) {
	params := generateDSsCert()

	serverConn := startServer(params)

	defer serverConn.Close()

	cmd := exec.Command("./openssl", "s_client", "-connect", "127.0.0.1:4221", "-ssl3", "-cipher", "EDH-DSS-DES-CBC3-SHA", "-reconnect")

	cmd.Dir = getOpenSslDir()

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		return
	}

	if !strings.Contains(string(output), "New, TLSv1/SSLv3, Cipher is EDH-DSS-DES-CBC3-SHA") {
		t.Error("handshake failed")
	}
	if !strings.Contains(string(output), "Reused, TLSv1/SSLv3, Cipher is EDH-DSS-DES-CBC3-SHA") {
		t.Error("handshake failed")
	}
}

func TestHandshakeOpenSSL_EDH_DSS_DES_CBC_SHA(t *testing.T) {
	params := generateDSsCert()

	serverConn := startServer(params)

	defer serverConn.Close()

	cmd := exec.Command("./openssl", "s_client", "-connect", "127.0.0.1:4221", "-ssl3", "-cipher", "EDH-DSS-DES-CBC-SHA", "-reconnect")

	cmd.Dir = getOpenSslDir()

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		return
	}

	if !strings.Contains(string(output), "New, TLSv1/SSLv3, Cipher is EDH-DSS-DES-CBC-SHA") {
		t.Error("handshake failed")
	}
	if !strings.Contains(string(output), "Reused, TLSv1/SSLv3, Cipher is EDH-DSS-DES-CBC-SHA") {
		t.Error("handshake failed")
	}
}

func TestHandshakeOpenSSL_EXP_EDH_RSA_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	serverConn := startServer(params)

	defer serverConn.Close()

	cmd := exec.Command("./openssl", "s_client", "-connect", "127.0.0.1:4221", "-ssl3", "-cipher", "EXP-EDH-RSA-DES-CBC-SHA", "-reconnect")

	cmd.Dir = getOpenSslDir()

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		return
	}

	if !strings.Contains(string(output), "New, TLSv1/SSLv3, Cipher is EXP-EDH-RSA-DES-CBC-SHA") {
		t.Error("handshake failed")
	}

	if !strings.Contains(string(output), "Reused, TLSv1/SSLv3, Cipher is EXP-EDH-RSA-DES-CBC-SHA") {
		t.Error("handshake failed")
	}

}

func TestHandshakeOpenSSL_EXP_EDH_DSS_DES_CBC_SHA(t *testing.T) {
	params := generateDSsCert()

	serverConn := startServer(params)

	defer serverConn.Close()

	cmd := exec.Command("./openssl", "s_client", "-connect", "127.0.0.1:4221", "-ssl3", "-cipher", "EXP-EDH-DSS-DES-CBC-SHA", "-reconnect")

	cmd.Dir = getOpenSslDir()

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		return
	}

	if !strings.Contains(string(output), "New, TLSv1/SSLv3, Cipher is EXP-EDH-DSS-DES-CBC-SHA") {
		t.Error("handshake failed")
	}
	if !strings.Contains(string(output), "Reused, TLSv1/SSLv3, Cipher is EXP-EDH-DSS-DES-CBC-SHA") {
		t.Error("handshake failed")
	}
}

func TestHandshakeOpenSSL_EXP_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(true)

	serverConn := startServer(params)
	defer serverConn.Close()
	cmd := exec.Command("./openssl", "s_client", "-connect", "127.0.0.1:4221", "-ssl3", "-cipher", "EXP-DES-CBC-SHA", "-reconnect")

	cmd.Dir = getOpenSslDir()

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		return
	}

	if !strings.Contains(string(output), "New, TLSv1/SSLv3, Cipher is EXP-DES-CBC-SHA") {
		t.Error("handshake failed")
	}

	if !strings.Contains(string(output), "Reused, TLSv1/SSLv3, Cipher is EXP-DES-CBC-SHA") {
		t.Error("handshake failed")
	}

}
