package handshake

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
	"handshakeServer/cipher"
	"handshakeServer/helpers"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

var OpenSSLVersion = "openssl-0.9.7e"
var Address = "127.0.0.1"
var Port = "4221"

func (serverData *ServerData) readNMessage(n int, conn net.Conn) ([][]byte, error) {
	messages := [][]byte{}
	leftovers := []byte{}
	for len(messages) < n {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)

		if err != nil {
			return [][]byte{}, fmt.Errorf("cant read message: %v", err)

		}

		input := []byte{}
		input = append(input, leftovers...)
		input = append(input, buf[:n]...)
		data, rest, err := serverData.Parser(input)
		leftovers = rest
		if err != nil {
			fmt.Printf("\n problem parsing, err %v", err)
			os.Exit(1)
		}
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

	if serverData.Version != nil {
		sslVersion = serverData.Version
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
		os.Exit(1)
	}

	clientHello = append(clientHello, recordLength...)
	clientHello = append(clientHello, byte(HandshakeMessageClientHello))
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

	if reflect.DeepEqual(serverData.session, session) {
		return fmt.Errorf("Session are different, expecting: %v, got:%v", serverData.session, session)
	}

	// 2 for protocol version
	// client random 32
	// 1 for session id
	handshakeAlgorithm := binary.BigEndian.Uint16((data[algorithmIndexStart : algorithmIndexStart+2]))
	handshakeCompression := data[algorithmIndexStart+2]

	if recType != byte(ContentTypeHandshake) {
		return fmt.Errorf("should return tls handshake type")
	}

	if sslVersion != uint16(SSL30Version) {
		return fmt.Errorf("version should be ssl 3.0")
	}

	if handshakeType != byte(HandshakeMessageServerHello) {
		return fmt.Errorf("Handshake type should be server hello")
	}

	currentTime := time.Now().Unix()

	if int64(handshakeRandomTime)-int64(currentTime) > 1000 {
		return fmt.Errorf("Handshkae invalid time, or really slow response")
	}

	if handshakeAlgorithm != uint16(serverData.CipherDef.CipherSuite) {
		return fmt.Errorf("Expected algorithm: %v, got:%v", cipher.CIPHER_SUITE_SSL_DH_anon_WITH_3DES_EDE_CBC_SHA, handshakeAlgorithm)
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

	if recType != byte(ContentTypeHandshake) {
		return fmt.Errorf("should return tls handshake type")
	}

	if sslVersion != uint16(SSL30Version) {
		return fmt.Errorf("version should be ssl 3.0")
	}

	if handshakeType != byte(HandshakeMessageServerKeyExchange) {
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

	p := dhParams[0]
	q := dhParams[1]
	serverPublic := dhParams[2]

	serverData.CipherDef.DhParams = cipher.DhParams{
		P:            p,
		Q:            q,
		ClientPublic: serverPublic, // Its confusing because i've written program to be use as server, and now we're resuing functions as a client, i won't fix it as i will be only focusing to test it with openssl.
	}

	return index, nil
}

func (serverData *ServerData) verifyServerHelloDone(data []byte) error {
	recType := data[0]
	sslVersion := binary.BigEndian.Uint16((data[1:3]))
	recLength := binary.BigEndian.Uint16((data[3:5]))
	handshakeType := data[5]
	handshakeLength := uint32(data[6])<<16 | uint32(data[7])<<8 | uint32(data[8])

	if recType != byte(ContentTypeHandshake) {
		return fmt.Errorf("should return tls handshake type")
	}

	if sslVersion != uint16(SSL30Version) {
		return fmt.Errorf("version should be ssl 3.0")
	}

	if recLength != 4 {
		return fmt.Errorf("Record length shuld be 4")
	}

	if handshakeType != byte(HandshakeMessageServerHelloDone) {
		return fmt.Errorf("Handshake type should be server hello")
	}

	if handshakeLength != 0 {
		return fmt.Errorf("Handshake length should be 0")
	}
	return nil
}

func (serverData *ServerData) computeKeys(data []byte) error {
	preMasterSecret, err := serverData.CipherDef.ComputeMasterSecret(data)
	if err != nil {
		return err
	}

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

	masterKey := s3_prf(preMasterSecret, masterKeySeed, MASTER_SECRET_LENGTH)

	keyBlock := s3_prf(masterKey, keyBlockSeed, keyBlockLen)

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

	return nil
}

func (serverData *ServerData) verifyServerChangeCipher(data []byte) error {
	if len(data) < 6 {
		return fmt.Errorf("server change cipher msg should be at least of length: 6")
	}
	changeCipherContentType := data[0]
	changeCipherContentSslVersion := binary.BigEndian.Uint16(data[1:3])
	changeCipherContentLength := binary.BigEndian.Uint16(data[3:5])
	changeCipherContentData := data[5]

	if changeCipherContentType != byte(ContentTypeChangeCipherSpec) {
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
	decryptedServerFinishedData, err := serverData.CipherDef.DecryptMessage(encryptedServerFinishedData, serverData.CipherDef.Keys.WriteKeyServer, serverData.CipherDef.Keys.IVServer)

	if err != nil {
		return err
	}

	decryptedServerFinishedDataNoHeader := decryptedServerFinishedData[4:]

	serverBytes := helpers.Int64ToBIgEndian(int64(serverSender))
	serverMd5Hash := decryptedServerFinishedDataNoHeader[:16]
	serverShaHash := decryptedServerFinishedDataNoHeader[16:36]
	serverCipher := decryptedServerFinishedDataNoHeader[36:]

	md5Hash := serverData.S3GenerateFinishedHandshakeMac(md5.New(), serverBytes, serverData.HandshakeMessages) // -1 without last message witch is client verify
	shaHash := serverData.S3GenerateFinishedHandshakeMac(sha1.New(), serverBytes, serverData.HandshakeMessages)
	cipherData := decryptedServerFinishedData[:4]
	cipherData = append(cipherData, md5Hash...)
	cipherData = append(cipherData, shaHash...)
	streamCipher := serverData.S3generateStreamCipher([]byte{byte(ContentTypeHandshake)}, cipherData, serverData.ClientSeqNum, serverData.CipherDef.Keys.MacServer)

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

func (serverData *ServerData) generateClientFinishedMsg() ([]byte, error) {

	clientBytes := helpers.Int64ToBIgEndian(int64(ClientSender))
	md5Hash := serverData.S3GenerateFinishedHandshakeMac(md5.New(), clientBytes, serverData.HandshakeMessages) // -1 without last message witch is client verify
	shaHash := serverData.S3GenerateFinishedHandshakeMac(sha1.New(), clientBytes, serverData.HandshakeMessages)

	hashMessages := append(md5Hash, shaHash...)

	msg := []byte{20, 0, 0, 36}
	msg = append(msg, hashMessages...)

	serverData.HandshakeMessages = append(serverData.HandshakeMessages, msg)

	streamCipher := serverData.S3generateStreamCipher([]byte{byte(ContentTypeHandshake)}, msg, serverData.ClientSeqNum, serverData.CipherDef.Keys.MacClient)

	msg = append(msg, streamCipher...)

	serverIV := serverData.CipherDef.Keys.IVServer

	encrypted, err := serverData.CipherDef.EncryptMessage(msg, serverData.CipherDef.Keys.WriteKeyClient, serverData.CipherDef.Keys.IVClient)

	// We implemented in the way that our program is always the server, so we're assigin iv to serverIv variable, but in the test we're client so there is a problem here, i don't think im gonna fix this as don't plan to implement program to be client.
	serverData.CipherDef.Keys.IVClient = serverData.CipherDef.Keys.IVServer
	serverData.CipherDef.Keys.IVServer = serverIV

	if err != nil {
		return nil, err
	}

	finishedMsg := []byte{22, 3, 0, 0, 64}
	finishedMsg = append(finishedMsg, encrypted...)

	return finishedMsg, nil

}

func generateRandBytes(len int) []byte {
	b := make([]byte, len)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error generting random bytes:", err)
		os.Exit(1)
	}

	return b

}

// Generated with cmd as go doesnt support dsa, can't create certificate because there is no crypto.Signer implementation
// TODO: we can make it better, same liens are reused over and over
func generateDSsCert() *HttpServerCertParam {
	cwd, err := os.Getwd()

	if err != nil {
		fmt.Errorf("cant get root path, err: %v", err)
		os.Exit(1)
	}
	parentDir := filepath.Dir(cwd) + "/cert/dsa_test"

	_, err = os.Stat(parentDir)

	if err != nil {
		err = os.Mkdir(parentDir, 0775)
		if err != nil {
			fmt.Printf("problem creating folder, err: %v", err)
			os.Exit(1)
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

	return &HttpServerCertParam{
		CertPath: parentDir + "/server.crt",
		KeyPath:  parentDir + "/server.key",
	}
}

func generateRsaDHCert() *HttpServerCertParam {
	cwd, err := os.Getwd()

	if err != nil {
		fmt.Errorf("cant get root path, err: %v", err)
		os.Exit(1)
	}
	parentDir := filepath.Dir(cwd) + "/cert/rsa_dh_test"

	_, err = os.Stat(parentDir)

	if err != nil {
		err = os.Mkdir(parentDir, 0775)
		if err != nil {
			fmt.Printf("problem creating folder, err: %v", err)
			os.Exit(1)
		}
	}

	cmd := exec.Command("openssl", "genrsa", "-out", "CAkey.pem", "1024")

	cmd.Dir = parentDir

	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		os.Exit(1)
	}

	cmd = exec.Command("openssl", "req", "-x509", "-new", "-nodes", "-key", "CAkey.pem", "-sha256", "-days", "3650", "-out", "CAcert.pem")

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

	cmd = exec.Command("openssl", "dhparam", "-out", "dhparam.pem", "1024")

	cmd.Dir = parentDir

	output, err = cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		os.Exit(1)
	}

	cmd = exec.Command("openssl", "genpkey", "-paramfile", "dhparam.pem", "-out", "dhkey.pem")

	cmd.Dir = parentDir

	output, err = cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		os.Exit(1)
	}

	cmd = exec.Command("openssl", "pkey", "-in", "dhkey.pem", "-pubout", "-out", "dhpubkey.pem")

	cmd.Dir = parentDir

	output, err = cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		os.Exit(1)
	}

	cmd = exec.Command("openssl", "genrsa", "-out", "rsakey.pem", "2048")
	cmd.Dir = parentDir

	output, err = cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		os.Exit(1)
	}

	cmd = exec.Command("openssl", "req", "-new", "-key", "rsakey.pem", "-out", "rsa.csr")
	cmd.Dir = parentDir

	stdin, err = cmd.StdinPipe()

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

	cmd = exec.Command("openssl", "x509", "-req", "-in", "rsa.csr", "-CA", "CAcert.pem", "-CAkey", "CAkey.pem", "-force_pubkey", "dhpubkey.pem", "-out", "dhcert.pem", "-CAcreateserial")
	cmd.Dir = parentDir

	output, err = cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error opening stdin pipe: %v\n", err)
		os.Exit(1)
	}

	return &HttpServerCertParam{
		CertPath: parentDir + "/dhcert.pem",
		KeyPath:  parentDir + "/dhkey.pem",
	}
}

func generateRsaCert(weak bool) *HttpServerCertParam {
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
	}

	if _, err := os.Stat(parentDir + "/cert/rsa_test"); os.IsNotExist(err) {
		// 2. Folder does not exist, create it
		err := os.Mkdir(parentDir+"/cert/rsa_test", 0755) // Permission mode: 0755 allows read/write/execute for owner and read/execute for others.
		if err != nil {
			fmt.Printf("Error creating folder: %v", err)
			os.Exit(1)
		}
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

	return &HttpServerCertParam{
		CertPath: parentDir + "/cert/rsa_test/server.crt",
		KeyPath:  parentDir + "/cert/rsa_test/server.key",
	}

}

func (serverData *ServerData) verifyCertificate(data []byte) (*x509.Certificate, error) {

	if len(data) < 15 {
		return nil, fmt.Errorf("Certificate data should be at lest of length: 15")
	}

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

	if recType != byte(ContentTypeHandshake) {
		return nil, fmt.Errorf("should return tls handshake type")
	}

	if sslVersion != uint16(SSL30Version) {
		return nil, fmt.Errorf("version should be ssl 3.0")
	}

	if handshakeType != byte(HandshakeMessageCertificate) {
		return nil, fmt.Errorf("Handshake type should be server hello")
	}

	//TODO add condition checking bytes length

	return cert, nil
}

func startServer(cert *HttpServerCertParam, version Version) *HttpServer {
	if version == TLS11Version || version == TLS12Version {
		OpenSSLVersion = "openssl-1.0.2u"
	} else if version == TLS10Version || version == SSL30Version {
		OpenSSLVersion = "openssl-0.9.7e"
	}
	versionByte := make([]byte, 2)
	binary.BigEndian.PutUint16(versionByte, uint16(version))

	server, err := CreateServer(
		WithAddress(Address, Port),
		WithCertificate(cert),
		WithSSLVersion(versionByte),
	)

	if err != nil {
		fmt.Printf("cant start the server, err: %v", err)
		os.Exit(1)
	}

	return server
}

func StopServer(server HttpServer) {
	server.CloseHttpServer()
}

func getOpenSslDir() string {
	dir, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error getting home directory: %v\n", err)
		os.Exit(1)
	}

	return filepath.Join(dir, "../openssl", OpenSSLVersion, "apps")
}

func runOpensslCommand(args []string) error {
	cmdArgs := []string{"s_client"}
	cmdArgs = append(cmdArgs, "-connect")
	cmdArgs = append(cmdArgs, Address+":"+Port)
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command("./openssl", cmdArgs...)

	var cipher string

	for i, v := range args {
		if v == "-cipher" {
			cipher = args[i+1]
		}
	}

	cmd.Dir = getOpenSslDir()

	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("Error running openssl command: %v\n, output: %s \n", err, output)
	}

	if !strings.Contains(string(output), "New, TLSv1/SSLv3, Cipher is "+cipher) {
		return fmt.Errorf("handshake failed, can't establish new handshake")
	}

	if !strings.Contains(string(output), "Reused, TLSv1/SSLv3, Cipher is "+cipher) {
		return fmt.Errorf("handshake failed, cant reused handshake")
	}

	return nil
}

func TestHandshakeOpenS3_ADH_DES_CBC3_SHA(t *testing.T) {
	server := startServer(nil, SSL30Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "ADH-DES-CBC3-SHA", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenS3_EDH_RSA_DES_CBC3_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, SSL30Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-RSA-DES-CBC3-SHA", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}

}

func TestHandshakeOpenS3_EDH_RSA_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, SSL30Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-RSA-DES-CBC-SHA", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenS3_DES_CBC3_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, SSL30Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DES-CBC3-SHA", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}

}

func TestHandshakeOpenS3_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert(false)

	server := startServer(params, SSL30Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DES-CBC-SHA", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}

}

func TestHandshakeOpenS3_EDH_DSS_DES_CBC3_SHA(t *testing.T) {
	params := generateDSsCert()

	server := startServer(params, SSL30Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-DSS-DES-CBC3-SHA", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenS3_EDH_DSS_DES_CBC_SHA(t *testing.T) {
	params := generateDSsCert()

	server := startServer(params, SSL30Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-DSS-DES-CBC-SHA", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenS3_RC4_SHA(t *testing.T) {
	params := generateRsaCert(true)

	server := startServer(params, SSL30Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "RC4-SHA", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}

}

func TestHandshakeOpenS3_RC4_MD5(t *testing.T) {
	params := generateRsaCert(true)

	server := startServer(params, SSL30Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "RC4-MD5", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}

}

func TestHandshakeOpenS3_ADH_RC4_MD5(t *testing.T) {
	server := startServer(nil, SSL30Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "ADH-RC4-MD5", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}

}

func TestHandshakeOpenS3_EXP_RC2_CBC_MD5(t *testing.T) {
	params := generateRsaCert(true)

	server := startServer(params, SSL30Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EXP-RC2-CBC-MD5", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}

}
