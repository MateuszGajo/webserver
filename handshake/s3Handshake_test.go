package handshake

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"handshakeServer/cipher"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var OpenSSLVersion = "openssl-0.9.7e"
var Address = "127.0.0.1"
var Port = "4221"

// Generated with cmd as go doesnt support dsa, can't create certificate because there is no crypto.Signer implementation
// TODO: we can make it better, same liens are reused over and over
func generateDSsCert() *HttpServerCertParam {
	cwd, err := os.Getwd()

	if err != nil {
		fmt.Errorf("cant get root path, err: %v", err)
		os.Exit(1)
	}
	parentDir := filepath.Dir(cwd) + "/cert/dsa_test"

	certPath := parentDir + "/server.crt"
	keyPath := parentDir + "/server.key"

	if err := checkIfFileExists(certPath); err == nil {
		if err := checkIfFileExists(keyPath); err == nil {
			return &HttpServerCertParam{
				CertPath: parentDir + "/server.crt",
				KeyPath:  parentDir + "/server.key",
			}
		}
	}

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

	certPath := parentDir + "/dhcert.pem"
	keyPath := parentDir + "/dhkey.pem"

	if err := checkIfFileExists(certPath); err == nil {
		if err := checkIfFileExists(keyPath); err == nil {
			return &HttpServerCertParam{
				CertPath: parentDir + "/dhcert.pem",
				KeyPath:  parentDir + "/dhkey.pem",
			}
		}
	}

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

func generateDssDHCert() *HttpServerCertParam {
	cwd, err := os.Getwd()

	if err != nil {
		fmt.Errorf("cant get root path, err: %v", err)
		os.Exit(1)
	}
	parentDir := filepath.Dir(cwd) + "/cert/dss_dh_test"

	certPath := parentDir + "/dssdhcert.pem"
	keyPath := parentDir + "/dhkey.pem"

	if err := checkIfFileExists(certPath); err == nil {
		if err := checkIfFileExists(keyPath); err == nil {
			return &HttpServerCertParam{
				CertPath: parentDir + "/dssdhcert.pem",
				KeyPath:  parentDir + "/dhkey.pem",
			}
		}
	}

	_, err = os.Stat(parentDir)

	if err != nil {
		err = os.Mkdir(parentDir, 0775)
		if err != nil {
			fmt.Printf("problem creating folder, err: %v", err)
			os.Exit(1)
		}
	}

	cmd := exec.Command("openssl", "dsaparam", "-out", "dsaparam.pem", "2048")

	cmd.Dir = parentDir

	output, err := cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		os.Exit(1)
	}

	cmd = exec.Command("openssl", "gendsa", "-out", "CAkey.pem", "dsaparam.pem")

	cmd.Dir = parentDir

	output, err = cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		os.Exit(1)
	}

	cmd = exec.Command("openssl", "req", "-x509", "-new", "-key", "CAkey.pem", "-sha256", "-days", "3650", "-out", "CAcert.pem")

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

	cmd = exec.Command("openssl", "gendsa", "-out", "dsakey.pem", "dsaparam.pem")
	cmd.Dir = parentDir

	output, err = cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error running openssl command: %v\n, output: %s \n", err, output)
		os.Exit(1)
	}

	cmd = exec.Command("openssl", "req", "-new", "-key", "dsakey.pem", "-out", "dsa.csr")
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

	cmd = exec.Command("openssl", "x509", "-req", "-in", "dsa.csr", "-CA", "CAcert.pem", "-CAkey", "CAkey.pem", "-force_pubkey", "dhpubkey.pem", "-out", "dssdhcert.pem", "-CAcreateserial")
	cmd.Dir = parentDir

	output, err = cmd.CombinedOutput()

	if err != nil {
		fmt.Printf("Error opening stdin pipe: %v\n", err)
		os.Exit(1)
	}

	return &HttpServerCertParam{
		CertPath: parentDir + "/dssdhcert.pem",
		KeyPath:  parentDir + "/dhkey.pem",
	}
}

func checkIfFileExists(filePath string) error {
	if _, err := os.Stat(filePath); err == nil {
		return nil
	} else if os.IsNotExist(err) {
		return fmt.Errorf("File %s does not exist.\n", filePath)
	} else {
		return fmt.Errorf("Error checking file: %v\n", err)
	}

}

func generateRsaCert() *HttpServerCertParam {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("Problem gettimg root path, err: %v", err)
		os.Exit(1)
	}
	parentDir := filepath.Dir(cwd)

	certPath := parentDir + "/cert/rsa_test/server.crt"
	KeyPath := parentDir + "/cert/rsa_test/server.key"

	if err := checkIfFileExists(certPath); err == nil {
		if err := checkIfFileExists(KeyPath); err == nil {
			return &HttpServerCertParam{
				CertPath: parentDir + "/cert/rsa_test/server.crt",
				KeyPath:  parentDir + "/cert/rsa_test/server.key",
			}
		}
	}

	keyLength := 2048

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
	} else if version == TLS13Version {
		OpenSSLVersion = "openssl-3.0.11"
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
	var reconnect bool = false
	var tls13 bool = false

	for i, v := range args {
		if v == "-cipher" {
			cipher = args[i+1]
		}
		if v == "-reconnect" {
			reconnect = true
		}
		if v == "-tls1_3" {
			tls13 = true
		}
	}

	cmd.Dir = getOpenSslDir()

	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf("Error running openssl command: %v\n, output: %s \n", err, output)
	}

	expectedConnectMsgVersion := "TLSv1/SSLv3"

	if tls13 {
		expectedConnectMsgVersion = "TLSv1.3"
	}

	fmt.Println(string(output))
	fmt.Println("New, " + expectedConnectMsgVersion + ", Cipher is " + cipher)

	if !strings.Contains(string(output), "New, "+expectedConnectMsgVersion+", Cipher is "+cipher) {
		return fmt.Errorf("handshake failed, can't establish new handshake")
	}

	if reconnect {
		if !strings.Contains(string(output), "Reused, "+expectedConnectMsgVersion+", Cipher is "+cipher) {
			return fmt.Errorf("handshake failed, cant reused handshake")
		}
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
	params := generateRsaCert()

	server := startServer(params, SSL30Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-RSA-DES-CBC3-SHA", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}

}

func TestHandshakeOpenS3_EDH_RSA_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert()

	server := startServer(params, SSL30Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "EDH-RSA-DES-CBC-SHA", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}
}

func TestHandshakeOpenS3_DES_CBC3_SHA(t *testing.T) {
	params := generateRsaCert()

	server := startServer(params, SSL30Version)

	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "DES-CBC3-SHA", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}

}

func TestHandshakeOpenS3_DES_CBC_SHA(t *testing.T) {
	params := generateRsaCert()

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
	params := generateRsaCert()

	server := startServer(params, SSL30Version)
	defer StopServer(*server)

	if err := runOpensslCommand([]string{"-cipher", "RC4-SHA", "-ssl3", "-reconnect"}); err != nil {
		t.Error(err)
	}

}

func TestHandshakeOpenS3_RC4_MD5(t *testing.T) {
	params := generateRsaCert()

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
