# About
## Description
PROJECT IN DEVELOPMENT PHASE! Don't use in production.

# How to run project
1. Download openssl
2. Extract data
3. Create certificate (rsa, dss, rsa/dh) if needed, remeber some cipher suites needs to be created with weak key, look at #Certificates section
4. Run project using `go run .` or  `go run . -cert <cert path> -key <key path>` if using a certificate
5. Connect openssl to the server using `./openssl s_client -connect 127.0.0.1:4221 -<version> -cipher <cipher>`
6. If everything went successfully you should see handshake details information, look for `New, <version>, Cipher is`


# How to run test
1. Download openssl prefered version, e.g openssl 0.9.7e to use ssl3.0
2. Extract data in openssl folder
3. Update "OpenSSLVersion" variable s3Handshake_test.go
4. In main folder run `go test ./...`


# ciphers

## Supported ciphers tls 1.2
Project supports following ciphers of tls1.2:
* ADH-AES-SHA
* ADH-AES-SHA256
* DHE-RSA-AES256-SHA
* DHE-RSA-AES256-SHA
* DHE-RSA-AES128-SHA256
* DHE-RSA-AES256-SHA256
* AES256-SHA256
* AES256-SHA
* AES128-SHA256
* AES128-SHA


## Supported ciphers tls 1.3
Project supports following ciphers of tls1.3:
* TLS_AES_256_GCM_SHA384
* TLS_AES_128_GCM_SHA256
* TLS_CHACHA20_POLY1305_SHA256


## Supported features
* session resumption (prior to tls 1.3)

## Supported extensions
* heart beat
* signature algorithms

# Certificates

## DH embeded certs

There are some ciphers that uses RSA/DSS etc with DH params embeded in it, eg Kx=DH/RSA, Kx=DH/DSS Au=DH. There are not many resources on that, u can follow instruction below to create this cert. It uses -force_pubkey flag which was added in openssl 1.0.2.

## RSA/DH cert

### Step 1: Create CA
openssl genrsa -out CAkey.pem 2048

openssl req -x509 -new -nodes -key CAkey.pem -sha256 -days 3650 -out CAcert.pem

### Step 2: Create DH Parameters and Keys
openssl dhparam -out dhparam.pem 1024

openssl genpkey -paramfile dhparam.pem -out dhkey.pem

openssl pkey -in dhkey.pem -pubout -out dhpubkey.pem

### Step 3: Create an RSA Key and CSR
openssl genrsa -out rsakey.pem 2048

openssl req -new -key rsakey.pem -out rsa.csr

### Step 4: Generate the DH Certificate
openssl x509 -req -in rsa.csr -CA CAcert.pem -CAkey CAkey.pem -force_pubkey dhpubkey.pem -out dhcert.pem -CAcreateserial

## DSS/DH cert

### Step 1: Create CA 
openssl dsaparam -out dsaparam.pem 2048

openssl gendsa -out CAkey.pem dsaparam.pem

openssl req -x509 -new -key CAkey.pem -sha256 -days 3650 -out CAcert.pem

### Step 2: Create DH Parameters and Keys
openssl dhparam -out dhparam.pem 1024

openssl genpkey -paramfile dhparam.pem -out dhkey.pem

openssl pkey -in dhkey.pem -pubout -out dhpubkey.pem

### Step 3: Create a DSA Key and CSR
openssl gendsa -out dsakey.pem dsaparam.pem

openssl req -new -key dsakey.pem -out dsa.csr

### Step 4: Generate the DH Certificate
openssl x509 -req -in dsa.csr -CA CAcert.pem -CAkey CAkey.pem -force_pubkey dhpubkey.pem -out dssdhcert.pem -CAcreateserial
