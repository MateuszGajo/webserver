# About
## Descrription
PROJECT IN DEVELOPMENT PHASE! Don't use in production.

## Supported ciphers ssl 3.0
Project supports following ciphers of ssl 3.0 (based on rfc 6101):
* EDH-DSS-DES-CBC3-SHA
* EDH-DSS-DES-CBC-SHA
* EDH-RSA-DES-CBC3-SHA
* DES-CBC3-SHA
* DES-CBC-SHA
* ADH-DES-CBC3-SHA
* ADH-DES-CBC-SHA
* EDH-RSA-DES-CBC-SHA
* EXP-EDH-RSA-DES-CBC-SHA
* EXP-EDH-DSS-DES-CBC-SHA
* EXP-DES-CBC-SHA (Uses weak key)
* EXP-ADH-DES-CBC-SHA
* RC4-SHA
* RC4-MD5 
* EXP-RC4-MD5 (Uses weak key)
* ADH-RC4-MD5
* EXP-ADH-RC4-MD5
* EXP-RC2-CBC-MD5 (Uses weak key)
Other ciphers can work but hasn't been tested yet.

*All fortezza ciphers are not implemented in ssl 3.0.
## Supported ciphers tls 1.0
Project supports following ciphers of tls1.0 (based on rfc 2246):
* ADH-DES-CBC3-SHA
* ADH-DES-CBC-SHA
* ADH-RC4-MD5
* EXP-ADH-RC4-MD5
* DES-CBC3-SHA
* DES-CBC-SHA
* EDH-RSA-DES-CBC-SHA
* EXP-EDH-RSA-DES-CBC-SHA
* EXP-DES-CBC-SHA (Uses weak key)
* EXP-ADH-DES-CBC-SHA
* RC4-SHA
* EXP-RC4-MD5  (Uses weak key)
* EXP-RC2-CBC-MD5 (Uses weak key)
* EDH-DSS-DES-CBC3-SHA
* EDH-DSS-DES-CBC-SHA
* EXP-EDH-DSS-DES-CBC-SHA
* EDH-RSA-DES-CBC3-SHA

## Supported ciphers tls 1.1
Project supports following ciphers of tls1.1:
* ADH-DES-CBC3-SHA
* ADH-DES-CBC-SHA
* ADH-RC4-MD5
* EXP-ADH-RC4-MD5
* DES-CBC3-SHA
* DES-CBC-SHA
* EDH-RSA-DES-CBC-SHA
* EXP-EDH-RSA-DES-CBC-SHA
* EXP-DES-CBC-SHA (Uses weak key)
* EXP-ADH-DES-CBC-SHA
* RC4-SHA
* EXP-RC4-MD5  (Uses weak key)
* EXP-RC2-CBC-MD5 (Uses weak key)
* EDH-DSS-DES-CBC3-SHA
* EDH-DSS-DES-CBC-SHA
* EXP-EDH-DSS-DES-CBC-SHA
* EDH-RSA-DES-CBC3-SHA

## Supported features
* session resumption

## Weak keys
Some cipher suites support only weak cert keys (<512 bytes, not all export cipher):
* EXP-RC4-MD5 
* EXP-DES-CBC-SHA 
* EXP-RC2-CBC-MD5

Project has been verified with openssl 0.9.7e.

# How to run project
1. Download openssl version supporting ssl 3.0, tls 1.0 (recommended openssl 0.9.7e)
2. Extract data
3. Create certificate (rsa, dss) if needed, remeber some cipher suites need to be created we weak key look at #weak keys in about
4. Run project using `go run .` or  `go run . -cert /cert/rsa/server.crt -key /cert/rsa/server.key` if using certificate
5. Connect openssl to the server using `./openssl s_client -connect 127.0.0.1:4221 -"version(ssl3/tls1)" -cipher "YOUR CIPHER"`, replace YOUR CIPHER with one from the #supported ciphers
6. If everything went sucessfull you should see handshake detaiLS information, look for `New, TLSv1/SSLv3, Cipher is YOUR CIPHER`


# How to run test
1. Download openssl version supporting ssl 3.0, tls 1.0 (recommended openssl 0.9.7e)
2. Extract data in openssl folder
3. Make variable "OpenSSLVersion" in handshake_test.go if needed
4. run `go test ./...`


