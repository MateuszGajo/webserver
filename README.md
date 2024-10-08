PROJECT IN DEVELOPMENT PHASE! Don't use in production.

Project supports following ciphers of ssl 3.0 (based on rfc 6101):
* EDH-DSS-DES-CBC3-SHA
* EDH-DSS-DES-CBC-SHA
* EDH-RSA-DES-CBC3-SHA
* DES-CBC3-SHA
* DES-CBC-SHA
* ADH-DES-CBC3-SHA
* ADH-DES-CBC-SHA
* EDH-RSA-DES-CBC-SHA
* DES-CBC-SHA
* EXP-EDH-RSA-DES-CBC-SHA
* EXP-EDH-DSS-DES-CBC-SHA
* EXP-DES-CBC-SHA (Uses weak key)
* EXP-ADH-DES-CBC-SHA
* RC4-SHA
* RC4-MD5
* EXP-RC4-MD5 (Uses weak key)
* ADH-RC4-MD5
* EXP-ADH-RC4-MD5
Other ciphers can work but hasn't been tested yet.

*All fortezza ciphers are not implemented in ssl 3.0.

Weak keys
Some cipher suites support only weak keys (<512 bytes):
* EXP-RC4-MD5 
* EXP-DES-CBC-SHA 



Supported features:
* session resumption

It has been tested with openssl 0.9.7e.
Not all the features work but let's hope they will soon :)
